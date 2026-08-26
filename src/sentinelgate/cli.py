"""SentinelGate command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sentinelgate.api import create_app
from sentinelgate.config import load_config
from sentinelgate.demo import seed_demo
from sentinelgate.monitor import FirewallMonitor, journal_lines
from sentinelgate.nftables import NftablesError
from sentinelgate.observations import load_observations
from sentinelgate.service import FirewallService

DEFAULT_CONFIG = """# SentinelGate configuration
# Keep dry-run enabled until you have tested the rules in an isolated VM.

[server]
host = "127.0.0.1"
port = 8080
token_env = "SENTINELGATE_ADMIN_TOKEN"

[firewall]
mode = "dry-run"
table_name = "sentinelgate"
management_cidrs = ["192.168.56.0/24"]
management_ports = [22, 8080]
default_input_policy = "drop"
default_forward_policy = "drop"
default_output_policy = "accept"
allow_icmp = true
log_rate = "10/second"
nft_binary = "nft"
auto_block = true
scan_threshold = 12
scan_window_seconds = 30
ban_seconds = 900

[storage]
state_dir = "./data"
database = "./data/sentinelgate.db"
"""


def _json(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str))


def _service(config_path: str | None) -> FirewallService:
    return FirewallService(load_config(config_path))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelgate",
        description="Safe-by-default Linux firewall and threat-monitoring platform",
    )
    parser.add_argument("--config", help="Path to sentinelgate.toml")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Create a starter configuration")
    init.add_argument("--output", default="sentinelgate.toml")
    init.add_argument("--force", action="store_true")

    commands.add_parser("status", help="Show firewall status")
    commands.add_parser("render", help="Print the generated nftables ruleset")

    apply = commands.add_parser("apply", help="Render or apply the current rules")
    apply.add_argument("--confirm", default="", help="Type APPLY in real mode")
    apply.add_argument("--reason", default="CLI apply")

    rules = commands.add_parser("rules", help="Manage firewall rules")
    rule_commands = rules.add_subparsers(dest="rules_command", required=True)
    rule_commands.add_parser("list")
    add = rule_commands.add_parser("add")
    add.add_argument("--name", required=True)
    add.add_argument("--direction", choices=["input", "forward", "output"], required=True)
    add.add_argument("--action", choices=["allow", "block"], required=True)
    add.add_argument("--protocol", choices=["any", "tcp", "udp", "icmp"], default="any")
    add.add_argument("--source")
    add.add_argument("--destination")
    add.add_argument("--source-port")
    add.add_argument("--destination-port")
    add.add_argument("--priority", type=int, default=500)
    add.add_argument("--no-log", action="store_true")
    delete = rule_commands.add_parser("delete")
    delete.add_argument("rule_id")
    toggle = rule_commands.add_parser("toggle")
    toggle.add_argument("rule_id")
    toggle.add_argument("state", choices=["on", "off"])

    events = commands.add_parser("events", help="List recent firewall events")
    events.add_argument("--limit", type=int, default=25)
    events.add_argument("--severity", choices=["info", "low", "medium", "high", "critical"])
    events.add_argument("--source")


    c2 = commands.add_parser(
        "c2",
        help="Analyse safe outbound-connection observations",
    )
    c2_commands = c2.add_subparsers(
        dest="c2_command",
        required=True,
    )

    c2_analyse = c2_commands.add_parser(
        "analyse",
        help="Analyse observations from a JSONL file",
    )
    c2_analyse.add_argument(
        "--file",
        required=True,
        help="Path to the JSONL observation file",
    )

    ban = commands.add_parser("ban", help="Temporarily block an IP address")
    ban.add_argument("address")
    ban.add_argument("--reason", default="Manual CLI ban")
    ban.add_argument("--seconds", type=int)
    unban = commands.add_parser("unban", help="Remove a temporary IP block")
    unban.add_argument("address")

    monitor = commands.add_parser("monitor", help="Read and analyse nftables kernel logs")
    monitor.add_argument("--file", help="Read a log file instead of following journalctl")

    serve = commands.add_parser("serve", help="Run the local API and dashboard")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)

    demo = commands.add_parser("demo", help="Load safe sample telemetry and run the dashboard")
    demo.add_argument("--host", default="127.0.0.1")
    demo.add_argument("--port", type=int, default=8080)
    demo.add_argument("--no-server", action="store_true")

    report = commands.add_parser("report", help="Export a JSON evidence report")
    report.add_argument("--output", default="reports/sentinelgate-report.json")

    commands.add_parser("snapshots", help="List rollback snapshots")
    rollback = commands.add_parser("rollback", help="Restore a saved ruleset")
    rollback.add_argument("snapshot_id", type=int)
    rollback.add_argument("--confirm", default="", help="Type ROLLBACK in real mode")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "init":
        destination = Path(args.output)
        if destination.exists() and not args.force:
            parser.error(f"{destination} already exists; use --force to replace it")
        destination.write_text(DEFAULT_CONFIG, encoding="utf-8")
        print(f"Created {destination.resolve()}")
        return

    try:
        service = _service(args.config)
        if args.command == "status":
            _json(service.status())
        elif args.command == "render":
            print(service.render(), end="")
        elif args.command == "apply":
            _json(service.apply(reason=args.reason, confirmed=args.confirm == "APPLY"))
        elif args.command == "rules":
            _handle_rules(service, args)
        elif args.command == "events":
            _json(
                [
                    event.to_dict()
                    for event in service.database.list_events(args.limit, args.severity, args.source)
                ]
            )
        elif args.command == "c2":
            _handle_c2(service, args)
        elif args.command == "ban":
            _json(service.ban(args.address, args.reason, args.seconds).to_dict())
        elif args.command == "unban":
            _json({"removed": service.unban(args.address)})
        elif args.command == "monitor":
            monitor = FirewallMonitor(service)
            if args.file:
                with Path(args.file).open(encoding="utf-8", errors="replace") as handle:
                    processed = monitor.process(handle)
                _json({"events_processed": processed})
            else:
                print("Following kernel logs. Press Ctrl+C to stop.", file=sys.stderr)
                monitor.process(journal_lines())
        elif args.command == "serve":
            _serve(service, args.host, args.port)
        elif args.command == "demo":
            if service.config.firewall.mode != "dry-run":
                parser.error("The demo command only runs in dry-run mode")
            _json(seed_demo(service))
            if not args.no_server:
                _serve(service, args.host, args.port)
        elif args.command == "report":
            print(service.export_report(args.output))
        elif args.command == "snapshots":
            _json(service.database.list_snapshots())
        elif args.command == "rollback":
            _json(service.rollback(args.snapshot_id, args.confirm == "ROLLBACK"))
    except (ValueError, KeyError, PermissionError, NftablesError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except KeyboardInterrupt:
        print("\nStopped.", file=sys.stderr)


def _handle_rules(service: FirewallService, args: argparse.Namespace) -> None:
    if args.rules_command == "list":
        _json([rule.to_dict() for rule in service.database.list_rules()])
    elif args.rules_command == "add":
        values = {
            "name": args.name,
            "direction": args.direction,
            "action": args.action,
            "protocol": args.protocol,
            "source": args.source,
            "destination": args.destination,
            "source_port": args.source_port,
            "destination_port": args.destination_port,
            "priority": args.priority,
            "log": not args.no_log,
        }
        _json(service.add_rule(values).to_dict())
    elif args.rules_command == "delete":
        _json({"deleted": service.delete_rule(args.rule_id)})
    elif args.rules_command == "toggle":
        _json(service.update_rule(args.rule_id, {"enabled": args.state == "on"}).to_dict())

def _handle_c2(
    service: FirewallService,
    args: argparse.Namespace,
) -> None:
    observations = load_observations(args.file)
    events = service.analyse_c2_observations(observations)

    _json(
        {
            "observations_processed": len(observations),
            "detections": len(events),
            "events": [
                event.to_dict()
                for event in events
            ],
        }
    )



def _serve(service: FirewallService, host: str | None, port: int | None) -> None:
    import uvicorn

    if host:
        service.config.server.host = host
    if port:
        service.config.server.port = port
    service.config.validate()
    uvicorn.run(
        create_app(service),
        host=service.config.server.host,
        port=service.config.server.port,
        access_log=False,
    )


if __name__ == "__main__":
    main()

