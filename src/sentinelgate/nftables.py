"""Safe nftables rendering and execution.

The backend never invokes a shell. Every interpolated value is validated by the
configuration or domain model before it reaches a generated nftables program.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from typing import Protocol as TypingProtocol

from sentinelgate.config import FirewallConfig
from sentinelgate.models import Action, Ban, Direction, Protocol, Rule


class NftablesError(RuntimeError):
    pass


class Runner(TypingProtocol):
    def run(self, args: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]: ...


class SubprocessRunner:
    def run(
        self, args: list[str], input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["LC_ALL"] = "C"
        return subprocess.run(
            args,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            env=environment,
        )


def _quote(value: str) -> str:
    """Return a valid nftables quoted string."""
    return json.dumps(value, ensure_ascii=True)


class RulesetRenderer:
    def __init__(self, config: FirewallConfig):
        self.config = config

    def render(self, rules: list[Rule], bans: list[Ban] | None = None) -> str:
        active = sorted((rule for rule in rules if rule.enabled), key=lambda item: item.priority)
        chains = {
            direction: [rule for rule in active if rule.direction == direction]
            for direction in Direction
        }
        lines = [f"table inet {self.config.table_name} {{"]
        lines.extend(self._sets(bans or []))
        lines.extend(self._chain(Direction.INPUT, chains[Direction.INPUT]))
        lines.extend(self._chain(Direction.FORWARD, chains[Direction.FORWARD]))
        lines.extend(self._chain(Direction.OUTPUT, chains[Direction.OUTPUT]))
        lines.append("}")
        return "\n".join(lines) + "\n"

    def _sets(self, bans: list[Ban]) -> list[str]:
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        elements: dict[int, list[str]] = {4: [], 6: []}
        for ban in bans:
            expires = datetime.fromisoformat(ban.expires_at)
            remaining = max(1, int((expires - now).total_seconds()))
            parsed = ip_address(ban.ip)
            elements[parsed.version].append(f"{parsed} timeout {remaining}s")
        lines = [
            "    set dynamic_block_v4 {",
            "        type ipv4_addr",
            "        flags timeout",
        ]
        if elements[4]:
            lines.append(f"        elements = {{ {', '.join(elements[4])} }}")
        lines.extend(
            [
                "    }",
                "    set dynamic_block_v6 {",
                "        type ipv6_addr",
                "        flags timeout",
            ]
        )
        if elements[6]:
            lines.append(f"        elements = {{ {', '.join(elements[6])} }}")
        lines.append("    }")
        return lines

    def _chain(self, direction: Direction, rules: list[Rule]) -> list[str]:
        policy = getattr(self.config, f"default_{direction.value}_policy")
        lines = [
            f"    chain {direction.value} {{",
            f"        type filter hook {direction.value} priority 0; policy {policy};",
        ]
        if direction == Direction.INPUT:
            lines.append('        iifname "lo" counter accept comment "Allow loopback"')
        lines.append(
            '        ct state established,related counter accept comment "Allow established traffic"'
        )
        lines.append('        ct state invalid counter drop comment "Drop invalid state"')
        if direction in {Direction.INPUT, Direction.FORWARD}:
            lines.extend(self._blocklist_lines())
        if direction == Direction.INPUT:
            lines.extend(self._management_lines())
        if self.config.allow_icmp:
            lines.append(
                '        meta l4proto { icmp, ipv6-icmp } counter accept comment "Allow ICMP"'
            )
        for rule in rules:
            lines.extend(self._rule_lines(rule))
        if policy == "drop":
            prefix = f"SG_{direction.value.upper()}_DROP "
            lines.append(
                f"        limit rate {self.config.log_rate} log prefix {_quote(prefix)}"
            )
            lines.append('        counter drop comment "Default deny"')
        lines.append("    }")
        return lines

    def _blocklist_lines(self) -> list[str]:
        return [
            (
                f"        ip saddr @dynamic_block_v4 limit rate {self.config.log_rate} "
                f"log prefix {_quote('SG_BLOCKLIST_V4 ')}"
            ),
            '        ip saddr @dynamic_block_v4 counter drop comment "Dynamic IPv4 blocklist"',
            (
                f"        ip6 saddr @dynamic_block_v6 limit rate {self.config.log_rate} "
                f"log prefix {_quote('SG_BLOCKLIST_V6 ')}"
            ),
            '        ip6 saddr @dynamic_block_v6 counter drop comment "Dynamic IPv6 blocklist"',
        ]

    def _management_lines(self) -> list[str]:
        if not self.config.management_ports:
            return []
        ports = ", ".join(str(int(port)) for port in sorted(set(self.config.management_ports)))
        port_expression = ports if len(set(self.config.management_ports)) == 1 else f"{{ {ports} }}"
        result: list[str] = []
        for network_text in self.config.management_cidrs:
            network = ip_network(network_text)
            family = "ip" if network.version == 4 else "ip6"
            result.append(
                f"        {family} saddr {network} tcp dport {port_expression} counter accept "
                f'comment "Protected management path"'
            )
        return result

    def _rule_lines(self, rule: Rule) -> list[str]:
        expressions: list[str] = []
        if rule.source:
            family = "ip" if ip_network(rule.source).version == 4 else "ip6"
            expressions.append(f"{family} saddr {rule.source}")
        if rule.destination:
            family = "ip" if ip_network(rule.destination).version == 4 else "ip6"
            expressions.append(f"{family} daddr {rule.destination}")
        if rule.protocol == Protocol.ICMP:
            if rule.ip_version == 4:
                expressions.append("meta l4proto icmp")
            elif rule.ip_version == 6:
                expressions.append("meta l4proto ipv6-icmp")
            else:
                expressions.append("meta l4proto { icmp, ipv6-icmp }")
        elif rule.protocol in {Protocol.TCP, Protocol.UDP}:
            expressions.append(f"meta l4proto {rule.protocol.value}")
            if rule.source_port:
                expressions.append(f"{rule.protocol.value} sport {rule.source_port}")
            if rule.destination_port:
                expressions.append(f"{rule.protocol.value} dport {rule.destination_port}")
        match = " ".join(expressions)
        if match:
            match += " "
        prefix = f"SG_RULE_{rule.id[:8].upper()} "
        lines: list[str] = []
        if rule.log:
            lines.append(
                f"        {match}limit rate {self.config.log_rate} log prefix {_quote(prefix)}"
            )
        verdict = "accept" if rule.action == Action.ALLOW else "drop"
        safe_name = "".join(char for char in rule.name if char.isalnum() or char in " ._-:")[:80]
        lines.append(
            f"        {match}counter {verdict} comment {_quote(f'SG: {safe_name}')}"
        )
        return lines


@dataclass(slots=True)
class ApplyResult:
    applied: bool
    dry_run: bool
    script: str
    message: str


class NftablesBackend:
    def __init__(self, config: FirewallConfig, runner: Runner | None = None):
        self.config = config
        self.runner = runner or SubprocessRunner()

    @property
    def dry_run(self) -> bool:
        return self.config.mode == "dry-run"

    def binary_path(self) -> str | None:
        if os.path.isabs(self.config.nft_binary):
            return self.config.nft_binary if os.path.isfile(self.config.nft_binary) else None
        return shutil.which(self.config.nft_binary)

    def available(self) -> bool:
        return self.binary_path() is not None

    def _require_binary(self) -> str:
        path = self.binary_path()
        if not path:
            raise NftablesError("nft was not found; install the nftables package first")
        return path

    def table_exists(self) -> bool:
        if self.dry_run or not self.available():
            return False
        result = self.runner.run(
            [self._require_binary(), "list", "table", "inet", self.config.table_name]
        )
        return result.returncode == 0

    def _transaction(self, rendered: str) -> str:
        if self.table_exists():
            return f"delete table inet {self.config.table_name}\n{rendered}"
        return rendered

    def apply(self, rendered: str) -> ApplyResult:
        if self.dry_run:
            return ApplyResult(
                applied=False,
                dry_run=True,
                script=rendered,
                message="Rules rendered successfully; the host firewall was not changed",
            )
        if os.geteuid() != 0:
            raise NftablesError("Real apply mode requires root privileges")
        binary = self._require_binary()
        script = self._transaction(rendered)
        checked = self.runner.run([binary, "--check", "-f", "-"], script)
        if checked.returncode != 0:
            raise NftablesError(f"nftables validation failed: {checked.stderr.strip()}")
        applied = self.runner.run([binary, "-f", "-"], script)
        if applied.returncode != 0:
            raise NftablesError(f"nftables apply failed: {applied.stderr.strip()}")
        return ApplyResult(
            applied=True,
            dry_run=False,
            script=script,
            message="Rules applied atomically to nftables",
        )

    def ban(self, address: str, seconds: int) -> str:
        parsed = ip_address(address)
        seconds = int(seconds)
        if not 30 <= seconds <= 604_800:
            raise ValueError("Ban duration must be between 30 and 604800 seconds")
        set_name = "dynamic_block_v4" if parsed.version == 4 else "dynamic_block_v6"
        command = (
            f"add element inet {self.config.table_name} {set_name} "
            f"{{ {parsed} timeout {seconds}s }}\n"
        )
        if self.dry_run:
            return command
        if os.geteuid() != 0:
            raise NftablesError("Real apply mode requires root privileges")
        result = self.runner.run([self._require_binary(), "-f", "-"], command)
        if result.returncode != 0:
            raise NftablesError(f"Unable to add dynamic ban: {result.stderr.strip()}")
        return command

    def unban(self, address: str) -> str:
        parsed = ip_address(address)
        set_name = "dynamic_block_v4" if parsed.version == 4 else "dynamic_block_v6"
        command = (
            f"delete element inet {self.config.table_name} {set_name} {{ {parsed} }}\n"
        )
        if self.dry_run:
            return command
        if os.geteuid() != 0:
            raise NftablesError("Real apply mode requires root privileges")
        result = self.runner.run([self._require_binary(), "-f", "-"], command)
        if result.returncode != 0:
            raise NftablesError(f"Unable to remove dynamic ban: {result.stderr.strip()}")
        return command
