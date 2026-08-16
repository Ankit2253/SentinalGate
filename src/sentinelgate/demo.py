"""Deterministic, documentation-range demo telemetry for portfolio use."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from sentinelgate.models import Event
from sentinelgate.service import FirewallService

DEMO_RULES = [
    {
        "name": "Allow outbound DNS",
        "direction": "output",
        "action": "allow",
        "protocol": "udp",
        "destination_port": "53",
        "priority": 100,
        "log": False,
    },
    {
        "name": "Allow outbound HTTPS",
        "direction": "output",
        "action": "allow",
        "protocol": "tcp",
        "destination_port": "443",
        "priority": 110,
        "log": False,
    },
    {
        "name": "Block inbound SMB",
        "direction": "input",
        "action": "block",
        "protocol": "tcp",
        "source": "0.0.0.0/0",
        "destination_port": "445",
        "priority": 50,
        "log": True,
    },
    {
        "name": "Allow internal application traffic",
        "direction": "input",
        "action": "allow",
        "protocol": "tcp",
        "source": "10.10.0.0/16",
        "destination_port": "8443",
        "priority": 90,
        "log": True,
    },
]


def seed_demo(service: FirewallService) -> dict[str, int]:
    rules_added = 0
    if not service.database.list_rules():
        for values in DEMO_RULES:
            service.add_rule(values)
            rules_added += 1

    stats = service.database.event_stats()
    events_added = 0
    if stats["total_events"] == 0:
        randomizer = random.Random(4242)
        now = datetime.now(UTC)
        sources = ["203.0.113.24", "198.51.100.77", "192.0.2.44", "203.0.113.91"]
        ports = [22, 80, 135, 139, 443, 445, 1433, 3389, 5900, 8080]
        for index in range(72):
            port = randomizer.choice(ports)
            source = randomizer.choices(sources, weights=[38, 18, 10, 6], k=1)[0]
            occurred = now - timedelta(minutes=(72 - index) * 3)
            severity = "medium" if port in {22, 445, 3389, 5900} else "low"
            service.database.add_event(
                Event(
                    event_type="firewall_drop",
                    severity=severity,
                    action="blocked",
                    source_ip=source,
                    destination_ip="10.10.20.15",
                    destination_port=port,
                    protocol="tcp",
                    raw=f"SG_INPUT_DROP SRC={source} DST=10.10.20.15 PROTO=TCP DPT={port}",
                    details={"demo": True, "input_interface": "eth0"},
                    occurred_at=occurred.isoformat(timespec="seconds"),
                )
            )
            events_added += 1
        service.database.add_event(
            Event(
                event_type="port_scan_detected",
                severity="high",
                action="alerted",
                source_ip="203.0.113.24",
                details={"attempts": 38, "unique_ports": 9, "demo": True},
                occurred_at=(now - timedelta(minutes=5)).isoformat(timespec="seconds"),
            )
        )
        events_added += 1
    return {"rules_added": rules_added, "events_added": events_added}
