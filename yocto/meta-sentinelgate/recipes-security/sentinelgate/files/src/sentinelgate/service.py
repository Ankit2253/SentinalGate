"""Application service coordinating persistence, rendering, and enforcement."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any

from sentinelgate import __version__
from sentinelgate.c2guard import BeaconDetector
from sentinelgate.config import AppConfig
from sentinelgate.database import Database
from sentinelgate.intelligence import ThreatIntelligence
from sentinelgate.models import Ban, Event, NetworkObservation, Rule, ThreatIndicator
from sentinelgate.nftables import NftablesBackend, RulesetRenderer


class FirewallService:
    def __init__(
        self,
        config: AppConfig,
        database: Database | None = None,
        backend: NftablesBackend | None = None,
    ):
        self.config = config
        self.database = database or Database(config.database_path)
        self.backend = backend or NftablesBackend(config.firewall)
        self.renderer = RulesetRenderer(config.firewall)
        intelligence = ThreatIntelligence(
             indicators=[
                ThreatIndicator(
                    value=address,
                    indicator_type="ip",
                    confidence=0.90,
                    source="local-config",
                    description="Configured local threat-intelligence indicator",
                )
                 for address in config.c2_guard.threat_intelligence_ips
             ]
        )

        self.c2_detector = BeaconDetector(
            intelligence=intelligence,
            trusted_destinations=set(config.c2_guard.trusted_destinations),
            minimum_confidence=config.c2_guard.minimum_confidence,
        )
        self.database.initialize()

    def status(self) -> dict[str, Any]:
        rules = self.database.list_rules()
        return {
            "name": "SentinelGate",
            "version": __version__,
            "mode": self.config.firewall.mode,
            "nftables_available": self.backend.available(),
            "rules_total": len(rules),
            "rules_enabled": sum(rule.enabled for rule in rules),
            "active_bans": len(self.database.list_bans()),
            "active_snapshot": self.database.active_snapshot_id(),
            "c2_guard": self.c2_status(),
            "policies": {
                "input": self.config.firewall.default_input_policy,
                "forward": self.config.firewall.default_forward_policy,
                "output": self.config.firewall.default_output_policy,
            },
        }

    def add_rule(self, values: dict[str, Any]) -> Rule:
        return self.database.add_rule(Rule.from_dict(values))

    def update_rule(self, rule_id: str, values: dict[str, Any]) -> Rule:
        current = self.database.get_rule(rule_id)
        if not current:
            raise KeyError(f"Rule not found: {rule_id}")
        merged = current.to_dict()
        merged.update(values)
        merged["id"] = current.id
        merged["created_at"] = current.created_at
        return self.database.update_rule(Rule.from_dict(merged))

    def delete_rule(self, rule_id: str) -> bool:
        return self.database.delete_rule(rule_id)

    def render(self) -> str:
        return self.renderer.render(
            self.database.list_rules(enabled_only=True), self.database.list_bans()
        )

    def apply(self, reason: str = "Manual apply", confirmed: bool = False) -> dict[str, Any]:
        if self.config.firewall.mode == "apply" and not confirmed:
            raise PermissionError("Real firewall changes require explicit confirmation")
        rendered = self.render()
        result = self.backend.apply(rendered)
        self.config.state_path.mkdir(parents=True, exist_ok=True)
        rendered_path = self.config.state_path / "last-rendered.nft"
        rendered_path.write_text(rendered, encoding="utf-8")
        digest = hashlib.sha256(rendered.encode()).hexdigest()
        snapshot_id = self.database.add_snapshot(digest, rendered, reason)
        self.database.add_event(
            Event(
                event_type="ruleset_apply",
                severity="info",
                action="applied" if result.applied else "rendered",
                details={"snapshot_id": snapshot_id, "digest": digest, "dry_run": result.dry_run},
            )
        )
        return {
            "snapshot_id": snapshot_id,
            "digest": digest,
            "applied": result.applied,
            "dry_run": result.dry_run,
            "message": result.message,
            "rendered_path": str(rendered_path),
        }

    def rollback(self, snapshot_id: int, confirmed: bool = False) -> dict[str, Any]:
        snapshot = self.database.get_snapshot(snapshot_id)
        if not snapshot:
            raise KeyError(f"Snapshot not found: {snapshot_id}")
        if self.config.firewall.mode == "apply" and not confirmed:
            raise PermissionError("Real firewall rollback requires explicit confirmation")
        result = self.backend.apply(snapshot["config"])
        digest = hashlib.sha256(snapshot["config"].encode()).hexdigest()
        new_id = self.database.add_snapshot(
            digest, snapshot["config"], f"Rollback from snapshot {snapshot_id}"
        )
        self.database.add_event(
            Event(
                event_type="ruleset_rollback",
                severity="medium",
                action="applied" if result.applied else "rendered",
                details={"source_snapshot": snapshot_id, "new_snapshot": new_id},
            )
        )
        return {
            "snapshot_id": new_id,
            "source_snapshot": snapshot_id,
            "applied": result.applied,
            "dry_run": result.dry_run,
            "message": result.message,
        }

    def is_protected_address(self, address: str) -> bool:
        parsed = ip_address(address)
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            return True
        return any(parsed in ip_network(network) for network in self.config.firewall.management_cidrs)

    def ban(self, address: str, reason: str, seconds: int | None = None) -> Ban:
        parsed = str(ip_address(address))
        if self.is_protected_address(parsed):
            raise ValueError("Refusing to ban a loopback or protected management address")
        duration = int(seconds or self.config.firewall.ban_seconds)
        now = datetime.now(UTC)
        self.backend.ban(parsed, duration)
        ban = Ban(
            ip=parsed,
            reason=reason[:200],
            created_at=now.isoformat(timespec="seconds"),
            expires_at=(now + timedelta(seconds=duration)).isoformat(timespec="seconds"),
        )
        self.database.upsert_ban(ban)
        self.database.add_event(
            Event(
                event_type="dynamic_ban",
                severity="high",
                action="banned",
                source_ip=parsed,
                details={"reason": ban.reason, "duration_seconds": duration},
            )
        )
        return ban

    def unban(self, address: str) -> bool:
        parsed = str(ip_address(address))
        self.backend.unban(parsed)
        changed = self.database.deactivate_ban(parsed)
        if changed:
            self.database.add_event(
                Event(
                    event_type="dynamic_unban",
                    severity="info",
                    action="unbanned",
                    source_ip=parsed,
                )
            )
        return changed

    def export_report(self, destination: str | Path) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "status": self.status(),
            "statistics": self.database.event_stats(),
            "rules": [rule.to_dict() for rule in self.database.list_rules()],
            "active_bans": [ban.to_dict() for ban in self.database.list_bans()],
            "recent_events": [event.to_dict() for event in self.database.list_events(limit=250)],
            "snapshots": self.database.list_snapshots(),
        }
        target.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return target.resolve()
    def analyse_c2_observations(
        self,
        observations: list[NetworkObservation],
    ) -> list[Event]:
        """Analyse outbound observations and store generated C2 events."""
        if not self.config.c2_guard.enabled:
            return []
        events = self.c2_detector.analyse_events(observations)

        for event in events:
            self.database.add_event(event)

        return events   
    def c2_status(self) -> dict[str, Any]:
        """Return a summary of stored C2 Guard alerts."""

        events = [
            event
            for event in self.database.list_events(limit=1000)
            if event.event_type == "suspected_c2_beacon"
        ]

        return {
            "enabled": self.config.c2_guard.enabled,
            "alerts_total": len(events),
            "high_severity": sum(
                event.severity in {"high", "critical"}
                for event in events
            ),
            "latest_alert": events[0].to_dict() if events else None,
        }
        
    def respond_to_c2_alert(
        self,
        event_id: int,
        *,
        reason: str = "Analyst-approved C2 response",
        seconds: int | None = None,
    ) -> dict[str, Any]:
        """Manually block the destination associated with a stored C2 alert."""

        event = self.database.get_event(event_id)

        if event is None:
            raise ValueError(f"Event {event_id} was not found")

        if event.event_type != "suspected_c2_beacon":
            raise ValueError("Event is not a C2 Guard alert")

        if not event.destination_ip:
            raise ValueError("C2 alert does not contain a destination IP")

        ban = self.ban(
            event.destination_ip,
            reason,
            seconds,
        )

        return {
            "event_id": event_id,
            "destination_ip": event.destination_ip,
            "action": "blocked",
            "ban": ban.to_dict(),
        }

   
