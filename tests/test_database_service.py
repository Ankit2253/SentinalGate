
import json

import pytest

from sentinelgate.c2guard import BeaconDetector
from sentinelgate.models import Event, NetworkObservation
from sentinelgate.service import FirewallService


def test_rule_crud_and_event_statistics(service: FirewallService) -> None:
    rule = service.add_rule(
        {
            "name": "Block SSH",
            "direction": "input",
            "action": "block",
            "protocol": "tcp",
            "destination_port": 22,
            "priority": 40,
        }
    )
    service.database.add_event(
        Event(
            event_type="firewall_drop",
            severity="medium",
            action="blocked",
            source_ip="203.0.113.8",
            destination_ip="10.0.0.4",
            destination_port=22,
            protocol="tcp",
        )
    )

    assert service.database.get_rule(rule.id).name == "Block SSH"
    changed = service.update_rule(rule.id, {"enabled": False, "priority": 70})
    assert changed.enabled is False
    assert changed.priority == 70
    assert service.database.event_stats()["blocked_events"] == 1
    assert service.delete_rule(rule.id) is True
    assert service.delete_rule(rule.id) is False


def test_dry_run_apply_snapshot_and_rollback(service: FirewallService) -> None:
    service.add_rule(
        {
            "name": "Allow web",
            "direction": "input",
            "action": "allow",
            "protocol": "tcp",
            "destination_port": 443,
        }
    )

    applied = service.apply("Automated test")
    assert applied["dry_run"] is True
    assert applied["applied"] is False
    assert applied["snapshot_id"] == 1
    assert service.config.state_path.joinpath("last-rendered.nft").exists()

    rollback = service.rollback(1)
    assert rollback["source_snapshot"] == 1
    assert rollback["snapshot_id"] == 2
    assert service.database.active_snapshot_id() == 2


def test_bans_protect_management_and_survive_render(service: FirewallService) -> None:
    with pytest.raises(ValueError, match="protected management"):
        service.ban("192.168.56.25", "Should never happen")

    ban = service.ban("203.0.113.45", "Scan detected", seconds=300)
    assert ban.active is True
    assert "203.0.113.45 timeout" in service.render()
    assert service.unban("203.0.113.45") is True
    assert service.database.list_bans() == []


def test_report_contains_evidence(service: FirewallService, tmp_path) -> None:
    service.apply("Create snapshot")
    report_path = service.export_report(tmp_path / "report.json")
    report = json.loads(report_path.read_text())
    assert report["status"]["name"] == "SentinelGate"
    assert report["snapshots"][0]["reason"] == "Create snapshot"
    assert report["recent_events"][0]["event_type"] == "ruleset_apply"

def test_database_stores_c2_detection_event(service) -> None:
    observations = [
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observed_at="2026-08-20T12:00:00+00:00",
        ),
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observed_at="2026-08-20T12:00:20+00:00",
        ),
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observed_at="2026-08-20T12:00:40+00:00",
        ),
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observed_at="2026-08-20T12:01:00+00:00",
        ),
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observed_at="2026-08-20T12:01:20+00:00",
        ),
    ]

    detector = BeaconDetector()

    events = detector.analyse_events(observations)

    assert len(events) == 1

    service.database.add_event(events[0])

    stored = service.database.list_events(limit=10)

    assert any(
        event.event_type == "suspected_c2_beacon"
        and event.destination_ip == "203.0.113.50"
        for event in stored
    )
def test_service_analyses_and_stores_c2_events(
    service: FirewallService,
) -> None:
    observations = [
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observed_at=f"2026-08-20T12:0{minute}:00+00:00",
        )
        for minute in range(5)
    ]

    events = service.analyse_c2_observations(observations)

    assert len(events) == 1
    assert events[0].id is not None
    assert events[0].event_type == "suspected_c2_beacon"

    stored = service.database.list_events(limit=10)

    assert any(
        event.event_type == "suspected_c2_beacon"
        and event.destination_ip == "203.0.113.50"
        for event in stored
    )
def test_service_does_not_store_normal_sparse_activity(
    service: FirewallService,
) -> None:
    observations = [
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observed_at="2026-08-20T12:00:00+00:00",
        ),
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observed_at="2026-08-20T12:03:00+00:00",
        ),
    ]

    events = service.analyse_c2_observations(observations)

    assert events == []
    assert service.database.list_events(limit=10) == []


def test_c2_status_is_empty_initially(service: FirewallService) -> None:
    status = service.c2_status()

    assert status["enabled"] is True
    assert status["alerts_total"] == 0
    assert status["high_severity"] == 0
    assert status["latest_alert"] is None


def test_c2_status_reports_stored_alert(service: FirewallService) -> None:
    service.database.add_event(
        Event(
            event_type="suspected_c2_beacon",
            severity="high",
            action="detected",
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            details={
                "confidence": 0.95,
                "detector": "periodic_beacon",
            },
        )
    )

    status = service.c2_status()

    assert status["alerts_total"] == 1
    assert status["high_severity"] == 1
    assert status["latest_alert"] is not None
    assert status["latest_alert"]["destination_ip"] == "203.0.113.50"


def test_main_status_includes_c2_guard(service: FirewallService) -> None:
    status = service.status()

    assert "c2_guard" in status
    assert status["c2_guard"]["alerts_total"] == 0
def test_c2_response_rejects_non_c2_event(service: FirewallService) -> None:
    event = Event(
        event_type="firewall_decision",
        severity="medium",
        action="blocked",
        destination_ip="203.0.113.25",
        destination_port=443,
        protocol="tcp",
    )

    stored = service.database.add_event(event)

    with pytest.raises(ValueError, match="not a C2 Guard alert"):
        service.respond_to_c2_alert(stored.id)
def test_c2_response_uses_existing_ban_path(service: FirewallService) -> None:
    event = Event(
        event_type="suspected_c2_beacon",
        severity="high",
        action="detected",
        destination_ip="203.0.113.90",
        destination_port=443,
        protocol="tcp",
        details={"confidence": 1.0},
    )

    stored = service.database.add_event(event)

    result = service.respond_to_c2_alert(
        stored.id,
        reason="Analyst approved test response",
        seconds=300,
    )

    assert result["event_id"] == stored.id
    assert result["destination_ip"] == "203.0.113.90"
    assert result["action"] == "blocked"


def test_service_uses_configured_c2_trusted_destination(app_config) -> None:
    app_config.c2_guard.trusted_destinations = ["192.0.2.25"]

    service = FirewallService(app_config)

    assert "192.0.2.25" in service.c2_detector.trusted_destinations


def test_service_uses_configured_threat_intelligence_ip(app_config) -> None:
    app_config.c2_guard.threat_intelligence_ips = ["198.51.100.99"]

    service = FirewallService(app_config)

    indicator = service.c2_detector.intelligence.match_ip("198.51.100.99")

    assert indicator is not None
    assert indicator.value == "198.51.100.99"
    assert indicator.source == "local-config"

    
def test_disabled_c2_guard_does_not_analyse_or_store_events(app_config) -> None:
    app_config.c2_guard.enabled = False
    service = FirewallService(app_config)

    observations = [
        NetworkObservation(
            destination_ip="198.51.100.200",
            destination_port=443,
            protocol="tcp",
            observed_at=f"2026-08-29T00:00:{second:02d}+00:00",
        )
        for second in (0, 20, 40)
    ]

    events = service.analyse_c2_observations(observations)

    assert events == []
    assert service.c2_status()["enabled"] is False
    assert service.c2_status()["alerts_total"] == 0


def test_c2_response_creates_audit_event(service: FirewallService) -> None:
    event = Event(
        event_type="suspected_c2_beacon",
        severity="high",
        action="detected",
        destination_ip="203.0.113.90",
        destination_port=443,
        protocol="tcp",
        details={"confidence": 1.0},
    )
    stored = service.database.add_event(event)

    service.respond_to_c2_alert(
        stored.id,
        reason="Analyst confirmed suspicious beacon",
        seconds=300,
    )

    events = service.database.list_events(limit=20)

    audit_events = [
        item
        for item in events
        if item.event_type == "c2_response"
    ]

    assert len(audit_events) == 1

    audit = audit_events[0]

    assert audit.action == "blocked"
    assert audit.destination_ip == "203.0.113.90"
    assert audit.details["source_c2_event_id"] == stored.id
    assert audit.details["reason"] == "Analyst confirmed suspicious beacon"
    assert audit.details["response"] == "analyst-approved-block"


def test_c2_response_can_be_unbanned_and_audited(service: FirewallService) -> None:
    event = Event(
        event_type="suspected_c2_beacon",
        severity="high",
        action="detected",
        destination_ip="203.0.113.91",
        destination_port=443,
        protocol="tcp",
        details={"confidence": 1.0},
    )
    stored = service.database.add_event(event)

    service.respond_to_c2_alert(
        stored.id,
        reason="Analyst approved temporary block",
        seconds=300,
    )

    changed = service.unban("203.0.113.91")

    assert changed is True

    events = service.database.list_events(limit=20)

    unban_events = [
        item
        for item in events
        if item.event_type == "dynamic_unban"
    ]

    assert len(unban_events) == 1
    assert unban_events[0].action == "unbanned"
    assert unban_events[0].source_ip == "203.0.113.91"



def test_rollback_creates_audit_event(service: FirewallService) -> None:
    result = service.apply(reason="Create rollback test snapshot")

    snapshot_id = result["snapshot_id"]

    rollback = service.rollback(snapshot_id)

    assert rollback["source_snapshot"] == snapshot_id

    events = service.database.list_events(limit=20)

    rollback_events = [
        item
        for item in events
        if item.event_type == "ruleset_rollback"
    ]

    assert len(rollback_events) == 1

    audit = rollback_events[0]

    assert audit.details["source_snapshot"] == snapshot_id
    assert audit.details["new_snapshot"] == rollback["snapshot_id"]
