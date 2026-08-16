from sentinelgate.models import Event
from sentinelgate.monitor import FirewallMonitor, ScanDetector, parse_nft_log
from sentinelgate.service import FirewallService


def test_parse_nftables_kernel_record() -> None:
    event = parse_nft_log(
        "Aug 13 kernel: SG_INPUT_DROP IN=eth0 OUT= SRC=203.0.113.7 "
        "DST=10.10.20.15 PROTO=TCP SPT=53001 DPT=445"
    )
    assert event is not None
    assert event.source_ip == "203.0.113.7"
    assert event.destination_port == 445
    assert event.severity == "medium"
    assert event.action == "blocked"


def test_non_sentinel_log_is_ignored() -> None:
    assert parse_nft_log("kernel: random message SRC=203.0.113.7") is None


def test_detector_requires_multiple_unique_ports() -> None:
    detector = ScanDetector(threshold=5, window_seconds=30)
    same_port = Event(
        event_type="firewall_drop",
        severity="low",
        action="blocked",
        source_ip="203.0.113.9",
        destination_port=80,
    )
    for index in range(6):
        assert detector.observe(same_port, now=float(index)) is None

    detection = None
    for index, port in enumerate([20, 21, 22, 23, 24], start=10):
        event = Event(
            event_type="firewall_drop",
            severity="low",
            action="blocked",
            source_ip="198.51.100.8",
            destination_port=port,
        )
        detection = detector.observe(event, now=float(index))
    assert detection is not None
    assert detection.unique_ports == 5


def test_monitor_records_scan_and_creates_dry_run_ban(service: FirewallService) -> None:
    lines = [
        f"SG_INPUT_DROP IN=eth0 SRC=203.0.113.90 DST=10.10.20.15 PROTO=TCP DPT={port}\n"
        for port in [20, 21, 22, 23, 24]
    ]
    count = FirewallMonitor(service).process(lines)
    assert count == 5
    assert service.database.list_bans()[0].ip == "203.0.113.90"
    assert service.database.event_stats()["blocked_events"] == 6


def test_monitor_never_bans_management_source(service: FirewallService) -> None:
    lines = [
        f"SG_INPUT_DROP IN=eth0 SRC=192.168.56.20 DST=10.10.20.15 PROTO=TCP DPT={port}\n"
        for port in [20, 21, 22, 23, 24]
    ]
    FirewallMonitor(service).process(lines)
    assert service.database.list_bans() == []
    events = service.database.list_events(limit=20)
    assert any(event.event_type == "auto_block_suppressed" for event in events)

