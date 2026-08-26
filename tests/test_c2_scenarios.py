from datetime import UTC, datetime, timedelta

from sentinelgate.c2guard import BeaconDetector
from sentinelgate.intelligence import ThreatIntelligence
from sentinelgate.models import NetworkObservation, ThreatIndicator


def test_scenario_regular_beacon_is_detected() -> None:
    start = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)

    observations = [
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observed_at=(start + timedelta(seconds=20 * index)).isoformat(),
        )
        for index in range(5)
    ]

    detector = BeaconDetector()

    events = detector.analyse_events(observations)

    assert len(events) == 1
    assert events[0].event_type == "suspected_c2_beacon"
    assert events[0].destination_ip == "203.0.113.50"


def test_scenario_irregular_traffic_is_not_detected() -> None:
    start = datetime(2026, 8, 23, 13, 0, tzinfo=UTC)

    intervals = [0, 7, 41, 96, 180]

    observations = [
        NetworkObservation(
            destination_ip="203.0.113.60",
            destination_port=443,
            protocol="tcp",
            observed_at=(start + timedelta(seconds=offset)).isoformat(),
        )
        for offset in intervals
    ]

    detector = BeaconDetector()

    events = detector.analyse_events(observations)

    assert events == []


def test_scenario_trusted_destination_is_suppressed() -> None:
    start = datetime(2026, 8, 23, 14, 0, tzinfo=UTC)

    observations = [
        NetworkObservation(
            destination_ip="192.0.2.25",
            destination_port=443,
            protocol="tcp",
            observed_at=(start + timedelta(seconds=30 * index)).isoformat(),
        )
        for index in range(5)
    ]

    detector = BeaconDetector(
        trusted_destinations={"192.0.2.25"},
    )

    events = detector.analyse_events(observations)

    assert events == []


def test_scenario_known_suspicious_destination_is_enriched() -> None:
    start = datetime(2026, 8, 23, 15, 0, tzinfo=UTC)

    intelligence = ThreatIntelligence(
        indicators=[
            ThreatIndicator(
                value="198.51.100.99",
                indicator_type="ip",
                confidence=0.95,
                source="scenario-test",
                description="Synthetic suspicious destination",
            )
        ]
    )

    observations = [
        NetworkObservation(
            destination_ip="198.51.100.99",
            destination_port=443,
            protocol="tcp",
            observed_at=(start + timedelta(seconds=20 * index)).isoformat(),
        )
        for index in range(5)
    ]

    detector = BeaconDetector(
        intelligence=intelligence,
    )

    events = detector.analyse_events(observations)

    assert len(events) == 1

    event = events[0]

    assert event.severity == "high"
    assert event.details["threat_intelligence_match"] is True
    assert event.details["indicator"]["value"] == "198.51.100.99"



def test_scenario_service_stores_detected_beacon(service) -> None:
    start = datetime(2026, 8, 23, 16, 0, tzinfo=UTC)

    observations = [
        NetworkObservation(
            destination_ip="203.0.113.75",
            destination_port=443,
            protocol="tcp",
            observed_at=(start + timedelta(seconds=20 * index)).isoformat(),
        )
        for index in range(5)
    ]

    events = service.analyse_c2_observations(observations)

    assert len(events) == 1

    status = service.c2_status()

    assert status["alerts_total"] == 1
    assert status["latest_alert"] is not None
def test_detection_does_not_automatically_create_ban(service) -> None:
    start = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)

    observations = [
        NetworkObservation(
            destination_ip="198.51.100.200",
            destination_port=443,
            protocol="tcp",
            observed_at=(start + timedelta(seconds=20 * index)).isoformat(),
        )
        for index in range(5)
    ]

    events = service.analyse_c2_observations(observations)

    assert len(events) == 1

    status = service.status()

    assert status["active_bans"] == 0
