from datetime import UTC, datetime, timedelta

from sentinelgate.c2guard import BeaconDetector
from sentinelgate.models import NetworkObservation


def test_empty_observations_return_no_events() -> None:
    detector = BeaconDetector()

    events = detector.analyse_events([])

    assert events == []


def test_three_periodic_observations_are_not_enough() -> None:
    start = datetime(2026, 8, 23, 12, 0, tzinfo=UTC)

    observations = [
        NetworkObservation(
            destination_ip="203.0.113.10",
            destination_port=443,
            protocol="tcp",
            observed_at=(start + timedelta(seconds=20 * index)).isoformat(),
        )
        for index in range(3)
    ]

    detector = BeaconDetector()

    events = detector.analyse_events(observations)

    assert events == []


def test_different_destinations_are_analysed_separately() -> None:
    start = datetime(2026, 8, 23, 13, 0, tzinfo=UTC)

    observations = []

    for index in range(3):
        observations.append(
            NetworkObservation(
                destination_ip="203.0.113.20",
                destination_port=443,
                protocol="tcp",
                observed_at=(start + timedelta(seconds=20 * index)).isoformat(),
            )
        )

        observations.append(
            NetworkObservation(
                destination_ip="203.0.113.21",
                destination_port=443,
                protocol="tcp",
                observed_at=(start + timedelta(seconds=20 * index)).isoformat(),
            )
        )

    detector = BeaconDetector()

    events = detector.analyse_events(observations)

    assert events == []

def test_different_ports_are_not_combined() -> None:
    start = datetime(2026, 8, 23, 14, 0, tzinfo=UTC)

    observations = []

    for index in range(3):
        observations.append(
            NetworkObservation(
                destination_ip="203.0.113.30",
                destination_port=443,
                protocol="tcp",
                observed_at=(start + timedelta(seconds=20 * index)).isoformat(),
            )
        )

        observations.append(
            NetworkObservation(
                destination_ip="203.0.113.30",
                destination_port=8443,
                protocol="tcp",
                observed_at=(start + timedelta(seconds=20 * index)).isoformat(),
            )
        )

    detector = BeaconDetector()

    events = detector.analyse_events(observations)

    assert events == []


def test_out_of_order_observations_are_sorted_before_analysis() -> None:
    start = datetime(2026, 8, 23, 15, 0, tzinfo=UTC)

    offsets = [80, 0, 60, 20, 40]

    observations = [
        NetworkObservation(
            destination_ip="198.51.100.20",
            destination_port=443,
            protocol="tcp",
            observed_at=(start + timedelta(seconds=offset)).isoformat(),
        )
        for offset in offsets
    ]

    detector = BeaconDetector()

    events = detector.analyse_events(observations)

    assert len(events) == 1
    assert events[0].destination_ip == "198.51.100.20"

    
