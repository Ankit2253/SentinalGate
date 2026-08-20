from sentinelgate.c2guard import BeaconDetector
from sentinelgate.models import NetworkObservation


def _observation(timestamp: str) -> NetworkObservation:
    return NetworkObservation(
        destination_ip="203.0.113.50",
        destination_port=443,
        protocol="tcp",
        observed_at=timestamp,
    )


def test_detects_regular_beaconing() -> None:
    observations = [
        _observation("2026-08-20T12:00:00+00:00"),
        _observation("2026-08-20T12:00:20+00:00"),
        _observation("2026-08-20T12:00:40+00:00"),
        _observation("2026-08-20T12:01:00+00:00"),
        _observation("2026-08-20T12:01:20+00:00"),
    ]

    detector = BeaconDetector()

    detections = detector.analyse(observations)

    assert len(detections) == 1

    detection = detections[0]

    assert detection.destination_ip == "203.0.113.50"
    assert detection.destination_port == 443
    assert detection.protocol == "tcp"
    assert detection.observation_count == 5
    assert detection.mean_interval_seconds == 20.0
    assert detection.jitter_seconds == 0.0
    assert detection.confidence == 1.0


def test_ignores_insufficient_observations() -> None:
    observations = [
        _observation("2026-08-20T12:00:00+00:00"),
        _observation("2026-08-20T12:00:20+00:00"),
        _observation("2026-08-20T12:00:40+00:00"),
    ]

    detector = BeaconDetector(minimum_observations=5)

    assert detector.analyse(observations) == []


def test_ignores_high_jitter_activity() -> None:
    observations = [
        _observation("2026-08-20T12:00:00+00:00"),
        _observation("2026-08-20T12:00:07+00:00"),
        _observation("2026-08-20T12:00:34+00:00"),
        _observation("2026-08-20T12:01:10+00:00"),
        _observation("2026-08-20T12:01:25+00:00"),
    ]

    detector = BeaconDetector(maximum_jitter_seconds=2.0)

    assert detector.analyse(observations) == []


def test_groups_destinations_independently() -> None:
    observations = [
        _observation("2026-08-20T12:00:00+00:00"),
        _observation("2026-08-20T12:00:20+00:00"),
        _observation("2026-08-20T12:00:40+00:00"),
        _observation("2026-08-20T12:01:00+00:00"),
        _observation("2026-08-20T12:01:20+00:00"),
        NetworkObservation(
            destination_ip="198.51.100.25",
            destination_port=443,
            protocol="tcp",
            observed_at="2026-08-20T12:00:05+00:00",
        ),
    ]

    detector = BeaconDetector()

    detections = detector.analyse(observations)

    assert len(detections) == 1
    assert detections[0].destination_ip == "203.0.113.50"


def test_rejects_invalid_detector_configuration() -> None:
    try:
        BeaconDetector(minimum_observations=2)
    except ValueError as exc:
        assert "at least 3" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
