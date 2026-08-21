from sentinelgate.c2guard import BeaconDetector
from sentinelgate.intelligence import ThreatIntelligence
from sentinelgate.models import C2Detection, NetworkObservation, ThreatIndicator


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
    assert detection.jitter_ratio == 0.0


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
def test_detects_beacon_with_small_timing_variation() -> None:
    observations = [
        _observation("2026-08-20T12:00:00+00:00"),
        _observation("2026-08-20T12:00:20+00:00"),
        _observation("2026-08-20T12:00:41+00:00"),
        _observation("2026-08-20T12:01:00+00:00"),
        _observation("2026-08-20T12:01:20+00:00"),
        _observation("2026-08-20T12:01:41+00:00"),
    ]

    detector = BeaconDetector()

    detections = detector.analyse(observations)

    assert len(detections) == 1
    assert detections[0].mean_interval_seconds > 19
    assert detections[0].jitter_ratio < 0.15

def test_rejects_high_relative_jitter() -> None:
    observations = [
        _observation("2026-08-20T12:00:00+00:00"),
        _observation("2026-08-20T12:00:05+00:00"),
        _observation("2026-08-20T12:00:12+00:00"),
        _observation("2026-08-20T12:00:17+00:00"),
        _observation("2026-08-20T12:00:25+00:00"),
    ]

    detector = BeaconDetector(
        maximum_jitter_seconds=3.0,
        maximum_jitter_ratio=0.15,
    )

    assert detector.analyse(observations) == []


def test_rejects_invalid_jitter_ratio_configuration() -> None:
    try:
        BeaconDetector(maximum_jitter_ratio=1.5)
    except ValueError as exc:
        assert "between 0 and 1" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
def test_converts_detection_to_event() -> None:
    observations = [
        _observation("2026-08-20T12:00:00+00:00"),
        _observation("2026-08-20T12:00:20+00:00"),
        _observation("2026-08-20T12:00:40+00:00"),
        _observation("2026-08-20T12:01:00+00:00"),
        _observation("2026-08-20T12:01:20+00:00"),
    ]

    detector = BeaconDetector()

    events = detector.analyse_events(observations)

    assert len(events) == 1

    event = events[0]

    assert event.event_type == "suspected_c2_beacon"
    assert event.action == "detected"
    assert event.severity == "high"
    assert event.destination_ip == "203.0.113.50"
    assert event.destination_port == 443
    assert event.protocol == "tcp"
    assert event.details["observation_count"] == 5
    assert event.details["mean_interval_seconds"] == 20.0
    assert event.details["jitter_seconds"] == 0.0
    assert event.details["jitter_ratio"] == 0.0
    assert event.details["confidence"] == 1.0
    assert event.details["detector"] == "periodic_beacon"
def test_c2_event_severity_uses_confidence() -> None:

    detector = BeaconDetector()

    medium = detector.detection_to_event(
        C2Detection(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observation_count=5,
            mean_interval_seconds=20,
            jitter_seconds=1,
            jitter_ratio=0.05,
            confidence=0.70,
        )
    )

    low = detector.detection_to_event(
        C2Detection(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observation_count=5,
            mean_interval_seconds=20,
            jitter_seconds=1.5,
            jitter_ratio=0.075,
            confidence=0.40,
        )
    )

    assert medium.severity == "medium"
    assert low.severity == "low"
def test_enriches_event_with_threat_intelligence_match() -> None:
    intelligence = ThreatIntelligence(
        [
            ThreatIndicator(
                value="203.0.113.50",
                indicator_type="ip",
                confidence=0.95,
                source="synthetic-test-feed",
                description="Synthetic suspicious destination",
            )
        ]
    )

    detector = BeaconDetector(intelligence=intelligence)

    observations = [
        _observation("2026-08-20T12:00:00+00:00"),
        _observation("2026-08-20T12:00:20+00:00"),
        _observation("2026-08-20T12:00:40+00:00"),
        _observation("2026-08-20T12:01:00+00:00"),
        _observation("2026-08-20T12:01:20+00:00"),
    ]

    events = detector.analyse_events(observations)

    assert len(events) == 1

    event = events[0]

    assert event.details["threat_intelligence_match"] is True
    assert event.details["indicator"]["value"] == "203.0.113.50"
    assert event.details["indicator"]["confidence"] == 0.95
    assert event.details["indicator"]["source"] == "synthetic-test-feed"


def test_event_without_intelligence_match_remains_unmatched() -> None:
    intelligence = ThreatIntelligence(
        [
            ThreatIndicator(
                value="198.51.100.25",
                indicator_type="ip",
                confidence=0.95,
            )
        ]
    )

    detector = BeaconDetector(intelligence=intelligence)

    observations = [
        _observation("2026-08-20T12:00:00+00:00"),
        _observation("2026-08-20T12:00:20+00:00"),
        _observation("2026-08-20T12:00:40+00:00"),
        _observation("2026-08-20T12:01:00+00:00"),
        _observation("2026-08-20T12:01:20+00:00"),
    ]

    events = detector.analyse_events(observations)

    assert len(events) == 1
    assert events[0].details["threat_intelligence_match"] is False
    assert "indicator" not in events[0].details


def test_high_confidence_indicator_can_raise_event_severity() -> None:
    intelligence = ThreatIntelligence(
        [
            ThreatIndicator(
                value="203.0.113.50",
                indicator_type="ip",
                confidence=0.90,
            )
        ]
    )

    detector = BeaconDetector(intelligence=intelligence)

    detection = C2Detection(
        destination_ip="203.0.113.50",
        destination_port=443,
        protocol="tcp",
        observation_count=5,
        mean_interval_seconds=20,
        jitter_seconds=1,
        jitter_ratio=0.05,
        confidence=0.65,
    )

    event = detector.detection_to_event(detection)

    assert event.severity == "high"
    assert event.details["threat_intelligence_match"] is True
