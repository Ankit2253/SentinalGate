import pytest

from sentinelgate.models import (
    Action,
    C2Detection,
    Direction,
    NetworkObservation,
    Protocol,
    Rule,
    normalize_port,
)


def test_rule_normalizes_network_and_port() -> None:
    rule = Rule(
        name="Allow application",
        direction="input",
        action="allow",
        protocol="tcp",
        source="10.10.4.23/16",
        destination_port="8000-8100",
    )

    assert rule.source == "10.10.0.0/16"
    assert rule.destination_port == "8000-8100"
    assert rule.direction is Direction.INPUT
    assert rule.action is Action.ALLOW
    assert rule.protocol is Protocol.TCP


@pytest.mark.parametrize("value", ["0", "65536", "100-99", "ssh", "22; drop"])
def test_invalid_ports_are_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_port(value)


def test_ports_require_tcp_or_udp() -> None:
    with pytest.raises(ValueError, match="TCP or UDP"):
        Rule(
            name="Invalid any-port rule",
            direction="input",
            action="block",
            protocol="any",
            destination_port=22,
        )


def test_mixed_ip_families_are_rejected() -> None:
    with pytest.raises(ValueError, match="same IP family"):
        Rule(
            name="Mixed family",
            direction="forward",
            action="block",
            protocol="tcp",
            source="10.0.0.0/8",
            destination="2001:db8::/32",
        )


def test_serialization_round_trip() -> None:
    original = Rule(
        name="Block SSH",
        direction="input",
        action="block",
        protocol="tcp",
        destination_port=22,
        priority=20,
    )
    restored = Rule.from_dict(original.to_dict())
    assert restored.to_dict() == original.to_dict()

def test_network_observation_validates_values() -> None:
    observation = NetworkObservation(
        destination_ip="203.0.113.50",
        destination_port=443,
        protocol="TCP",
    )

    assert observation.destination_ip == "203.0.113.50"
    assert observation.destination_port == 443
    assert observation.protocol == "tcp"


def test_network_observation_rejects_invalid_port() -> None:
    with pytest.raises(ValueError):
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=70000,
            protocol="tcp",
        )


def test_network_observation_rejects_invalid_protocol() -> None:
    with pytest.raises(ValueError):
        NetworkObservation(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="icmp",
        )


def test_c2_detection_validates_values() -> None:
    detection = C2Detection(
        destination_ip="203.0.113.50",
        destination_port=443,
        protocol="tcp",
        observation_count=6,
        mean_interval_seconds=20,
        jitter_seconds=0.5,
        confidence=0.92,
    )

    assert detection.observation_count == 6
    assert detection.mean_interval_seconds == 20.0
    assert detection.confidence == 0.92


def test_c2_detection_rejects_invalid_confidence() -> None:
    with pytest.raises(ValueError):
        C2Detection(
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            observation_count=6,
            mean_interval_seconds=20,
            jitter_seconds=0.5,
            confidence=1.5,
        )
