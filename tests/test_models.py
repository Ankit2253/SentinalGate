import pytest

from sentinelgate.models import Action, Direction, Protocol, Rule, normalize_port


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

