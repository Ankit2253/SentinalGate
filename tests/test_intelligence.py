from sentinelgate.intelligence import ThreatIntelligence
from sentinelgate.models import ThreatIndicator


def test_matches_known_suspicious_ip() -> None:
    indicator = ThreatIndicator(
        value="203.0.113.50",
        indicator_type="ip",
        confidence=0.95,
        source="test-feed",
        description="Synthetic suspicious destination",
    )

    intelligence = ThreatIntelligence([indicator])

    match = intelligence.match_ip("203.0.113.50")

    assert match is not None
    assert match.value == "203.0.113.50"
    assert match.confidence == 0.95


def test_returns_none_for_unknown_ip() -> None:
    intelligence = ThreatIntelligence(
        [
            ThreatIndicator(
                value="203.0.113.50",
                indicator_type="ip",
                confidence=0.95,
            )
        ]
    )

    assert intelligence.match_ip("198.51.100.25") is None


def test_adds_indicator() -> None:
    intelligence = ThreatIntelligence()

    intelligence.add(
        ThreatIndicator(
            value="203.0.113.50",
            indicator_type="ip",
            confidence=0.80,
        )
    )

    assert len(intelligence.list_indicators()) == 1
