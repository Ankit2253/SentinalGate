"""Local threat-intelligence matching for SentinelGate."""

from __future__ import annotations

from sentinelgate.models import ThreatIndicator


class ThreatIntelligence:
    def __init__(self, indicators: list[ThreatIndicator] | None = None) -> None:
        self._indicators = indicators or []

    def add(self, indicator: ThreatIndicator) -> None:
        self._indicators.append(indicator)

    def match_ip(self, address: str) -> ThreatIndicator | None:
        for indicator in self._indicators:
            if indicator.indicator_type == "ip" and indicator.value == address:
                return indicator
        return None

    def list_indicators(self) -> list[ThreatIndicator]:
        return list(self._indicators)
