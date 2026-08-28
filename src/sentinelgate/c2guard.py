"""Behavioural detection of suspicious periodic outbound connections."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from ipaddress import ip_address
from itertools import pairwise
from statistics import mean, pstdev

from sentinelgate.intelligence import ThreatIntelligence
from sentinelgate.models import C2Detection, Event, NetworkObservation


class BeaconDetector:
    """Detect unusually regular communication with the same destination."""

    def __init__(
        self,
        minimum_observations: int = 5,
        maximum_jitter_seconds: float = 2.0,
        maximum_jitter_ratio: float = 0.15,
        minimum_interval_seconds: float = 5.0,
        intelligence: ThreatIntelligence | None = None,
        trusted_destinations: set[str] | None = None,
        minimum_confidence: float = 0.50,
    ) -> None:
        self.minimum_observations = int(minimum_observations)
        self.maximum_jitter_seconds = float(maximum_jitter_seconds)
        self.maximum_jitter_ratio = float(maximum_jitter_ratio)
        self.minimum_interval_seconds = float(minimum_interval_seconds)
        self.intelligence = intelligence
        self.trusted_destinations = {
            str(ip_address(address))
            for address in (trusted_destinations or set())
        }
        self.minimum_confidence = float(minimum_confidence)
        
        if self.minimum_observations < 3:
            raise ValueError("minimum_observations must be at least 3")

        if self.maximum_jitter_seconds < 0:
            raise ValueError("maximum_jitter_seconds cannot be negative")
            
        if not 0.0 < self.maximum_jitter_ratio <= 1.0:
            raise ValueError("maximum_jitter_ratio must be between 0 and 1")

        if self.minimum_interval_seconds <= 0:
            raise ValueError("minimum_interval_seconds must be greater than zero")
       
        if not 0.0 <= self.minimum_confidence <= 1.0:
            raise ValueError("minimum_confidence must be between 0 and 1")

    def analyse(
        self,
        observations: list[NetworkObservation],
    ) -> list[C2Detection]:
        grouped: dict[
            tuple[str, int, str],
            list[NetworkObservation],
        ] = defaultdict(list)

        for observation in observations:
            key = (
                observation.destination_ip,
                observation.destination_port,
                observation.protocol,
            )
            grouped[key].append(observation)

        detections: list[C2Detection] = []

        for key, group in grouped.items():
            detection = self._analyse_group(key, group)
            if detection:
                detections.append(detection)

        return detections
        
    def analyse_events(
        self,
        observations: list[NetworkObservation],
    ) -> list[Event]:
        return [
            self.detection_to_event(detection)
            for detection in self.analyse(observations)
        ]
    def detection_to_event(self, detection: C2Detection) -> Event:
        """Convert a behavioural C2 detection into a SentinelGate event."""

        if detection.confidence >= 0.85:
            severity = "high"
        elif detection.confidence >= 0.60:
            severity = "medium"
        else:
            severity = "low"

        details = {
            "observation_count": detection.observation_count,
            "mean_interval_seconds": detection.mean_interval_seconds,
            "jitter_seconds": detection.jitter_seconds,
            "jitter_ratio": detection.jitter_ratio,
            "confidence": detection.confidence,
            "detector": "periodic_beacon",
            "threat_intelligence_match": False,
        }

        if self.intelligence is not None:
            indicator = self.intelligence.match_ip(detection.destination_ip)

            if indicator is not None:
                details["threat_intelligence_match"] = True
                details["indicator"] = indicator.to_dict()

                if indicator.confidence >= 0.80:
                    severity = "high"

        return Event(
            event_type="suspected_c2_beacon",
            severity=severity,
            action="detected",
            destination_ip=detection.destination_ip,
            destination_port=detection.destination_port,
            protocol=detection.protocol,
            details=details,
        )        
    
    def _analyse_group(
        self,
        key: tuple[str, int, str],
        observations: list[NetworkObservation],
    ) -> C2Detection | None:
        if len(observations) < self.minimum_observations:
            return None

        timestamps = sorted(
            datetime.fromisoformat(observation.observed_at)
            for observation in observations
        )

        intervals = [
            (current - previous).total_seconds()
            for previous, current in pairwise(timestamps)
        ]

        if not intervals:
            return None

        mean_interval = mean(intervals)

        if mean_interval < self.minimum_interval_seconds:
            return None

        jitter = pstdev(intervals)
        jitter_ratio = jitter / mean_interval

        if (
             jitter > self.maximum_jitter_seconds
             or jitter_ratio > self.maximum_jitter_ratio
        ):
             return None

        confidence = self._confidence(jitter, jitter_ratio)

        destination_ip, destination_port, protocol = key

        if confidence < self.minimum_confidence:
            return None

        if destination_ip in self.trusted_destinations:
            return None

        return C2Detection(
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            observation_count=len(observations),
            mean_interval_seconds=round(mean_interval, 3),
            jitter_seconds=round(jitter, 3),
            jitter_ratio=round(jitter_ratio, 3),
            confidence=round(confidence, 3),
        )

    def _confidence(
        self,
        jitter_seconds: float,
        jitter_ratio: float,
    ) -> float:
        if self.maximum_jitter_seconds == 0:
            absolute_score = 1.0 if jitter_seconds == 0 else 0.0
        else:
            absolute_score = 1.0 - (
                jitter_seconds / self.maximum_jitter_seconds
            )

        relative_score = 1.0 - (
            jitter_ratio / self.maximum_jitter_ratio
        )

        return max(
            0.0,
            min(1.0, (absolute_score + relative_score) / 2),
        )
	
