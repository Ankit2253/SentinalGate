"""Behavioural detection of suspicious periodic outbound connections."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from itertools import pairwise
from statistics import mean, pstdev

from sentinelgate.models import C2Detection, NetworkObservation


class BeaconDetector:
    """Detect unusually regular communication with the same destination."""

    def __init__(
        self,
        minimum_observations: int = 5,
        maximum_jitter_seconds: float = 2.0,
        maximum_jitter_ratio: float = 0.15,
        minimum_interval_seconds: float = 5.0,
    ) -> None:
        self.minimum_observations = int(minimum_observations)
        self.maximum_jitter_seconds = float(maximum_jitter_seconds)
        self.maximum_jitter_ratio = float(maximum_jitter_ratio)
        self.minimum_interval_seconds = float(minimum_interval_seconds)

        if self.minimum_observations < 3:
            raise ValueError("minimum_observations must be at least 3")

        if self.maximum_jitter_seconds < 0:
            raise ValueError("maximum_jitter_seconds cannot be negative")
            
        if not 0.0 < self.maximum_jitter_ratio <= 1.0:
            raise ValueError("maximum_jitter_ratio must be between 0 and 1")

        if self.minimum_interval_seconds <= 0:
            raise ValueError("minimum_interval_seconds must be greater than zero")

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
