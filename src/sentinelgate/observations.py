"""Load safe outbound-connection observations from JSON Lines files."""

from __future__ import annotations

import json
from pathlib import Path

from sentinelgate.models import NetworkObservation

MAX_OBSERVATIONS = 10_000


def load_observations(
    source: str | Path,
) -> list[NetworkObservation]:
    """Load and validate network observations from a JSONL file."""

    path = Path(source)
    observations: list[NetworkObservation] = []

    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()

                if not stripped:
                    continue

                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"Invalid JSON on line {line_number}"
                    ) from exc

                if not isinstance(payload, dict):
                    raise TypeError(
                        f"Observation on line {line_number} must be an object"
                    )

                try:
                    observation = NetworkObservation(**payload)
                except (TypeError, ValueError) as exc:
                    raise ValueError(
                        f"Invalid observation on line {line_number}: {exc}"
                    ) from exc

                observations.append(observation)

                if len(observations) > MAX_OBSERVATIONS:
                    raise ValueError(
                        f"Observation file exceeds limit of "
                        f"{MAX_OBSERVATIONS}"
                    )
    except FileNotFoundError as exc:
        raise ValueError(
            f"Observation file not found: {path}"
        ) from exc

    return observations
