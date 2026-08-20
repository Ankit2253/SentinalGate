import json

import pytest

from sentinelgate.observations import load_observations


def _payload(
    observed_at: str = "2026-08-20T12:00:00+00:00",
) -> dict[str, object]:
    return {
        "destination_ip": "203.0.113.50",
        "destination_port": 443,
        "protocol": "tcp",
        "observed_at": observed_at,
    }


def test_loads_jsonl_observations(tmp_path) -> None:
    source = tmp_path / "observations.jsonl"
    source.write_text(
        "\n".join(
            [
                json.dumps(_payload()),
                "",
                json.dumps(
                    _payload("2026-08-20T12:00:20+00:00")
                ),
            ]
        ),
        encoding="utf-8",
    )

    observations = load_observations(source)

    assert len(observations) == 2
    assert observations[0].destination_ip == "203.0.113.50"
    assert observations[1].destination_port == 443


def test_rejects_malformed_json(tmp_path) -> None:
    source = tmp_path / "broken.jsonl"
    source.write_text(
        '{"destination_ip":',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Invalid JSON on line 1",
    ):
        load_observations(source)


def test_rejects_invalid_observation(tmp_path) -> None:
    source = tmp_path / "invalid.jsonl"
    payload = _payload()
    payload["protocol"] = "icmp"

    source.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Invalid observation on line 1",
    ):
        load_observations(source)


def test_reports_missing_file(tmp_path) -> None:
    source = tmp_path / "missing.jsonl"

    with pytest.raises(
        ValueError,
        match="Observation file not found",
    ):
        load_observations(source)
