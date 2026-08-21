from fastapi.testclient import TestClient

from sentinelgate.api import create_app
from sentinelgate.config import AppConfig
from sentinelgate.models import Event
from sentinelgate.service import FirewallService


def test_dashboard_api_rule_and_apply_flow(service: FirewallService) -> None:
    client = TestClient(create_app(service))
    status_response = client.get("/api/status")
    assert status_response.status_code == 200
    assert status_response.json()["mode"] == "dry-run"
    assert status_response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in status_response.headers["content-security-policy"]

    created = client.post(
        "/api/rules",
        json={
            "name": "Block Telnet",
            "direction": "input",
            "action": "block",
            "protocol": "tcp",
            "destination_port": 23,
        },
    )
    assert created.status_code == 201
    rule_id = created.json()["id"]
    assert len(client.get("/api/rules").json()) == 1

    applied = client.post("/api/apply", json={"reason": "API test"})
    assert applied.status_code == 200
    assert applied.json()["dry_run"] is True

    deleted = client.delete(f"/api/rules/{rule_id}")
    assert deleted.status_code == 204


def test_invalid_api_rule_is_rejected(service: FirewallService) -> None:
    client = TestClient(create_app(service))
    response = client.post(
        "/api/rules",
        json={
            "name": "Invalid",
            "direction": "input",
            "action": "block",
            "protocol": "any",
            "destination_port": "22; accept",
        },
    )
    assert response.status_code == 422


def test_bearer_token_is_enforced(app_config: AppConfig, monkeypatch) -> None:
    monkeypatch.setenv("SENTINELGATE_TEST_TOKEN", "a-long-test-token")
    app_config.server.token_env = "SENTINELGATE_TEST_TOKEN"
    service = FirewallService(app_config)
    client = TestClient(create_app(service))

    assert client.get("/api/status").status_code == 401
    response = client.get(
        "/api/status", headers={"Authorization": "Bearer a-long-test-token"}
    )
    assert response.status_code == 200


def test_non_loopback_without_token_is_rejected(app_config: AppConfig) -> None:
    app_config.server.host = "0.0.0.0"
    app_config.server.token_env = "SENTINELGATE_MISSING_TOKEN"
    try:
        app_config.validate()
    except ValueError as exc:
        assert "non-loopback" in str(exc)
    else:
        raise AssertionError("Non-loopback startup should require a token")


def test_c2_alerts_endpoint_returns_stored_alert(service) -> None:
    service.database.add_event(
        Event(
            event_type="suspected_c2_beacon",
            severity="high",
            action="detected",
            destination_ip="203.0.113.50",
            destination_port=443,
            protocol="tcp",
            details={
                "confidence": 0.95,
                "detector": "periodic_beacon",
            },
        )
    )

    client = TestClient(create_app(service))

    response = client.get("/api/c2/alerts")

    assert response.status_code == 200

    payload = response.json()

    assert len(payload) == 1
    assert payload[0]["event_type"] == "suspected_c2_beacon"
    assert payload[0]["destination_ip"] == "203.0.113.50"
