from models import ActionRequest
from security.audit_logger import log_event


def _action(tool, action, resource):
    return ActionRequest(
        agent="customer_support_bot",
        user="customer_support_bot",
        tool=tool,
        action=action,
        resource=resource,
        environment="development",
        records=1,
    )


def test_rate_limit_denial_is_authoritative_and_audited(
    isolated_gateway, monkeypatch
):
    import main

    monkeypatch.setattr(
        main,
        "check_rate_limit",
        lambda *_: (False, "test rate limit exceeded"),
    )
    response = isolated_gateway["client"].post(
        "/check-action",
        headers=isolated_gateway["auth_headers"](isolated_gateway["agent"]),
        json={
            "agent": "customer_support_bot",
            "user": "customer_support_bot",
            "tool": "customer.lookup",
            "action": "read",
            "resource": "customer",
            "environment": "development",
            "records": 1,
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["reason"] == "test rate limit exceeded"
    assert response.json()["audit"]["decision"] == "BLOCK"


def test_anomaly_model_uses_history_without_overriding_block(
    isolated_gateway,
):
    for _ in range(20):
        log_event(
            _action("customer.lookup", "read", "customer"),
            "ALLOW",
            "Controlled benign training event",
        )

    response = isolated_gateway["client"].post(
        "/check-action",
        headers=isolated_gateway["auth_headers"](isolated_gateway["agent"]),
        json={
            "agent": "customer_support_bot",
            "user": "customer_support_bot",
            "tool": "credential.dump",
            "action": "export",
            "resource": "secrets",
            "environment": "production",
            "records": 5000,
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["audit"]["risk_score"] is not None
    assert isinstance(response.json()["audit"]["anomaly_detected"], bool)

    summary = isolated_gateway["client"].get(
        "/security/summary",
        headers=isolated_gateway["auth_headers"](isolated_gateway["reviewer"]),
    )
    assert summary.status_code == 200
    assert summary.json()["total_events"] >= 21
    assert summary.json()["blocked_actions"] >= 1


def test_dashboard_security_apis_return_persisted_events_and_valid_hash_chain(
    isolated_gateway,
):
    client = isolated_gateway["client"]
    reviewer_headers = isolated_gateway["auth_headers"](
        isolated_gateway["reviewer"]
    )
    agent_headers = isolated_gateway["auth_headers"](isolated_gateway["agent"])

    action = client.post(
        "/check-action",
        headers=agent_headers,
        json={
            "agent": "customer_support_bot",
            "user": "customer_support_bot",
            "tool": "customer.lookup",
            "action": "read",
            "resource": "customer",
            "environment": "development",
            "records": 1,
        },
    )
    assert action.status_code == 200
    event_id = action.json()["audit"]["event_id"]

    audit = client.get("/audit-logs", headers=reviewer_headers)
    assert audit.status_code == 200
    assert any(event["event_id"] == event_id for event in audit.json()["audit_logs"])

    integrity = client.get("/audit-logs/integrity", headers=reviewer_headers)
    assert integrity.status_code == 200
    assert integrity.json()["verified"] is True

    forbidden = client.get("/audit-logs", headers=agent_headers)
    assert forbidden.status_code == 403
