import uuid

from database.models import AuditLog, User

def _action_payload(
    agent, *, tool, action, resource, environment="development", user=None
):
    return {
        "agent": agent,
        "user": user or agent,
        "tool": tool,
        "action": action,
        "resource": resource,
        "environment": environment,
        "records": 1,
    }


def test_registration_authentication_policy_and_audit_lifecycle(isolated_gateway):
    client = isolated_gateway["client"]
    admin_headers = isolated_gateway["auth_headers"](isolated_gateway["admin"])
    name = f"lifecycle_agent_{uuid.uuid4().hex[:8]}"
    password = "lifecycle-agent-password-12"

    registered = client.post(
        "/agents",
        headers=admin_headers,
        json={
            "name": name,
            "description": "Integration-test agent",
            "password": password,
        },
    )
    assert registered.status_code == 201
    assert registered.json()["name"] == name

    login = client.post(
        "/auth/login",
        json={"username": name, "password": password},
    )
    assert login.status_code == 200
    agent_headers = isolated_gateway["auth_headers"](login.json())
    assert client.get("/auth/me", headers=agent_headers).status_code == 200

    allowed = client.post(
        "/check-action",
        headers=agent_headers,
        json=_action_payload(
            name,
            tool="unknown.safe.read",
            action="read",
            resource="public-record",
        ),
    )
    assert allowed.status_code == 200
    assert allowed.json()["decision"] == "BLOCK"
    assert allowed.json()["audit"]["decision"] == "BLOCK"

    support_headers = isolated_gateway["auth_headers"](isolated_gateway["agent"])
    legitimate = client.post(
        "/check-action",
        headers=support_headers,
        json=_action_payload(
            "customer_support_bot",
            tool="customer.lookup",
            action="read",
            resource="customer",
        ),
    )
    assert legitimate.status_code == 200
    assert legitimate.json()["decision"] == "ALLOW"
    assert legitimate.json()["audit"]["decision"] == "ALLOW"

    denied = client.post(
        "/check-action",
        headers=support_headers,
        json=_action_payload(
            "customer_support_bot",
            tool="customer.delete",
            action="delete",
            resource="customer",
        ),
    )
    assert denied.status_code == 200
    assert denied.json()["decision"] == "BLOCK"

    with isolated_gateway["session_factory"]() as db:
        decisions = {
            entry.decision
            for entry in db.query(AuditLog).filter(
                AuditLog.agent.in_([name, "customer_support_bot"])
            )
        }
    assert {"ALLOW", "BLOCK"} <= decisions


def test_agent_identity_is_bound_to_action_and_inactive_accounts_are_rejected(
    isolated_gateway,
):
    client = isolated_gateway["client"]
    agent_headers = isolated_gateway["auth_headers"](isolated_gateway["agent"])

    spoofed = client.post(
        "/check-action",
        headers=agent_headers,
        json=_action_payload(
            "admin_bot",
            tool="customer.lookup",
            action="read",
            resource="customer",
        ),
    )
    assert spoofed.status_code == 403

    with isolated_gateway["session_factory"]() as db:
        identity = db.query(User).filter_by(username="customer_support_bot").one()
        identity.is_active = False
        db.commit()
    rejected = client.post(
        "/auth/login",
        json={
            "username": "customer_support_bot",
            "password": "isolated-agent-password-12",
        },
    )
    assert rejected.status_code == 401


def test_cors_preflight_allows_dashboard_management_methods(isolated_gateway):
    client = isolated_gateway["client"]

    for origin in ("http://127.0.0.1:5173", "http://localhost:5173"):
        response = client.options(
            "/agents/example/status",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "PATCH",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin
        assert "PATCH" in response.headers["access-control-allow-methods"]


def test_expired_and_missing_credentials_do_not_access_protected_data(
    isolated_gateway,
):
    import jwt
    from datetime import datetime, timedelta, timezone

    from config import get_secret_key

    expired = jwt.encode(
        {
            "sub": "test_reviewer",
            "role": "reviewer",
            "iat": datetime.now(timezone.utc) - timedelta(hours=2),
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        },
        get_secret_key(),
        algorithm="HS256",
    )
    client = isolated_gateway["client"]
    assert client.get("/audit-logs").status_code == 401
    response = client.get(
        "/audit-logs",
        headers={"Authorization": f"Bearer {expired}"},
    )
    assert response.status_code == 401
