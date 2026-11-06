import threading
import time
from concurrent.futures import ThreadPoolExecutor

from database.models import ApprovalRequest, AuditLog
import main


def _request_approval(gateway):
    response = gateway["client"].post(
        "/check-action",
        headers=gateway["auth_headers"](gateway["agent"]),
        json={
            "agent": "customer_support_bot",
            "user": "customer_support_bot",
            "tool": "customer.export",
            "action": "export",
            "resource": "customer",
            "environment": "development",
            "records": 1,
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "HUMAN_APPROVAL"
    return response.json()


def test_approval_requires_reviewer_and_rejects_replay(isolated_gateway):
    gateway = isolated_gateway
    approval = _request_approval(gateway)
    decision = {
        "approval_id": approval["approval_id"],
        "approved": True,
    }

    denied = gateway["client"].post(
        "/approvals/decision",
        headers=gateway["auth_headers"](gateway["agent"]),
        json=decision,
    )
    assert denied.status_code == 403

    accepted = gateway["client"].post(
        "/approvals/decision",
        headers=gateway["auth_headers"](gateway["reviewer"]),
        json=decision,
    )
    assert accepted.status_code == 200
    assert accepted.json()["decision"] == "EXECUTION_UNAVAILABLE"
    assert accepted.json()["execution"]["executed"] is False
    assert "simulated" in accepted.json()["execution"]["message"].lower()

    replay = gateway["client"].post(
        "/approvals/decision",
        headers=gateway["auth_headers"](gateway["reviewer"]),
        json=decision,
    )
    assert replay.status_code == 400

    with gateway["session_factory"]() as db:
        persisted = db.query(ApprovalRequest).filter_by(
            id=approval["approval_id"]
        ).one()
        assert persisted.status == "EXECUTION_UNAVAILABLE"
        events = db.query(AuditLog).filter_by(
            approval_id=approval["approval_id"]
        ).all()
    assert [event.decision for event in events] == [
        "HUMAN_APPROVAL",
        "EXECUTION_UNAVAILABLE",
    ]


def test_concurrent_review_can_dispatch_an_approval_only_once(
    isolated_gateway, monkeypatch
):
    gateway = isolated_gateway
    approval = _request_approval(gateway)
    original_executor = main.execute_action
    calls = 0
    calls_lock = threading.Lock()

    def counted_executor(*args, **kwargs):
        nonlocal calls
        with calls_lock:
            calls += 1
        time.sleep(0.15)
        return original_executor(*args, **kwargs)

    monkeypatch.setattr(main, "execute_action", counted_executor)
    decision = {
        "approval_id": approval["approval_id"],
        "approved": True,
    }

    def decide():
        from fastapi.testclient import TestClient

        with TestClient(main.app) as client:
            return client.post(
                "/approvals/decision",
                headers=gateway["auth_headers"](gateway["reviewer"]),
                json=decision,
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(lambda _: decide(), range(2)))

    assert sorted(response.status_code for response in responses) == [200, 400]
    assert calls == 1
    with gateway["session_factory"]() as db:
        persisted = db.query(ApprovalRequest).filter_by(
            id=approval["approval_id"]
        ).one()
        assert persisted.status == "EXECUTION_UNAVAILABLE"


def test_duplicate_pending_approval_request_returns_same_request(isolated_gateway):
    gateway = isolated_gateway
    first = _request_approval(gateway)
    second = _request_approval(gateway)

    assert second["approval_id"] == first["approval_id"]
    assert second["status"] == "PENDING"
    assert second["duplicate"] is True
    with gateway["session_factory"]() as db:
        assert db.query(ApprovalRequest).count() == 1
