import os
os.environ["AGENTSHIELD_SECRET_KEY"] = "isolated-lifecycle-test-secret-key-32-bytes"
os.environ["AGENTSHIELD_CORS_ORIGINS"] = (
    "http://localhost:5173,http://127.0.0.1:5173"
)

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import database.database as database
import main
from auth.auth import hash_password
from database.database import Base
from database.models import Agent, User
from security import anomaly_detection, audit_logger, policy_engine
from tools import tool_executor


@pytest.fixture
def isolated_gateway(tmp_path, monkeypatch):
    database_path = tmp_path / "agentshield-lifecycle.sqlite3"
    engine = create_engine(
        f"sqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 10},
        pool_pre_ping=True,
    )
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    for module, attribute in (
        (database, "SessionLocal"),
        (main, "SessionLocal"),
        (audit_logger, "SessionLocal"),
        (policy_engine, "SessionLocal"),
        (anomaly_detection, "SessionLocal"),
        (tool_executor, "SessionLocal"),
    ):
        monkeypatch.setattr(module, attribute, session_factory)
    monkeypatch.setattr(main, "initialize_development_schema", lambda *_: None)
    monkeypatch.setattr(main, "check_rate_limit", lambda *_: (True, "allowed"))
    monkeypatch.setattr(anomaly_detection, "_MODEL", None)
    monkeypatch.setattr(anomaly_detection, "_VECTORIZER", None)
    monkeypatch.setattr(anomaly_detection, "_MODEL_CREATED_AT", 0.0)

    admin_password = "isolated-admin-password-12"
    reviewer_password = "isolated-reviewer-password"
    agent_password = "isolated-agent-password-12"
    with session_factory() as db:
        db.add_all(
            [
                User(
                    username="test_admin",
                    password_hash=hash_password(admin_password),
                    role="security_admin",
                    is_active=True,
                ),
                User(
                    username="test_reviewer",
                    password_hash=hash_password(reviewer_password),
                    role="reviewer",
                    is_active=True,
                ),
                Agent(name="customer_support_bot", description="Test agent"),
                User(
                    username="customer_support_bot",
                    password_hash=hash_password(agent_password),
                    role="agent",
                    is_active=True,
                ),
            ]
        )
        db.commit()

    with TestClient(main.app) as client:
        admin_login = client.post(
            "/auth/login",
            json={"username": "test_admin", "password": admin_password},
        )
        reviewer_login = client.post(
            "/auth/login",
            json={"username": "test_reviewer", "password": reviewer_password},
        )
        agent_login = client.post(
            "/auth/login",
            json={
                "username": "customer_support_bot",
                "password": agent_password,
            },
        )
        assert admin_login.status_code == 200
        assert reviewer_login.status_code == 200
        assert agent_login.status_code == 200
        yield {
            "client": client,
            "engine": engine,
            "session_factory": session_factory,
            "admin": admin_login.json(),
            "reviewer": reviewer_login.json(),
            "agent": agent_login.json(),
            "auth_headers": auth_headers,
        }

    engine.dispose()


def auth_headers(session):
    return {"Authorization": f"Bearer {session['access_token']}"}
