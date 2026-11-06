import os
import unittest
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

os.environ["AGENTSHIELD_SECRET_KEY"] = (
    "test-only-secret-key-with-at-least-32-bytes"
)
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["AGENTSHIELD_CORS_ORIGINS"] = (
    "http://localhost:5173,http://127.0.0.1:5173"
)

import redis
from fastapi import HTTPException
from fastapi.testclient import TestClient
from fastapi.security import HTTPAuthorizationCredentials
from starlette.websockets import WebSocketDisconnect
from sqlalchemy.exc import OperationalError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import database.database as database
import main
from auth.auth import create_access_token, get_current_user, hash_password
from database.database import Base
from database.models import Agent, AuditLog, BenchmarkRun, User, UserPreference
from models import ActionRequest, ApprovalDecision, LoginRequest
from security import audit_logger, rate_limiter
from security import policy_engine
from security import anomaly_detection
from tools.sandbox_executor import execute_in_sandbox
from tools.tool_executor import execute_action
from database import create_agent


class SecurityControlsTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )
        Base.metadata.create_all(self.engine)
        self.session_factory = sessionmaker(
            bind=self.engine,
            expire_on_commit=False
        )
        self.session_local_patch = patch.object(
            database,
            "SessionLocal",
            self.session_factory
        )
        self.audit_session_patch = patch.object(
            audit_logger,
            "SessionLocal",
            self.session_factory
        )
        self.policy_session_patch = patch.object(
            policy_engine,
            "SessionLocal",
            self.session_factory
        )
        self.main_session_patch = patch.object(
            main,
            "SessionLocal",
            self.session_factory
        )
        self.anomaly_session_patch = patch.object(
            anomaly_detection,
            "SessionLocal",
            self.session_factory
        )
        self.session_local_patch.start()
        self.audit_session_patch.start()
        self.policy_session_patch.start()
        self.main_session_patch.start()
        self.anomaly_session_patch.start()

        with self.session_factory() as db:
            db.add_all([
                Agent(
                    name="customer_support_bot",
                    description="Test agent"
                ),
                Agent(
                    name="new_agent",
                    description="Provisioning test agent"
                ),
                Agent(
                    name="admin_bot",
                    description="Test administrative agent"
                ),
                User(
                    username="customer_support_bot",
                    password_hash="test-hash",
                    role="agent",
                    is_active=True
                ),
                User(
                    username="admin_bot",
                    password_hash="test-hash",
                    role="agent",
                    is_active=True
                ),
                User(
                    username="inactive_agent",
                    password_hash="test-hash",
                    role="agent",
                    is_active=False
                ),
                User(
                    username="reviewer",
                    password_hash="test-hash",
                    role="security_admin",
                    is_active=True
                )
            ])
            db.commit()

    def tearDown(self):
        self.audit_session_patch.stop()
        self.policy_session_patch.stop()
        self.main_session_patch.stop()
        self.anomaly_session_patch.stop()
        self.session_local_patch.stop()
        Base.metadata.drop_all(self.engine)
        self.engine.dispose()

    @staticmethod
    def credentials(username, role):
        return HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials=create_access_token(username, role)
        )

    @staticmethod
    def action_request(agent, user):
        return ActionRequest(
            agent=agent,
            user=user,
            tool="test",
            action="read",
            resource="customer",
            environment="development"
        )

    def test_current_user_uses_active_database_role(self):
        user = get_current_user(
            self.credentials("customer_support_bot", "security_admin")
        )

        self.assertEqual(user["role"], "agent")

    def test_inactive_account_cannot_use_existing_token(self):
        with self.assertRaises(HTTPException) as raised:
            get_current_user(
                self.credentials("inactive_agent", "agent")
            )

        self.assertEqual(raised.exception.status_code, 401)

    def test_reviewer_can_login_and_validate_jwt(self):
        password = "reviewer-test-password"
        with self.session_factory() as db:
            reviewer = db.query(User).filter_by(username="reviewer").one()
            reviewer.password_hash = hash_password(password)
            db.commit()

        with (
            patch.object(main, "check_rate_limit", return_value=(True, "allowed")),
            TestClient(main.app) as client,
        ):
            login = client.post(
                "/auth/login",
                json={"username": "reviewer", "password": password},
            )
            self.assertEqual(login.status_code, 200)
            login_data = login.json()
            self.assertEqual(login_data["role"], "security_admin")
            self.assertTrue(login_data["access_token"])

            current_user = client.get(
                "/auth/me",
                headers={"Authorization": f"Bearer {login_data['access_token']}"},
            )

        self.assertEqual(current_user.status_code, 200)
        self.assertEqual(current_user.json()["username"], "reviewer")
        self.assertEqual(current_user.json()["role"], "security_admin")

    def test_login_returns_service_unavailable_for_database_auth_failure(self):
        session_state = {"rolled_back": False, "closed": False}

        class UnavailableSession:
            @staticmethod
            def query(_model):
                raise OperationalError(
                    "SELECT users",
                    {},
                    RuntimeError("database authentication failed"),
                )

            @staticmethod
            def rollback():
                session_state["rolled_back"] = True

            @staticmethod
            def close():
                session_state["closed"] = True

        with (
            patch.object(main, "check_rate_limit", return_value=(True, "allowed")),
            patch.object(main, "SessionLocal", return_value=UnavailableSession()),
            TestClient(main.app) as client,
        ):
            response = client.post(
                "/auth/login",
                json={
                    "username": "reviewer",
                    "password": "valid-test-password",
                },
            )

        self.assertEqual(response.status_code, 503)
        self.assertIn("DATABASE_URL", response.json()["detail"])
        self.assertTrue(session_state["rolled_back"])
        self.assertTrue(session_state["closed"])

    def test_invalid_reviewer_password_returns_401(self):
        with self.session_factory() as db:
            reviewer = db.query(User).filter_by(username="reviewer").one()
            reviewer.password_hash = hash_password("valid-reviewer-password")
            db.commit()

        with (
            patch.object(main, "check_rate_limit", return_value=(True, "allowed")),
            TestClient(main.app) as client,
        ):
            response = client.post(
                "/auth/login",
                json={
                    "username": "reviewer",
                    "password": "invalid-reviewer-password",
                },
            )

        self.assertEqual(response.status_code, 401)

    def test_health_endpoint_checks_the_configured_database(self):
        with (
            patch.object(main.rate_limit_redis, "ping", return_value=True),
            TestClient(main.app) as client,
        ):
            response = client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["database"], "available")
        self.assertEqual(response.json()["redis"], "available")

    def test_health_endpoint_returns_503_when_database_is_unavailable(self):
        unavailable_engine = Mock()
        unavailable_engine.connect.side_effect = OperationalError(
            "SELECT 1",
            {},
            RuntimeError("database unavailable"),
        )
        with (
            patch.object(main, "engine", unavailable_engine),
            TestClient(main.app) as client,
        ):
            response = client.get("/health")

        self.assertEqual(response.status_code, 503)

    def test_health_endpoint_returns_503_when_redis_is_unavailable(self):
        with (
            patch.object(
                main.rate_limit_redis,
                "ping",
                side_effect=redis.ConnectionError("redis unavailable"),
            ),
            TestClient(main.app) as client,
        ):
            response = client.get("/health")

        self.assertEqual(response.status_code, 503)
        self.assertIn("Redis", response.json()["detail"])

    def test_cors_preflight_allows_both_local_vite_origins(self):
        with TestClient(main.app) as client:
            for origin in ("http://localhost:5173", "http://127.0.0.1:5173"):
                response = client.options(
                    "/auth/login",
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "POST",
                        "Access-Control-Request-Headers": "content-type",
                    },
                )
                self.assertEqual(response.status_code, 200, origin)
                self.assertEqual(
                    response.headers.get("access-control-allow-origin"),
                    origin,
                )
                self.assertNotIn(
                    "access-control-allow-credentials",
                    response.headers,
                )
            blocked = client.options(
                "/auth/login",
                headers={
                    "Origin": "https://untrusted.example",
                    "Access-Control-Request-Method": "POST",
                },
            )
            self.assertEqual(blocked.status_code, 400)
            self.assertNotIn("access-control-allow-origin", blocked.headers)

    def test_dashboard_data_endpoints_are_reviewer_only_and_well_shaped(self):
        reviewer_headers = {
            "Authorization": f"Bearer {self.credentials('reviewer', 'security_admin').credentials}"
        }
        agent_headers = {
            "Authorization": f"Bearer {self.credentials('customer_support_bot', 'agent').credentials}"
        }

        with TestClient(main.app) as client:
            for path in (
                "/approvals/history",
                "/audit-logs",
                "/security/summary",
                "/security/policies",
                "/agents",
            ):
                response = client.get(path, headers=reviewer_headers)
                self.assertEqual(response.status_code, 200, path)
                self.assertIsInstance(response.json(), dict)

                denied = client.get(path, headers=agent_headers)
                self.assertEqual(denied.status_code, 403, path)

            policy_response = client.get(
                "/security/policies",
                headers=reviewer_headers,
            )
            self.assertEqual(policy_response.json()["default_decision"], "BLOCK")

            agents_response = client.get("/agents", headers=reviewer_headers)
            agent = next(
                item for item in agents_response.json()["agents"]
                if item["name"] == "customer_support_bot"
            )
            self.assertIn("permissions", agent)
            self.assertNotIn("password", agent)

    def test_new_user_defaults_to_non_privileged_role(self):
        with self.session_factory() as db:
            user = User(
                username="new_user",
                password_hash="test-hash"
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        self.assertEqual(user.role, "user")

    def test_rejection_requires_a_nonempty_reason(self):
        with self.assertRaises(ValueError):
            ApprovalDecision(approval_id=1, approved=False)
        with self.assertRaises(ValueError):
            ApprovalDecision(
                approval_id=1,
                approved=False,
                rejection_reason="   ",
            )
        self.assertEqual(
            ApprovalDecision(approval_id=1, approved=True).approved,
            True,
        )

    def test_yaml_policy_is_deny_by_default_and_environment_aware(self):
        development = policy_engine.check_action_policy(
            "customer_support_bot",
            "customer",
            "update",
            "development",
            1,
        )
        production = policy_engine.check_action_policy(
            "customer_support_bot",
            "customer",
            "update",
            "production",
            1,
        )
        unknown = policy_engine.check_action_policy(
            "customer_support_bot",
            "customer",
            "unknown",
            "development",
            1,
        )

        self.assertEqual(development["decision"], "ALLOW")
        self.assertEqual(production["decision"], "BLOCK")
        self.assertEqual(unknown["decision"], "BLOCK")

    def test_isolation_forest_only_returns_risk_signal(self):
        with self.session_factory() as db:
            db.add_all([
                AuditLog(
                    agent="customer_support_bot",
                    user="customer_support_bot",
                    tool="demo",
                    action="read",
                    resource="customer",
                    environment="development",
                    records=index % 4,
                    decision="ALLOW",
                    reason="approved baseline",
                )
                for index in range(25)
            ])
            db.commit()

        signal = anomaly_detection.score_action(
            self.action_request(
                "customer_support_bot",
                "customer_support_bot"
            )
        )

        self.assertTrue(signal["available"])
        self.assertIsInstance(signal["risk_score"], float)
        self.assertNotIn("decision", signal)

    def test_anomaly_features_use_observed_agent_and_tool_frequencies(self):
        from security.anomaly_detection import _features

        observed_at = datetime.now()
        history = [
            AuditLog(
                agent="customer_support_bot",
                user="customer_support_bot",
                tool="customer.lookup",
                action="read",
                resource="customer",
                environment="development",
                records=1,
                decision="ALLOW",
                reason="baseline",
                timestamp=observed_at - timedelta(seconds=30),
            )
            for _ in range(2)
        ]
        familiar = self.action_request(
            "customer_support_bot",
            "customer_support_bot",
        )
        familiar.tool = "customer.lookup"
        novel = self.action_request(
            "customer_support_bot",
            "customer_support_bot",
        )
        novel.tool = "billing.export"

        familiar_features = anomaly_detection._features(
            familiar, history, observed_at
        )
        novel_features = _features(novel, history, observed_at)
        self.assertGreater(
            familiar_features["agent_tool_count"],
            novel_features["agent_tool_count"],
        )
        self.assertAlmostEqual(
            familiar_features["agent_recent_event_count"],
            1.0986122886681096,
        )
        self.assertEqual(novel_features["agent_tool_count"], 0.0)

    def test_agent_provisioning_requires_registered_agent(self):
        with patch.object(create_agent, "SessionLocal", self.session_factory), patch.dict(
            os.environ,
            {
                "AGENTSHIELD_AGENT_USERNAME": "new_agent",
                "AGENTSHIELD_AGENT_PASSWORD": "test-agent-password"
            }
        ):
            create_agent.create_agent_user()

        with self.session_factory() as db:
            agent_user = db.query(User).filter_by(
                username="new_agent"
            ).one()
            self.assertEqual(agent_user.role, "agent")

        with patch.object(create_agent, "SessionLocal", self.session_factory), patch.dict(
            os.environ,
            {
                "AGENTSHIELD_AGENT_USERNAME": "not_registered",
                "AGENTSHIELD_AGENT_PASSWORD": "test-agent-password"
            }
        ):
            with self.assertRaises(RuntimeError):
                create_agent.create_agent_user()

    def test_check_action_binds_user_and_agent_to_token(self):
        request = self.action_request(
            "customer_support_bot",
            "spoofed-user"
        )
        credentials = self.credentials(
            "customer_support_bot",
            "agent"
        )
        logged_users = []

        with (
            patch.object(
                main,
                "check_action_policy",
                return_value={
                    "decision": "BLOCK",
                    "reason": "test",
                    "rate_limit": None
                }
            ),
            patch.object(
                main,
                "log_event",
                side_effect=lambda action, *args: (
                    logged_users.append(action.user) or {}
                )
            )
        ):
            main.check_action(request, credentials)

        self.assertEqual(logged_users, ["customer_support_bot"])

    def test_check_action_rejects_mismatched_agent(self):
        request = self.action_request(
            "admin_bot",
            "customer_support_bot"
        )

        with self.assertRaises(HTTPException) as raised:
            main.check_action(
                request,
                self.credentials("customer_support_bot", "agent")
            )

        self.assertEqual(raised.exception.status_code, 403)

    def test_duplicate_pending_approvals_reuse_existing_request(self):
        request = self.action_request("admin_bot", "admin_bot")
        request.action = "export"
        request.records = 100
        token = self.credentials("admin_bot", "agent")
        with (
            patch.object(
                main,
                "check_action_policy",
                return_value={
                    "decision": "HUMAN_APPROVAL",
                    "reason": "review",
                    "rate_limit": None,
                },
            ),
            patch.object(main, "log_event", return_value={}),
        ):
            first = main.check_action(request, token)
            second = main.check_action(request, token)

        self.assertEqual(first["approval_id"], second["approval_id"])
        self.assertTrue(second["duplicate"])
        with self.session_factory() as db:
            self.assertEqual(db.query(main.ApprovalRequest).count(), 1)

    def test_reviewer_cannot_call_agent_action_endpoint(self):
        with self.assertRaises(HTTPException) as raised:
            main.check_action(
                self.action_request("reviewer", "reviewer"),
                self.credentials("reviewer", "security_admin")
            )

        self.assertEqual(raised.exception.status_code, 403)

    def test_agent_cannot_view_reviewer_approval_queue(self):
        with self.assertRaises(HTTPException) as raised:
            main.get_approvals(
                self.credentials("customer_support_bot", "security_admin")
            )

        self.assertEqual(raised.exception.status_code, 403)

    def test_agent_simulation_mediates_each_action(self):
        from models import AgentSimulationRequest

        credentials = self.credentials("customer_support_bot", "agent")
        simulation = AgentSimulationRequest(actions=[
            self.action_request("spoofed", "spoofed"),
            self.action_request("spoofed", "spoofed"),
        ])
        with patch.object(
            main,
            "check_action",
            side_effect=[{"decision": "ALLOW"}, {"decision": "BLOCK"}],
        ) as gateway:
            response = main.simulate_agent(simulation, credentials)

        self.assertEqual(response["tool_calls_mediated"], 2)
        self.assertEqual(gateway.call_count, 2)

    def test_http_action_endpoint_requires_agent_and_preserves_contract(self):
        token = self.credentials("customer_support_bot", "security_admin")
        payload = self.action_request(
            "customer_support_bot",
            "untrusted-user"
        ).model_dump()
        payload["tool"] = "customer.lookup"
        with (
            patch.object(
                main,
                "check_action_policy",
                return_value={
                    "decision": "ALLOW",
                    "reason": "test allowed",
                    "rate_limit": None,
                },
            ),
            patch.object(main, "log_event", return_value={"id": 1}),
            TestClient(main.app) as client,
        ):
            response = client.post(
                "/check-action",
                headers={"Authorization": f"Bearer {token.credentials}"},
                json=payload,
            )
            reviewer_response = client.post(
                "/check-action",
                headers={
                    "Authorization": (
                        "Bearer "
                        + self.credentials(
                            "reviewer",
                            "security_admin"
                        ).credentials
                    )
                },
                json=payload,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["decision"], "ALLOW")
        self.assertFalse(response.json()["execution"]["executed"])
        self.assertEqual(reviewer_response.status_code, 403)

    def test_login_is_rate_limited_by_client_ip(self):
        request = type(
            "HttpRequest",
            (),
            {"client": type("Client", (), {"host": "127.0.0.1"})()}
        )()

        with patch.object(
            main,
            "check_rate_limit",
            return_value=(False, "Rate limit exceeded")
        ) as check_limit:
            with self.assertRaises(HTTPException) as raised:
                main.login(
                    LoginRequest(username="unknown", password="password"),
                    request
                )

        self.assertEqual(raised.exception.status_code, 429)
        self.assertEqual(
            check_limit.call_args.args,
            ("login:127.0.0.1", 10)
        )

    def test_audit_events_are_persisted(self):
        event = audit_logger.log_event(
            self.action_request("customer_support_bot", "customer_support_bot"),
            "BLOCK",
            "test"
        )

        self.assertGreater(event["id"], 0)
        with self.session_factory() as db:
            self.assertEqual(db.query(AuditLog).count(), 1)

    def test_audit_hash_chain_detects_record_tampering(self):
        first = audit_logger.log_event(
            self.action_request("customer_support_bot", "customer_support_bot"),
            "ALLOW",
            "first event",
        )
        second = audit_logger.log_event(
            self.action_request("customer_support_bot", "customer_support_bot"),
            "BLOCK",
            "second event",
        )
        self.assertEqual(second["previous_hash"], first["event_hash"])

        headers = {
            "Authorization": (
                "Bearer "
                + self.credentials("reviewer", "security_admin").credentials
            )
        }
        with TestClient(main.app) as client:
            response = client.get("/audit-logs/integrity", headers=headers)
            self.assertTrue(response.json()["verified"])

            with self.session_factory() as db:
                row = db.query(AuditLog).filter_by(id=first["id"]).one()
                row.reason = "modified outside the audit writer"
                db.commit()

            response = client.get("/audit-logs/integrity", headers=headers)

        self.assertFalse(response.json()["verified"])
        self.assertEqual(response.json()["first_invalid_id"], first["id"])

    def test_agent_event_submission_is_policy_evaluated_and_never_executed(self):
        payload = {
            "event_type": "unauthorized_tool_invocation",
            "tool": "customer.lookup",
            "action": "read",
            "resource": "customer",
            "environment": "development",
            "records": 1,
            "evidence": "Attempt stopped; token=example-sensitive-value",
        }
        with (
            patch.object(
                main,
                "check_rate_limit",
                return_value=(True, "allowed"),
            ),
            patch.object(
                main,
                "check_action_policy",
                return_value={
                    "decision": "BLOCK",
                    "reason": "No matching permission",
                    "rate_limit": None,
                },
            ),
            TestClient(main.app) as client,
        ):
            response = client.post(
                "/security/events/ingest",
                headers={
                    "Authorization": (
                        "Bearer "
                        + self.credentials(
                            "customer_support_bot", "agent"
                        ).credentials
                    )
                },
                json=payload,
            )
            reviewer_response = client.post(
                "/security/events/ingest",
                headers={
                    "Authorization": (
                        "Bearer "
                        + self.credentials(
                            "reviewer", "security_admin"
                        ).credentials
                    )
                },
                json=payload,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(reviewer_response.status_code, 403)
        body = response.json()
        self.assertEqual(body["policy_decision"], "BLOCK")
        self.assertFalse(body["executed"])
        self.assertEqual(body["event"]["severity"], "CRITICAL")
        with self.session_factory() as db:
            saved = db.query(AuditLog).one()
            self.assertEqual(saved.event_type, payload["event_type"])
            self.assertEqual(
                saved.evidence,
                "Attempt stopped; token=[REDACTED]",
            )

    def test_live_event_stream_requires_reviewer_and_delivers_persisted_events(self):
        reviewer_token = self.credentials("reviewer", "security_admin").credentials
        protocols = [
            "agentshield.events.v1",
            f"agentshield.jwt.{reviewer_token}",
        ]
        with TestClient(main.app) as client:
            with client.websocket_connect(
                "/security/stream",
                subprotocols=protocols,
                headers={"origin": "http://localhost:5173"},
            ) as websocket:
                audit_logger.log_event(
                    self.action_request(
                        "customer_support_bot", "customer_support_bot"
                    ),
                    "BLOCK",
                    "stream test",
                )
                message = websocket.receive_json()
                self.assertEqual(message["type"], "security_event")
                self.assertEqual(message["event"]["reason"], "stream test")

            agent_token = self.credentials(
                "customer_support_bot", "agent"
            ).credentials
            with self.assertRaises(WebSocketDisconnect):
                with client.websocket_connect(
                    "/security/stream",
                    subprotocols=[
                        "agentshield.events.v1",
                        f"agentshield.jwt.{agent_token}",
                    ],
                    headers={"origin": "http://localhost:5173"},
                ):
                    pass

    def test_rate_limit_uses_atomic_script_and_fails_closed(self):
        with patch.object(rate_limiter.redis_client, "eval", return_value=2) as eval_script:
            allowed, _ = rate_limiter.check_rate_limit(
                "customer_support_bot",
                3
            )

        self.assertTrue(allowed)
        self.assertEqual(
            eval_script.call_args.args[0],
            rate_limiter.INCREMENT_WITH_EXPIRY
        )

        with patch.object(
            rate_limiter.redis_client,
            "eval",
            side_effect=[
                redis.RedisError("redis unavailable"),
                1,
            ],
        ):
            with self.assertRaises(HTTPException) as raised:
                rate_limiter.check_rate_limit(
                    "customer_support_bot",
                    3
                )
            recovered, _ = rate_limiter.check_rate_limit(
                "customer_support_bot",
                3
            )

        self.assertEqual(raised.exception.status_code, 503)
        self.assertTrue(recovered)

    def test_placeholder_executors_never_claim_execution(self):
        request = self.action_request(
            "customer_support_bot",
            "customer_support_bot"
        )
        request.tool = "customer.lookup"

        self.assertFalse(execute_action(request)["executed"])
        with self.assertRaises(PermissionError):
            execute_in_sandbox(request)

    def test_negative_record_count_is_rejected(self):
        with self.assertRaises(ValueError):
            ActionRequest(
                agent="customer_support_bot",
                user="customer_support_bot",
                tool="test",
                action="read",
                resource="customer",
                environment="development",
                records=-1
            )

    def test_agent_management_is_admin_only_and_persists_identity_state(self):
        admin_headers = {
            "Authorization": (
                "Bearer "
                + self.credentials("reviewer", "security_admin").credentials
            )
        }
        reviewer = User(
            username="read_only_reviewer",
            password_hash="test-hash",
            role="reviewer",
            is_active=True,
        )
        with self.session_factory() as db:
            db.add(reviewer)
            db.commit()
        reviewer_headers = {
            "Authorization": (
                "Bearer "
                + self.credentials("read_only_reviewer", "reviewer").credentials
            )
        }
        payload = {
            "name": "new_registered_agent",
            "password": "secure-initial-password",
            "description": "created by a regression test",
        }

        with TestClient(main.app) as client:
            denied = client.post(
                "/agents",
                headers=reviewer_headers,
                json=payload,
            )
            created = client.post(
                "/agents",
                headers=admin_headers,
                json=payload,
            )
            suspended = client.patch(
                "/agents/new_registered_agent/status",
                headers=admin_headers,
                json={"active": False},
            )
            reactivated = client.patch(
                "/agents/new_registered_agent/status",
                headers=admin_headers,
                json={"active": True},
            )

        self.assertEqual(denied.status_code, 403)
        self.assertEqual(created.status_code, 201)
        self.assertTrue(created.json()["active"])
        self.assertEqual(suspended.status_code, 200)
        self.assertEqual(suspended.json()["status"], "suspended")
        self.assertEqual(reactivated.status_code, 200)
        self.assertEqual(reactivated.json()["status"], "active")
        with self.session_factory() as db:
            identity = db.query(User).filter_by(
                username="new_registered_agent"
            ).one()
            self.assertNotEqual(identity.password_hash, payload["password"])
            self.assertTrue(identity.is_active)

    def test_account_preferences_are_persisted_per_user(self):
        headers = {
            "Authorization": (
                "Bearer "
                + self.credentials("reviewer", "security_admin").credentials
            )
        }
        with TestClient(main.app) as client:
            initial = client.get("/settings/preferences", headers=headers)
            saved = client.put(
                "/settings/preferences",
                headers=headers,
                json={
                    "animations_enabled": False,
                    "refresh_seconds": 60,
                    "auto_refresh": False,
                    "compact_mode": True,
                    "notifications_enabled": True,
                    "critical_notifications_only": True,
                    "desktop_notifications": False,
                },
            )
            loaded = client.get("/settings/preferences", headers=headers)

        self.assertEqual(initial.status_code, 200)
        self.assertEqual(
            initial.json(),
            {
                "animations_enabled": True,
                "refresh_seconds": 15,
                "auto_refresh": True,
                "compact_mode": False,
                "notifications_enabled": True,
                "critical_notifications_only": False,
                "desktop_notifications": False,
            },
        )
        self.assertEqual(saved.status_code, 200)
        self.assertEqual(
            loaded.json(),
            {
                "animations_enabled": False,
                "refresh_seconds": 60,
                "auto_refresh": False,
                "compact_mode": True,
                "notifications_enabled": True,
                "critical_notifications_only": True,
                "desktop_notifications": False,
            },
        )
        with self.session_factory() as db:
            self.assertEqual(db.query(UserPreference).count(), 1)

    def test_policy_update_versions_documents_and_rejects_stale_writes(self):
        headers = {
            "Authorization": (
                "Bearer "
                + self.credentials("reviewer", "security_admin").credentials
            )
        }
        with (
            patch.object(main, "log_event", return_value={"id": 1}),
            TestClient(main.app) as client,
        ):
            current = client.get("/security/policies", headers=headers).json()
            payload = {
                "expected_version": current["version"],
                "default_decision": current["default_decision"],
                "required_subject_roles": current["required_subject_roles"],
                "rules": current["rules"],
            }
            updated = client.post(
                "/security/policies",
                headers=headers,
                json=payload,
            )
            stale = client.post(
                "/security/policies",
                headers=headers,
                json=payload,
            )
            history = client.get(
                "/security/policies/history",
                headers=headers,
            )

        self.assertEqual(updated.status_code, 200, updated.text)
        self.assertEqual(updated.json()["version"], current["version"] + 1)
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(
            history.json()["versions"][0]["version"],
            updated.json()["version"],
        )

    def test_benchmark_result_and_summary_are_persisted(self):
        report = {
            "summary": {"scenario_count": 160, "f1_score": 0.9},
            "scenarios": [{"scenario_id": "TEST-001"}],
            "methodology": {"executor": "mocked"},
        }
        headers = {
            "Authorization": (
                "Bearer "
                + self.credentials("reviewer", "security_admin").credentials
            )
        }
        with (
            patch(
                "attack_benchmark.runner.run_benchmark",
                return_value=report,
            ),
            TestClient(main.app) as client,
        ):
            created = client.post("/security/benchmark", headers=headers)
            run_id = created.json()["run_id"]
            history = client.get("/security/benchmark/runs", headers=headers)
            detail = client.get(
                f"/security/benchmark/runs/{run_id}",
                headers=headers,
            )

        self.assertEqual(created.status_code, 200)
        self.assertEqual(history.json()["runs"][0]["summary"], report["summary"])
        self.assertEqual(detail.json()["scenarios"], report["scenarios"])
        with self.session_factory() as db:
            self.assertEqual(db.query(BenchmarkRun).count(), 1)

    def test_policy_dry_run_never_executes_an_action(self):
        headers = {
            "Authorization": (
                "Bearer "
                + self.credentials("reviewer", "security_admin").credentials
            )
        }
        payload = self.action_request(
            "customer_support_bot",
            "customer_support_bot",
        ).model_dump()
        with (
            patch.object(
                main,
                "check_action_policy",
                return_value={
                    "decision": "BLOCK",
                    "reason": "denied by test policy",
                    "rate_limit": None,
                },
            ),
            TestClient(main.app) as client,
        ):
            result = client.post(
                "/security/policies/dry-run",
                headers=headers,
                json=payload,
            )

        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json()["dry_run"])
        self.assertFalse(result.json()["executed"])
        self.assertEqual(result.json()["decision"], "BLOCK")

    def test_summary_metrics_respect_requested_time_window(self):
        audit_logger.log_event(
            self.action_request(
                "customer_support_bot",
                "customer_support_bot",
            ),
            "BLOCK",
            "summary regression event",
        )
        headers = {
            "Authorization": (
                "Bearer "
                + self.credentials("reviewer", "security_admin").credentials
            )
        }
        with TestClient(main.app) as client:
            response = client.get(
                "/security/summary?hours=1",
                headers=headers,
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["hours"], 1)
        self.assertEqual(body["total_events"], 1)
        self.assertEqual(body["blocked_actions"], 1)
        self.assertGreaterEqual(body["agents"]["total"], body["agents"]["active"])
        self.assertEqual(sum(event["count"] for event in body["events_over_time"]), 1)

    def test_anomaly_evaluation_reports_synthetic_holdout_metrics(self):
        headers = {
            "Authorization": (
                "Bearer "
                + self.credentials("reviewer", "security_admin").credentials
            )
        }
        with TestClient(main.app) as client:
            response = client.get(
                "/security/anomaly/evaluation",
                headers=headers,
            )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body["available"])
        self.assertGreater(body["training_benign"], 0)
        self.assertGreater(body["test_attacks"], 0)
        self.assertGreater(body["test_benign"], 0)
        self.assertGreaterEqual(body["precision"], 0)
        self.assertLessEqual(body["precision"], 1)
        self.assertGreaterEqual(body["recall"], 0)
        self.assertLessEqual(body["recall"], 1)
        self.assertIn("Synthetic benchmark labels", body["limitations"])


if __name__ == "__main__":
    unittest.main()
