import os
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from config import load_environment

load_environment()
# The benchmark itself always uses its own in-memory engine; this URL only lets
# the imported ASGI application construct its unused module-level engine.
if not os.getenv("DATABASE_URL", "").strip():
    os.environ["DATABASE_URL"] = "sqlite://"

import database.database as database
import main
from auth.auth import create_access_token
from database.database import Base
from database.models import Agent, User
from models import ActionRequest
from security import anomaly_detection, audit_logger, policy_engine

from attack_benchmark.metrics import calculate_metrics
from attack_benchmark.reports import write_reports
from attack_benchmark.scenarios import Scenario, build_scenarios


def _seed_isolated_database(factory) -> None:
    agents = ("customer_support_bot", "admin_bot", "operator")
    users = [
        User(
            username=name,
            password_hash="benchmark-not-used",
            role="user" if name == "operator" else "agent",
            is_active=True,
        )
        for name in agents
    ]
    users.extend([
        User(
            username="reviewer",
            password_hash="benchmark-not-used",
            role="security_admin",
            is_active=True,
        ),
        User(
            username="inactive_agent",
            password_hash="benchmark-not-used",
            role="agent",
            is_active=False,
        ),
    ])
    with factory() as db:
        db.add_all([Agent(name=name) for name in agents])
        db.add_all(users)
        db.commit()


def _scenario_request(scenario: Scenario) -> ActionRequest:
    return ActionRequest(
        agent=scenario.agent_identity,
        user=scenario.authenticated_identity,
        tool=scenario.tool,
        action=scenario.action,
        resource=scenario.resource,
        environment=scenario.environment,
        records=scenario.records,
    )


def run_benchmark(
    report_dir: str | Path | None = None,
    write_output: bool = True,
) -> dict[str, Any]:
    """Run the real authenticated gateway against isolated data and safe doubles."""
    scenarios = build_scenarios()
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    _seed_isolated_database(factory)

    observations: list[dict[str, Any]] = []
    scenario_results: list[dict[str, Any]] = []
    rate_counts: dict[str, int] = {}

    def isolated_rate_limit(identity: str, limit: int):
        key = f"{identity}:{limit}"
        rate_counts[key] = rate_counts.get(key, 0) + 1
        allowed = rate_counts[key] <= limit
        return allowed, "Rate limit allowed" if allowed else "Rate limit exceeded"

    def simulated_tool_dispatch(_request):
        return {
            "status": "BENCHMARK_MOCK",
            "message": "No external tool or customer system was called.",
            "executed": True,
            "mocked": True,
        }

    def simulated_sandbox_dispatch(_request):
        return {
            "status": "BENCHMARK_MOCK",
            "message": "No sandbox container or external system was called.",
            "executed": True,
            "mocked": True,
        }

    try:
        with (
            patch.object(database, "SessionLocal", factory),
            patch.object(main, "SessionLocal", factory),
            patch.object(policy_engine, "SessionLocal", factory),
            patch.object(audit_logger, "SessionLocal", factory),
            patch.object(anomaly_detection, "SessionLocal", factory),
            patch.object(
                audit_logger,
                "score_action",
                return_value={
                    "available": False,
                    "risk_score": None,
                    "anomalous": False,
                    "reason": "Anomaly model is advisory and disabled in benchmark",
                },
            ),
            patch.object(main, "check_rate_limit", side_effect=isolated_rate_limit),
            patch.object(main, "execute_action", side_effect=simulated_tool_dispatch),
            patch.object(main, "execute_in_sandbox", side_effect=simulated_sandbox_dispatch),
        ):
            for scenario in scenarios:
                # Each scenario is a separate reproducible test window.
                rate_counts.clear()
                credentials = type(
                    "BenchmarkCredentials",
                    (),
                    {
                        "credentials": create_access_token(
                            scenario.authenticated_identity,
                            "agent",
                        ),
                    },
                )()
                request = _scenario_request(scenario)
                scenario_observations = []

                for attempt in range(1, scenario.repeat_count + 1):
                    started = time.perf_counter()
                    http_status = 200
                    dispatch_attempted = False
                    try:
                        response = main.check_action(request, credentials)
                        decision = response["decision"]
                        dispatch_attempted = (
                            decision == "ALLOW" and "execution" in response
                        ) or (
                            decision == "SANDBOX" and "execution" in response
                        )
                        reason = str(response.get("reason", ""))
                    except Exception as error:
                        from fastapi import HTTPException

                        if isinstance(error, HTTPException):
                            http_status = error.status_code
                            decision = "BLOCK"
                            reason = str(error.detail)
                        else:
                            raise
                    latency_ms = (time.perf_counter() - started) * 1000
                    observation = {
                        "scenario_id": scenario.scenario_id,
                        "attempt": attempt,
                        "category": scenario.category,
                        "is_attack": scenario.is_attack,
                        "authenticated_identity": scenario.authenticated_identity,
                        "agent_identity": scenario.agent_identity,
                        "tool": scenario.tool,
                        "action": scenario.action,
                        "resource": scenario.resource,
                        "environment": scenario.environment,
                        "records": scenario.records,
                        "expected_security_outcome": scenario.expected_security_outcome,
                        "decision": decision,
                        "dispatch_attempted": dispatch_attempted,
                        "http_status": http_status,
                        "latency_ms": round(latency_ms, 4),
                        "reason": reason,
                    }
                    observations.append(observation)
                    scenario_observations.append(observation)

                decisions = [row["decision"] for row in scenario_observations]
                if scenario.expected_security_outcome == "RATE_LIMITED":
                    outcome_met = "BLOCK" in decisions and "ALLOW" in decisions
                else:
                    outcome_met = all(
                        decision == scenario.expected_security_outcome
                        for decision in decisions
                    )
                scenario_results.append({
                    **scenario.as_dict(),
                    "observed_decisions": decisions,
                    "successful_attack_requests": sum(
                        scenario.is_attack and row["decision"] == "ALLOW"
                        for row in scenario_observations
                    ),
                    "expected_outcome_met": outcome_met,
                })

        report: dict[str, Any] = {
            "benchmark": "AgentShield controlled attack simulation",
            "version": 1,
            "methodology": {
                "policy_and_authentication": "Actual AgentShield main.check_action, database-backed JWT identity lookup, RBAC, and YAML policy evaluation.",
                "database": "Fresh in-memory SQLite database per run; seeded with synthetic agent accounts only.",
                "rate_limiting": "Local deterministic counter enforces the limit returned by the real policy path; Redis is never contacted.",
                "tool_execution": "Tool and sandbox executors are mocked and isolated; no external system or real data is accessed.",
                "anomaly_detection": "Risk scoring is replaced with an unavailable advisory signal; it is not part of authorization.",
                "attack_success_definition": "An attack request is counted successful only when the gateway decision is ALLOW. SANDBOX, BLOCK, and HUMAN_APPROVAL are not counted as successful external dispatch.",
                "detection_definition": "A malicious request is detected when its effective gateway result is BLOCK. Approval is preventive but not counted as attack detection.",
                "baseline_definition": "The simulated unprotected baseline has no authentication, policy, rate limiting, or dispatch gate; all attack requests are assumed dispatchable.",
                "reproducibility": "Scenario order, payloads, and local rate windows are deterministic; latency is measured and naturally varies between runs.",
            },
            "summary": calculate_metrics(
                [scenario.as_dict() for scenario in scenarios],
                observations,
            ),
            "scenarios": scenario_results,
            "observations": observations,
        }
        report["summary"]["expected_scenarios_met"] = sum(
            item["expected_outcome_met"] for item in scenario_results
        )
        report["summary"]["expected_scenario_mismatches"] = sum(
            not item["expected_outcome_met"] for item in scenario_results
        )

        if write_output:
            target_dir = Path(report_dir) if report_dir else (
                Path(__file__).resolve().parent / "reports"
            )
            report["report_files"] = write_reports(report, target_dir)
        return report
    finally:
        engine.dispose()
