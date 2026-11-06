import csv
import json
import os
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

os.environ["AGENTSHIELD_CORS_ORIGINS"] = (
    "http://localhost:5173,http://127.0.0.1:5173"
)

import main
from attack_benchmark.runner import run_benchmark
from attack_benchmark.scenarios import build_scenarios
from auth.auth import require_reviewer


def test_scenario_dataset_has_unique_ids_and_required_coverage():
    scenarios = build_scenarios()
    identifiers = [scenario.scenario_id for scenario in scenarios]
    attack_categories = {
        scenario.category for scenario in scenarios if scenario.is_attack
    }

    assert len(identifiers) == len(set(identifiers))
    assert sum(scenario.is_attack for scenario in scenarios) >= 100
    assert sum(not scenario.is_attack for scenario in scenarios) >= 50
    assert {
        "unauthorized_tool_access",
        "privilege_escalation",
        "prompt_injection",
        "sensitive_data_exfiltration",
        "destructive_database_operation",
        "excessive_record_extraction",
        "rate_limit_abuse",
        "environment_policy_violation",
        "identity_spoofing",
        "repeated_malicious_actions",
    } <= attack_categories
    for scenario in scenarios:
        assert scenario.agent_identity
        assert scenario.tool
        assert scenario.action
        assert scenario.resource
        assert scenario.environment
        assert scenario.expected_security_outcome
        assert scenario.explanation


def test_runner_uses_gateway_calculates_metrics_and_writes_reports(tmp_path):
    report = run_benchmark(report_dir=tmp_path)
    summary = report["summary"]

    assert summary["attack_scenarios"] >= 100
    assert summary["legitimate_scenarios"] >= 50
    assert summary["attack_requests"] == 380
    assert summary["expected_scenario_mismatches"] == 0
    assert summary["category_results"]["legitimate_action"][
        "accepted_legitimate_requests"
    ] == summary["legitimate_requests"]
    assert summary["category_results"]["legitimate_action"][
        "successful_attack_requests"
    ] == 0
    assert summary["baseline_comparison"]["unprotected_agent"][
        "successful_attack_requests"
    ] == summary["attack_requests"]
    assert summary["baseline_comparison"]["agentshield_protected"][
        "successful_attack_requests"
    ] < summary["attack_requests"]
    assert 0.0 <= summary["false_positive_rate"] <= 1.0
    assert 0.0 <= summary["false_negative_rate"] <= 1.0
    assert 0.0 <= summary["legitimate_action_acceptance_rate"] <= 1.0
    assert set(summary["decision_distribution"]) == {
        "ALLOW", "BLOCK", "SANDBOX", "HUMAN_APPROVAL"
    }
    assert sum(
        decision["count"]
        for decision in summary["decision_distribution"].values()
    ) == summary["attack_requests"] + summary["legitimate_requests"]

    json_report = report["report_files"]["json"]
    csv_report = report["report_files"]["csv"]
    assert json.loads(Path(json_report).read_text(encoding="utf-8"))["summary"] == summary
    with Path(csv_report).open(newline="", encoding="utf-8") as csv_file:
        rows = list(csv.DictReader(csv_file))
    assert len(rows) == summary["attack_requests"] + summary["legitimate_requests"]
    assert all(row["dispatch_attempted"] in {"True", "False"} for row in rows)


def test_benchmark_endpoint_requires_reviewer():
    with (
        patch.object(
            main,
            "get_current_user",
            return_value={"username": "agent", "role": "agent"},
        ),
        TestClient(main.app) as client,
    ):
        response = client.post(
            "/security/benchmark",
            headers={"Authorization": "Bearer benchmark-test"},
        )
    assert response.status_code == 403

    report = {
        "summary": {"scenario_count": 160},
        "scenarios": [],
        "methodology": {"decision_authority": "deterministic policy"},
    }
    with (
        patch.object(
            main,
            "get_current_user",
            return_value={"username": "reviewer", "role": "security_admin"},
        ),
        patch(
            "attack_benchmark.runner.run_benchmark",
            return_value=report,
        ) as benchmark,
        TestClient(main.app) as client,
    ):
        response = client.post(
            "/security/benchmark",
            headers={"Authorization": "Bearer benchmark-test"},
        )

    assert response.status_code == 200
    response_body = response.json()
    assert response_body["summary"] == report["summary"]
    assert response_body["scenarios"] == report["scenarios"]
    assert response_body["methodology"] == report["methodology"]
    assert isinstance(response_body["run_id"], int)
    assert isinstance(response_body["started_at"], str)
    benchmark.assert_called_once_with(write_output=False)
