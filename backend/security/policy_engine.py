import json
from pathlib import Path
from typing import Any

from database.database import SessionLocal
from database.models import Agent, PolicyVersion, User


POLICY_FILE = Path(__file__).resolve().parents[1] / "policies" / "agentshield.yaml"
VALID_DECISIONS = {"ALLOW", "BLOCK", "HUMAN_APPROVAL", "SANDBOX"}
SUPPORTED_MATCH_FIELDS = {
    "agent",
    "tool",
    "resource",
    "action",
    "environment",
    "max_records",
    "subject_roles",
}


def validate_policy_document(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict) or not isinstance(policy.get("rules"), list):
        raise RuntimeError("Policy file must contain a rules list")
    if policy.get("default_decision", "BLOCK") != "BLOCK":
        raise RuntimeError("Policy default decision must remain BLOCK")
    required_roles = policy.get("required_subject_roles", ["agent"])
    if (
        not isinstance(required_roles, list)
        or not required_roles
        or any(not isinstance(role, str) or not role for role in required_roles)
    ):
        raise RuntimeError("Policy required_subject_roles must be a nonempty role list")
    if not isinstance(policy.get("version"), int) or policy["version"] < 1:
        raise RuntimeError("Policy version must be a positive integer")
    rule_ids = set()
    for rule in policy["rules"]:
        if not isinstance(rule, dict):
            raise RuntimeError("Each policy rule must be an object")
        rule_id = rule.get("id")
        match = rule.get("match")
        if not isinstance(rule_id, str) or not rule_id or rule_id in rule_ids:
            raise RuntimeError("Each policy rule must have a unique nonempty id")
        if rule.get("decision") not in VALID_DECISIONS:
            raise RuntimeError(f"Unsupported policy decision in rule {rule_id}")
        if not isinstance(match, dict) or set(match) - SUPPORTED_MATCH_FIELDS:
            raise RuntimeError(f"Invalid match fields in policy rule {rule_id}")
        for field in ("agent", "tool", "resource", "action"):
            if field in match and not isinstance(match[field], str):
                raise RuntimeError(f"Policy field {field} must be a string")
        if "environment" in match and not isinstance(match["environment"], (str, list)):
            raise RuntimeError(f"Policy environment must be a string or list in {rule_id}")
        if "environment" in match and isinstance(match["environment"], list) and (
            not match["environment"]
            or any(not isinstance(value, str) or not value for value in match["environment"])
        ):
            raise RuntimeError(f"Policy environment list is invalid in {rule_id}")
        if "subject_roles" in match and (
            not isinstance(match["subject_roles"], list)
            or not match["subject_roles"]
            or any(not isinstance(role, str) or not role for role in match["subject_roles"])
        ):
            raise RuntimeError(f"Policy subject_roles must be a nonempty role list in {rule_id}")
        if not isinstance(rule.get("reason"), str) or not rule["reason"].strip():
            raise RuntimeError(f"Policy reason must be nonempty in {rule_id}")
        rate_limit = rule.get("rate_limit")
        max_records = match.get("max_records")
        if rate_limit is not None and (
            not isinstance(rate_limit, int) or isinstance(rate_limit, bool) or rate_limit <= 0
        ):
            raise RuntimeError(f"Invalid rate limit in policy rule {rule_id}")
        if max_records is not None and (
            not isinstance(max_records, int) or isinstance(max_records, bool) or max_records < 0
        ):
            raise RuntimeError(f"Invalid record ceiling in policy rule {rule_id}")
        rule_ids.add(rule_id)
    conflicts = find_policy_conflicts(policy["rules"])
    if conflicts:
        pair = conflicts[0]
        raise RuntimeError(
            f"Conflicting overlapping policy rules: {pair[0]} and {pair[1]}"
        )
    return policy


def _read_policy() -> dict[str, Any]:
    try:
        # JSON is a strict subset of YAML 1.2, keeping the runtime dependency-free.
        with POLICY_FILE.open("r", encoding="utf-8") as policy_file:
            policy = json.load(policy_file)
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError("Unable to load AgentShield policy-as-code file") from error
    return validate_policy_document(policy)


def _condition_values(rule: dict[str, Any], key: str) -> set[str]:
    value = rule.get("match", {}).get(key, "*")
    if key in {"environment", "subject_roles"}:
        if isinstance(value, str):
            return {value}
        return set(value)
    return {value}


def _rules_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool:
    for field in (
        "agent",
        "tool",
        "resource",
        "action",
        "environment",
        "subject_roles",
    ):
        left_values = _condition_values(left, field)
        right_values = _condition_values(right, field)
        if (
            "*" not in left_values
            and "*" not in right_values
            and not left_values.intersection(right_values)
        ):
            return False
    return True


def find_policy_conflicts(rules: list[dict[str, Any]]) -> list[tuple[str, str]]:
    return [
        (left["id"], right["id"])
        for index, left in enumerate(rules)
        for right in rules[index + 1 :]
        if left.get("decision") != right.get("decision")
        and _rules_overlap(left, right)
    ]


POLICY_DOCUMENT = _read_policy()


def get_active_policy_document() -> dict[str, Any]:
    db = SessionLocal()
    try:
        latest = db.query(PolicyVersion).order_by(
            PolicyVersion.version.desc()
        ).first()
        if not latest:
            return POLICY_DOCUMENT
        document = json.loads(latest.document_json)
        return validate_policy_document(document)
    except (json.JSONDecodeError, RuntimeError) as error:
        raise RuntimeError("Persisted AgentShield policy is invalid") from error
    finally:
        db.close()


def check_action_policy(
    agent_name: str,
    resource: str,
    action: str,
    environment: str,
    records: int,
    ignore_approval: bool = False,
    tool: str | None = None,
    policy_document: dict[str, Any] | None = None,
) -> dict[str, Any]:
    active_policy = policy_document or get_active_policy_document()
    if records < 0:
        return {
            "decision": "BLOCK",
            "reason": "Record count cannot be negative",
            "rate_limit": None,
        }

    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.name == agent_name).first()
        identity = db.query(User).filter(User.username == agent_name).first()
        if (
            not agent
            or not identity
            or not identity.is_active
            or identity.role not in active_policy["required_subject_roles"]
        ):
            return {
                "decision": "BLOCK",
                "reason": "Unknown, inactive, or unauthorized agent",
                "rate_limit": None,
            }
    finally:
        db.close()

    subject_role = identity.role
    for rule in active_policy["rules"]:
        match = rule.get("match", {})
        if not isinstance(match, dict):
            raise RuntimeError("Policy rule match must be an object")
        if match.get("agent", "*") not in ("*", agent_name):
            continue
        if tool is not None and match.get("tool", "*") not in ("*", tool):
            continue
        if match.get("resource", "*") not in ("*", resource):
            continue
        if match.get("action", "*").lower() not in ("*", action.lower()):
            continue
        environments = match.get("environment", ["*"])
        if isinstance(environments, str):
            environments = [environments]
        if "*" not in environments and environment not in environments:
            continue
        roles = match.get("subject_roles")
        if roles is not None and (subject_role is None or subject_role not in roles):
            continue

        max_records = match.get("max_records")
        if max_records is not None and records > max_records:
            return {
                "decision": "BLOCK",
                "reason": f"Record limit exceeded: maximum {max_records}, requested {records}",
                "rate_limit": rule.get("rate_limit"),
            }

        decision = rule.get("decision", "BLOCK")
        if decision not in VALID_DECISIONS:
            raise RuntimeError(f"Unsupported policy decision: {decision}")
        if decision == "HUMAN_APPROVAL" and ignore_approval:
            decision = "ALLOW"
        return {
            "decision": decision,
            "reason": rule.get("reason", "Policy matched"),
            "rate_limit": rule.get("rate_limit"),
            "policy_id": rule.get("id"),
        }

    return {
        "decision": active_policy["default_decision"],
        "reason": "No policy rule matched",
        "rate_limit": None,
    }
