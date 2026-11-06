import math
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from database.database import SessionLocal
from database.models import AuditLog


MINIMUM_TRAINING_EVENTS = 20
BENIGN_DECISIONS = ("ALLOW", "EXECUTED", "EXECUTION_UNAVAILABLE")
MODEL_REFRESH_SECONDS = 60
_MODEL = None
_VECTORIZER = None
_MODEL_CREATED_AT = 0.0
_MODEL_LOCK = threading.Lock()


def _features(
    request: Any,
    history: list[AuditLog],
    observed_at: datetime | None = None,
) -> dict[str, str | float]:
    timestamp = observed_at or getattr(request, "timestamp", None)
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).replace(tzinfo=None)
    elif timestamp.tzinfo is not None:
        timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)

    agent_history = [row for row in history if row.agent == request.agent]
    latest_agent_event = max(
        (row.timestamp for row in agent_history if row.timestamp is not None),
        default=None,
    )
    recent_events = sum(
        1
        for row in agent_history
        if row.timestamp is not None
        and 0 <= (timestamp - row.timestamp).total_seconds() <= 300
    )
    blocked_events = sum(row.decision == "BLOCK" for row in agent_history)
    agent_count = len(agent_history)

    return {
        "agent": request.agent.lower(),
        "tool": request.tool.lower(),
        "action": request.action.lower(),
        "resource": request.resource.lower(),
        "environment": request.environment.lower(),
        "records_log": math.log1p(max(request.records, 0)),
        "agent_seen": float(agent_count > 0),
        "agent_event_count": math.log1p(agent_count),
        "agent_recent_event_count": math.log1p(recent_events),
        "agent_block_rate": blocked_events / agent_count if agent_count else 0.0,
        "agent_tool_count": math.log1p(
            sum(row.tool == request.tool for row in agent_history)
        ),
        "agent_action_count": math.log1p(
            sum(row.action == request.action for row in agent_history)
        ),
        "agent_resource_count": math.log1p(
            sum(row.resource == request.resource for row in agent_history)
        ),
        "agent_environment_count": math.log1p(
            sum(row.environment == request.environment for row in agent_history)
        ),
        "agent_unique_tools": float(len({row.tool for row in agent_history})),
        "seconds_since_agent_event": (
            min(3600.0, max(0.0, (timestamp - latest_agent_event).total_seconds()))
            if latest_agent_event is not None
            else 3600.0
        ),
    }


def score_action(request: Any) -> dict[str, Any]:
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.feature_extraction import DictVectorizer
    except ImportError:
        return {
            "available": False,
            "risk_score": None,
            "anomalous": False,
            "reason": "scikit-learn is not installed",
        }

    db = SessionLocal()
    try:
        history = db.query(AuditLog).order_by(
            AuditLog.timestamp.desc()
        ).limit(500).all()
    finally:
        db.close()

    timeline = list(reversed(history))
    benign = [row for row in timeline if row.decision in BENIGN_DECISIONS]
    if len(benign) < MINIMUM_TRAINING_EVENTS:
        return {
            "available": True,
            "risk_score": None,
            "anomalous": False,
            "reason": "Insufficient benign audit history for anomaly scoring",
        }

    training: list[dict[str, str | float]] = []
    preceding: list[AuditLog] = []
    for row in timeline:
        if row.decision in BENIGN_DECISIONS:
            training.append(_features(row, preceding, row.timestamp))
        preceding.append(row)

    global _MODEL, _VECTORIZER, _MODEL_CREATED_AT
    with _MODEL_LOCK:
        if (
            _MODEL is None
            or _VECTORIZER is None
            or time.monotonic() - _MODEL_CREATED_AT > MODEL_REFRESH_SECONDS
        ):
            vectorizer = DictVectorizer(sparse=False)
            training_matrix = vectorizer.fit_transform(training)
            model = IsolationForest(
                n_estimators=100,
                contamination="auto",
                random_state=17,
            )
            model.fit(training_matrix)
            _VECTORIZER = vectorizer
            _MODEL = model
            _MODEL_CREATED_AT = time.monotonic()
        model = _MODEL
        vectorizer = _VECTORIZER

    sample = vectorizer.transform([_features(request, timeline)])
    decision_score = float(model.decision_function(sample)[0])
    risk_score = max(0.0, min(1.0, 0.5 - decision_score))
    return {
        "available": True,
        "risk_score": round(risk_score, 6),
        "anomalous": bool(model.predict(sample)[0] == -1),
        "reason": (
            "Behavior-frequency and action-context risk signal only; "
            "deterministic policy remains authoritative"
        ),
    }


def evaluate_synthetic_benchmark() -> dict[str, Any]:
    """Evaluate Isolation Forest signals on deterministic held-out benchmark cases."""
    from sklearn.ensemble import IsolationForest
    from sklearn.feature_extraction import DictVectorizer

    from attack_benchmark.scenarios import build_scenarios
    from models import ActionRequest

    scenarios = build_scenarios()
    benign = [item for item in scenarios if not item.is_attack]
    attack = [item for item in scenarios if item.is_attack]
    training_scenarios = [
        item for index, item in enumerate(benign) if index % 5 != 0
    ]
    heldout_benign = [
        item for index, item in enumerate(benign) if index % 5 == 0
    ]
    if len(training_scenarios) < MINIMUM_TRAINING_EVENTS:
        return {
            "available": False,
            "reason": "Insufficient legitimate benchmark scenarios for a holdout evaluation",
        }

    def request_for(item: Any) -> Any:
        return ActionRequest(
            agent=item.agent_identity,
            user=item.authenticated_identity,
            tool=item.tool,
            action=item.action,
            resource=item.resource,
            environment=item.environment,
            records=item.records,
        )

    origin = datetime(2020, 1, 1)
    history: list[AuditLog] = []
    training_rows: list[dict[str, str | float]] = []
    for index, item in enumerate(training_scenarios):
        observed_at = origin + timedelta(seconds=index * 30)
        training_rows.append(
            _features(request_for(item), history, observed_at)
        )
        history.append(
            AuditLog(
                agent=item.agent_identity,
                user=item.authenticated_identity,
                tool=item.tool,
                action=item.action,
                resource=item.resource,
                environment=item.environment,
                records=item.records,
                decision="ALLOW",
                reason="Synthetic benchmark training observation",
                timestamp=observed_at,
            )
        )

    vectorizer = DictVectorizer(sparse=False)
    training_matrix = vectorizer.fit_transform(training_rows)
    model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=17,
    )
    model.fit(training_matrix)

    test_cases = [
        *((item, False) for item in heldout_benign),
        *((item, True) for item in attack),
    ]
    test_time = origin + timedelta(seconds=len(training_scenarios) * 30)
    true_positive = false_positive = false_negative = true_negative = 0
    scoring_latency: list[float] = []
    for item, is_attack in test_cases:
        features = vectorizer.transform(
            [_features(request_for(item), history, test_time)]
        )
        started = time.perf_counter()
        anomalous = bool(model.predict(features)[0] == -1)
        scoring_latency.append((time.perf_counter() - started) * 1000)
        if is_attack and anomalous:
            true_positive += 1
        elif is_attack:
            false_negative += 1
        elif anomalous:
            false_positive += 1
        else:
            true_negative += 1

    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    benign_total = len(heldout_benign)
    return {
        "available": True,
        "evaluation": "deterministic synthetic holdout; advisory signals only",
        "training_benign": len(training_scenarios),
        "test_attacks": len(attack),
        "test_benign": benign_total,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1_score": round(f1, 6),
        "false_positive_rate": round(
            false_positive / benign_total if benign_total else 0.0,
            6,
        ),
        "mean_detection_latency_ms": round(
            sum(scoring_latency) / len(scoring_latency) if scoring_latency else 0.0,
            4,
        ),
        "limitations": (
            "Synthetic benchmark labels are scenario labels, not real-world ground truth; "
            "results do not measure production attack detection."
        ),
    }
