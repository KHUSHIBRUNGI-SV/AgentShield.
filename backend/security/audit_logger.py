from datetime import datetime, timezone
import threading
import uuid
from typing import Any

from sqlalchemy import text
from database.database import SessionLocal
from database.models import AuditLog
from models import ActionRequest
from security.audit_integrity import calculate_audit_hash
from security.anomaly_detection import score_action
from security.event_stream import event_stream


_AUDIT_LOCK = threading.RLock()
_CHAIN_LOCK_ID = 729143822


def _severity(decision: str, anomalous: bool, score: float | None) -> str:
    if decision == "BLOCK" and anomalous:
        return "CRITICAL"
    if decision == "BLOCK":
        return "HIGH"
    if anomalous or (score is not None and score >= 0.75):
        return "MEDIUM"
    return "LOW"


def log_event(
    request: ActionRequest,
    decision: str,
    reason: str,
    approval_id: int | None = None,
    *,
    event_type: str = "agent_action",
    severity: str | None = None,
    evidence: str | None = None,
) -> dict[str, Any]:
    anomaly = score_action(request)

    db = SessionLocal()
    with _AUDIT_LOCK:
        try:
            if db.bind is not None and db.bind.dialect.name == "postgresql":
                db.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_id)"),
                    {"lock_id": _CHAIN_LOCK_ID},
                )
            previous = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
            previous_hash = previous.event_hash if previous else None
            severity = severity or _severity(
                decision, anomaly["anomalous"], anomaly["risk_score"]
            )
            audit_log = AuditLog(
                event_id=str(uuid.uuid4()),
                previous_hash=previous_hash,
                timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
                agent=request.agent,
                user=request.user,
                tool=request.tool,
                action=request.action,
                resource=request.resource,
                environment=request.environment,
                records=request.records,
                decision=decision,
                reason=reason,
                approval_id=approval_id,
                risk_score=anomaly["risk_score"],
                anomaly_detected=anomaly["anomalous"],
                event_type=event_type,
                severity=severity,
                evidence=evidence,
            )
            db.add(audit_log)
            db.flush()
            audit_log.event_hash = calculate_audit_hash(audit_log)
            db.commit()
            db.refresh(audit_log)
            event = {
                "id": audit_log.id,
                "event_id": audit_log.event_id,
                "timestamp": audit_log.timestamp.isoformat(),
                "agent": audit_log.agent,
                "user": audit_log.user,
                "tool": audit_log.tool,
                "action": audit_log.action,
                "resource": audit_log.resource,
                "environment": audit_log.environment,
                "records": audit_log.records,
                "decision": audit_log.decision,
                "reason": audit_log.reason,
                "approval_id": audit_log.approval_id,
                "risk_score": audit_log.risk_score,
                "anomaly_detected": audit_log.anomaly_detected,
                "event_type": audit_log.event_type,
                "severity": audit_log.severity,
                "evidence": audit_log.evidence,
                "previous_hash": audit_log.previous_hash,
                "event_hash": audit_log.event_hash,
            }
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    event_stream.publish({"type": "security_event", "event": event})
    return event