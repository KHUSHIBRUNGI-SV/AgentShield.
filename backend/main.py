import os
import logging
import asyncio
import re
import json
from contextlib import asynccontextmanager

from datetime import datetime, timedelta, timezone
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Request,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from config import get_cors_origins, validate_runtime_configuration
from redis.exceptions import RedisError

from auth.auth import (
    get_current_user,
    require_agent,
    require_reviewer,
    create_access_token,
    verify_password,
    hash_password,
    security
)

from models import (
    AgentSimulationRequest,
    ActionRequest,
    ApprovalDecision,
    LoginRequest,
    SecurityEventSubmission,
    AgentRegistration,
    AgentStatusUpdate,
    DashboardPreferences,
    PolicyDocumentUpdate,
)

from security.policy_engine import check_action_policy
from security.rate_limiter import check_rate_limit
from security.rate_limiter import redis_client as rate_limit_redis

from tools.tool_executor import execute_action
from tools.sandbox_executor import execute_in_sandbox

from security.audit_logger import log_event
from security.audit_integrity import calculate_audit_hash
from security.event_stream import event_stream

from database.database import (
    DATABASE_MODE,
    SessionLocal,
    engine,
    initialize_development_schema,
)

from database.models import (
    Agent,
    ApprovalRequest,
    AuditLog,
    User,
    BenchmarkRun,
    PolicyVersion,
    UserPreference,
)
from security.policy_engine import (
    POLICY_DOCUMENT,
    find_policy_conflicts,
    get_active_policy_document,
    validate_policy_document,
)

logger = logging.getLogger(__name__)

_BEARER_SECRET = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|secret|token|api[_-]?key)\b(\s*[:=]\s*)(['\"]?)([^\s,'\";}]+)"
)


def _persisted_approval_id(approval: ApprovalRequest) -> int:
    approval_id = approval.id
    if not isinstance(approval_id, int):
        raise RuntimeError("Approval record has no persisted database ID")
    return approval_id


def _approval_status_value(approval: ApprovalRequest) -> str:
    status = approval.status
    if not isinstance(status, str):
        raise RuntimeError("Approval record has no persisted status")
    return status


def _redact_event_evidence(value: str | None) -> str | None:
    if value is None:
        return None
    redacted = _BEARER_SECRET.sub("Bearer [REDACTED]", value)
    return _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]",
        redacted,
    )


@asynccontextmanager
async def lifespan(_app: FastAPI):
    validate_runtime_configuration()
    initialize_development_schema()
    yield


app = FastAPI(
    title="AgentShield",
    description=(
        "Deterministic runtime policy gateway for simulated AI-agent actions. "
        "OpenAPI documentation describes the current HTTP contracts."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return {
        "message": "AgentShield is running"
    }


@app.get("/health")
def health():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1 FROM users LIMIT 0"))
    except SQLAlchemyError as error:
        logger.error(
            "Database health check failed (%s)",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=503,
            detail=(
                "Database storage is unavailable or its schema is not "
                "initialized. Check backend configuration and run "
                "python -m database.create_tables."
            ),
        ) from error

    try:
        rate_limit_redis.ping()
    except RedisError as error:
        logger.error(
            "Redis readiness check failed (%s)",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=503,
            detail="Redis rate-limiting service is unavailable.",
        ) from error

    return {
        "status": "ok",
        "database": "available",
        "database_mode": DATABASE_MODE,
        "redis": "available",
    }


# =========================================================
# LOGIN
# =========================================================

@app.post("/auth/login")
def login(
    request: LoginRequest,
    http_request: Request
):
    if http_request.client is None:
        raise HTTPException(
            status_code=503,
            detail="Unable to determine login client for rate limiting"
        )

    rate_allowed, rate_reason = check_rate_limit(
        f"login:{http_request.client.host}",
        10
    )
    if not rate_allowed:
        raise HTTPException(
            status_code=429,
            detail=rate_reason
        )

    db = SessionLocal()
    try:
        try:
            user = db.query(User).filter(
                User.username == request.username
            ).first()
        except SQLAlchemyError as error:
            db.rollback()
            logger.error(
                "Authentication storage query failed (%s)",
                type(error).__name__,
            )
            raise HTTPException(
                status_code=503,
                detail=(
                    "Authentication database is unavailable. Verify the "
                    "configured database service and DATABASE_URL, then "
                    "check GET /health."
                ),
            ) from error
        if not user or not user.is_active:
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password"
            )
        password_hash = user.password_hash
        username = user.username
        role = user.role
    finally:
        db.close()

    if not verify_password(
        request.password,
        password_hash
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )


    token = create_access_token(
        username,
        role
    )


    return {
        "access_token": token,
        "token_type": "bearer",
        "username": username,
        "role": role
    }


# =========================================================
# CURRENT USER
# =========================================================

@app.get("/auth/me")
def current_user(
    credentials=Depends(security)
):

    return get_current_user(
        credentials
    )


# =========================================================
# CHECK ACTION
# =========================================================

@app.post("/check-action")
def check_action(
    request: ActionRequest,
    credentials=Depends(security)
):

    agent_user = require_agent(
        get_current_user(credentials)
    )
    if request.agent != agent_user["username"]:
        raise HTTPException(
            status_code=403,
            detail="Authenticated agent does not match the requested agent"
        )

    action_data = request.model_dump()
    action_data["user"] = agent_user["username"]
    request = ActionRequest(**action_data)

    policy_result = check_action_policy(
        request.agent,
        request.resource,
        request.action,
        request.environment,
        request.records,
        tool=request.tool,
    )

    decision = policy_result["decision"]
    reason = policy_result["reason"]
    rate_limit = policy_result["rate_limit"]


    # -----------------------------------------------------
    # RATE LIMIT
    # -----------------------------------------------------

    if (
        decision in [
            "ALLOW",
            "SANDBOX",
            "HUMAN_APPROVAL"
        ]
        and rate_limit is not None
    ):

        rate_allowed, rate_reason = check_rate_limit(
            request.agent,
            rate_limit
        )

        if not rate_allowed:

            decision = "BLOCK"
            reason = rate_reason

            audit_event = log_event(
                request,
                decision,
                reason
            )

            return {
                "decision": decision,
                "reason": reason,
                "audit": audit_event
            }


    # -----------------------------------------------------
    # BLOCK
    # -----------------------------------------------------

    if decision == "BLOCK":

        audit_event = log_event(
            request,
            decision,
            reason
        )

        return {
            "decision": decision,
            "reason": reason,
            "audit": audit_event
        }


    # -----------------------------------------------------
    # HUMAN APPROVAL
    # -----------------------------------------------------

    if decision == "HUMAN_APPROVAL":

        db = SessionLocal()

        existing_approval = db.query(ApprovalRequest).filter(
            ApprovalRequest.agent == request.agent,
            ApprovalRequest.user == request.user,
            ApprovalRequest.tool == request.tool,
            ApprovalRequest.action == request.action,
            ApprovalRequest.resource == request.resource,
            ApprovalRequest.environment == request.environment,
            ApprovalRequest.records == request.records,
            ApprovalRequest.status == "PENDING",
        ).first()
        if existing_approval:
            db.close()
            return {
                "decision": "HUMAN_APPROVAL",
                "reason": reason,
                "approval_id": existing_approval.id,
                "status": "PENDING",
                "duplicate": True,
            }

        approval = ApprovalRequest(

            agent=request.agent,

            user=request.user,

            tool=request.tool,

            action=request.action,

            resource=request.resource,

            environment=request.environment,

            records=request.records,

            status="PENDING",

            reason=reason
        )

        db.add(approval)

        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            existing_approval = db.query(ApprovalRequest).filter(
                ApprovalRequest.agent == request.agent,
                ApprovalRequest.user == request.user,
                ApprovalRequest.tool == request.tool,
                ApprovalRequest.action == request.action,
                ApprovalRequest.resource == request.resource,
                ApprovalRequest.environment == request.environment,
                ApprovalRequest.records == request.records,
                ApprovalRequest.status == "PENDING",
            ).first()
            if not existing_approval:
                db.close()
                raise
            db.close()
            return {
                "decision": "HUMAN_APPROVAL",
                "reason": reason,
                "approval_id": existing_approval.id,
                "status": "PENDING",
                "duplicate": True,
            }

        db.refresh(approval)

        db.close()


        audit_event = log_event(

            request,

            decision,

            reason,

            _persisted_approval_id(approval)
        )


        return {

            "decision": "HUMAN_APPROVAL",

            "reason": reason,

            "approval_id": approval.id,

            "status": "PENDING",

            "audit": audit_event
        }


    # -----------------------------------------------------
    # SANDBOX
    # -----------------------------------------------------

    if decision == "SANDBOX":

        result = execute_in_sandbox(
            request
        )

        if not result["executed"]:
            reason = result["message"]
            audit_event = log_event(
                request,
                "BLOCK",
                reason
            )
            return {
                "decision": "BLOCK",
                "reason": reason,
                "execution": result,
                "audit": audit_event
            }

        audit_event = log_event(
            request,
            decision,
            reason
        )

        return {

            "decision": decision,

            "reason": reason,

            "execution": result,

            "audit": audit_event
        }


    # -----------------------------------------------------
    # ALLOW
    # -----------------------------------------------------

    if decision == "ALLOW":

        result = execute_action(
            request
        )

        audit_event = log_event(
            request,
            decision,
            reason
        )

        return {

            "decision": decision,

            "reason": reason,

            "execution": result,

            "audit": audit_event
        }


@app.post("/agents/simulate")
def simulate_agent(
    request: AgentSimulationRequest,
    credentials=Depends(security)
):
    principal = get_current_user(credentials)
    require_agent(principal)
    results = []
    for action in request.actions:
        action_data = action.model_dump()
        action_data["agent"] = principal["username"]
        action_data["user"] = principal["username"]
        results.append(
            check_action(
                ActionRequest(**action_data),
                credentials
            )
        )
    return {
        "status": "SIMULATED",
        "tool_calls_mediated": len(results),
        "results": results
    }


# =========================================================
# VIEW PENDING APPROVALS
# =========================================================

@app.get("/approvals")
def get_approvals(
    credentials=Depends(security)
):

    user = get_current_user(
        credentials
    )

    require_reviewer(user)


    db = SessionLocal()
    try:
        approvals = db.query(
            ApprovalRequest
        ).filter(
            ApprovalRequest.status == "PENDING"
        ).all()
        return {
            "pending_approvals": [
                {
                    "id": approval.id,
                    "agent": approval.agent,
                    "user": approval.user,
                    "tool": approval.tool,
                    "action": approval.action,
                    "resource": approval.resource,
                    "environment": approval.environment,
                    "records": approval.records,
                    "status": approval.status,
                    "reason": approval.reason,
                }
                for approval in approvals
            ]
        }
    finally:
        db.close()


@app.get("/approvals/history")
def get_approval_history(credentials=Depends(security)):
    user = get_current_user(credentials)
    require_reviewer(user)

    db = SessionLocal()
    try:
        approvals = db.query(ApprovalRequest).filter(
            ApprovalRequest.status != "PENDING"
        ).order_by(
            ApprovalRequest.reviewed_at.desc(),
            ApprovalRequest.id.desc(),
        ).limit(100).all()
        return {
            "approval_history": [
                {
                    "id": item.id,
                    "agent": item.agent,
                    "tool": item.tool,
                    "action": item.action,
                    "resource": item.resource,
                    "environment": item.environment,
                    "records": item.records,
                    "status": item.status,
                    "reason": item.reason,
                    "approved_by": item.approved_by,
                    "reviewed_at": (
                        item.reviewed_at.isoformat()
                        if item.reviewed_at else None
                    ),
                }
                for item in approvals
            ],
        }
    finally:
        db.close()


def _transition_pending_approval(
    db,
    approval: ApprovalRequest,
    status: str,
    reviewer: str,
) -> bool:
    reviewed_at = datetime.now(timezone.utc).replace(tzinfo=None)
    updated = db.query(ApprovalRequest).filter(
        ApprovalRequest.id == approval.id,
        ApprovalRequest.status == "PENDING",
    ).update(
        {
            ApprovalRequest.status: status,
            ApprovalRequest.approved_by: reviewer,
            ApprovalRequest.reviewed_at: reviewed_at,
        },
        synchronize_session=False,
    )
    if updated != 1:
        return False
    db.commit()
    approval.status = status
    approval.approved_by = reviewer
    approval.reviewed_at = reviewed_at
    return True


# =========================================================
# APPROVE / REJECT
# =========================================================

@app.post("/approvals/decision")
def approval_decision(

    request: ApprovalDecision,

    credentials=Depends(security)

):

    # -----------------------------------------------------
    # AUTHENTICATE REVIEWER
    # -----------------------------------------------------

    reviewer = get_current_user(
        credentials
    )

    require_reviewer(
        reviewer
    )


    # -----------------------------------------------------
    # FIND APPROVAL
    # -----------------------------------------------------

    db = SessionLocal()

    approval = db.query(
        ApprovalRequest
    ).filter(
        ApprovalRequest.id == request.approval_id
    ).with_for_update().first()


    if not approval:

        db.close()

        raise HTTPException(
            status_code=404,
            detail="Approval request not found"
        )


    if approval.status != "PENDING":

        db.close()

        raise HTTPException(
            status_code=400,
            detail="Approval request already processed"
        )


    # -----------------------------------------------------
    # RECONSTRUCT ORIGINAL ACTION
    # -----------------------------------------------------

    action_request = ActionRequest(

        agent=approval.agent,

        user=approval.user,

        tool=approval.tool,

        action=approval.action,

        resource=approval.resource,

        environment=approval.environment,

        records=approval.records
    )


    # -----------------------------------------------------
    # REJECT
    # -----------------------------------------------------

    if not request.approved:

        if not _transition_pending_approval(
            db, approval, "REJECTED", reviewer["username"]
        ):
            db.rollback()
            db.close()
            raise HTTPException(
                status_code=400,
                detail="Approval request already processed",
            )

        db.close()


        rejection_reason = (
            request.rejection_reason
            or "Action rejected by reviewer"
        )


        audit_event = log_event(

            action_request,

            "REJECTED",

            rejection_reason,

            _persisted_approval_id(approval)
        )


        return {

            "approval_id": approval.id,

            "decision": "REJECTED",

            "reviewer": reviewer["username"],

            "reason": rejection_reason,

            "audit": audit_event
        }


    # -----------------------------------------------------
    # REVALIDATE POLICY
    # -----------------------------------------------------

    policy_result = check_action_policy(

        action_request.agent,

        action_request.resource,

        action_request.action,

        action_request.environment,

        action_request.records,
        ignore_approval=True,
        tool=action_request.tool,
    )


    decision = policy_result["decision"]

    reason = policy_result["reason"]

    rate_limit = policy_result["rate_limit"]


    if decision != "ALLOW":

        if not _transition_pending_approval(
            db, approval, "BLOCKED", reviewer["username"]
        ):
            db.rollback()
            db.close()
            raise HTTPException(
                status_code=400,
                detail="Approval request already processed",
            )

        db.close()


        audit_event = log_event(

            action_request,

            "BLOCK",

            (
                "Previously approved action "
                f"cannot execute: {reason}"
            ),

            _persisted_approval_id(approval)
        )


        return {

            "approval_id": approval.id,

            "decision": "BLOCK",

            "reason": reason,

            "audit": audit_event
        }


    # -----------------------------------------------------
    # RATE LIMIT
    # -----------------------------------------------------

    if rate_limit is not None:

        rate_allowed, rate_reason = check_rate_limit(

            action_request.agent,

            rate_limit
        )


        if not rate_allowed:

            if not _transition_pending_approval(
                db, approval, "BLOCKED", reviewer["username"]
            ):
                db.rollback()
                db.close()
                raise HTTPException(
                    status_code=400,
                    detail="Approval request already processed",
                )

            db.close()


            audit_event = log_event(

                action_request,

                "BLOCK",

                rate_reason,

                _persisted_approval_id(approval)
            )


            return {

                "approval_id": approval.id,

                "decision": "BLOCK",

                "reason": rate_reason,

                "audit": audit_event
            }


    # -----------------------------------------------------
    # EXECUTE
    # -----------------------------------------------------

    if not _transition_pending_approval(
        db, approval, "EXECUTING", reviewer["username"]
    ):
        db.rollback()
        db.close()
        raise HTTPException(
            status_code=400,
            detail="Approval request already processed",
        )

    try:

        result = execute_action(
            action_request,
            approval_id=approval.id
        )

    except Exception as error:

        approval.status = "EXECUTION_FAILED"

        approval.approved_by = reviewer["username"]

        approval.reviewed_at = datetime.now(timezone.utc).replace(tzinfo=None)

        db.commit()

        db.close()


        audit_event = log_event(

            action_request,

            "EXECUTION_FAILED",

            str(error),

            _persisted_approval_id(approval)
        )


        return {

            "approval_id": approval.id,

            "decision": "EXECUTION_FAILED",

            "reason": str(error),

            "audit": audit_event
        }


    # -----------------------------------------------------
    # MARK EXECUTED
    # -----------------------------------------------------

    was_executed = result.get("executed") is True
    approval.status = (
        "EXECUTED" if was_executed else "EXECUTION_UNAVAILABLE"
    )

    db.commit()

    db.close()


    audit_event = log_event(

        action_request,

        _approval_status_value(approval),

        (
            "Action approved and executed successfully"
            if was_executed
            else result.get("message", "The action was not executed")
        ),

        _persisted_approval_id(approval)
    )


    return {

        "approval_id": approval.id,

        "decision": approval.status,

        "reviewer": reviewer["username"],

        "execution": result,

        "audit": audit_event
    }


# =========================================================
# AUDIT LOGS
# =========================================================

@app.get("/audit-logs")
def get_audit_logs(
    credentials=Depends(security)
):

    user = get_current_user(
        credentials
    )

    require_reviewer(user)


    db = SessionLocal()
    try:
        logs = db.query(
            AuditLog
        ).order_by(
            AuditLog.timestamp.desc()
        ).limit(100).all()
        return {
            "audit_logs": [
                {
                    "id": log.id,
                    "timestamp": log.timestamp.isoformat(),
                    "agent": log.agent,
                    "user": log.user,
                    "tool": log.tool,
                    "action": log.action,
                    "resource": log.resource,
                    "environment": log.environment,
                    "records": log.records,
                    "decision": log.decision,
                    "reason": log.reason,
                    "approval_id": log.approval_id,
                    "risk_score": log.risk_score,
                    "anomaly_detected": log.anomaly_detected,
                    "event_id": log.event_id,
                    "event_type": log.event_type,
                    "severity": log.severity,
                    "evidence": log.evidence,
                    "previous_hash": log.previous_hash,
                    "event_hash": log.event_hash,
                }
                for log in logs
            ]
        }
    finally:
        db.close()


@app.get("/audit-logs/integrity")
def verify_audit_integrity(credentials=Depends(security)):
    user = get_current_user(credentials)
    require_reviewer(user)

    db = SessionLocal()
    try:
        rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
        previous_hash = None
        for row in rows:
            if (
                not row.event_id
                or not row.event_hash
                or row.previous_hash != previous_hash
                or calculate_audit_hash(row) != row.event_hash
            ):
                return {
                    "verified": False,
                    "records_checked": row.id,
                    "first_invalid_id": row.id,
                }
            previous_hash = row.event_hash
        return {
            "verified": True,
            "records_checked": len(rows),
            "first_invalid_id": None,
            "head_hash": previous_hash,
        }
    finally:
        db.close()


@app.post("/security/events/ingest")
def ingest_security_event(
    submission: SecurityEventSubmission,
    credentials=Depends(security),
):
    principal = require_agent(get_current_user(credentials))
    rate_allowed, rate_reason = check_rate_limit(
        f"event:{principal['username']}",
        120,
    )
    if not rate_allowed:
        raise HTTPException(status_code=429, detail=rate_reason)

    db = SessionLocal()
    try:
        registered = db.query(Agent.id).filter(
            Agent.name == principal["username"]
        ).first()
        if not registered:
            raise HTTPException(
                status_code=403,
                detail="Only registered agents may submit security events",
            )
    finally:
        db.close()

    action_request = ActionRequest(
        agent=principal["username"],
        user=principal["username"],
        tool=submission.tool,
        action=submission.action,
        resource=submission.resource,
        environment=submission.environment,
        records=submission.records,
    )
    policy_result = check_action_policy(
        action_request.agent,
        action_request.resource,
        action_request.action,
        action_request.environment,
        action_request.records,
        tool=action_request.tool,
    )
    policy_decision = policy_result["decision"]
    severity_by_type = {
        "unauthorized_tool_invocation": "CRITICAL",
        "privilege_escalation_attempt": "CRITICAL",
        "sensitive_data_access_attempt": "CRITICAL",
        "prompt_injection_indicator": "HIGH",
        "suspicious_agent_behavior": "HIGH",
        "policy_violation": "HIGH",
        "unexpected_identity_or_permissions": "HIGH",
        "unusual_api_request": "MEDIUM",
        "excessive_action_frequency": "MEDIUM",
        "repeated_authentication_failure": "MEDIUM",
        "agent_action": "LOW",
    }
    severity = severity_by_type[submission.event_type]
    if policy_decision == "BLOCK":
        severity = "CRITICAL"
    event = log_event(
        action_request,
        policy_decision,
        f"Agent-reported {submission.event_type}: {policy_result['reason']}",
        event_type=submission.event_type,
        severity=severity,
        evidence=_redact_event_evidence(submission.evidence),
    )

    return {
        "event": event,
        "policy_decision": policy_decision,
        "reason": policy_result["reason"],
        "executed": False,
    }


@app.websocket("/security/stream")
async def security_event_stream(websocket: WebSocket):
    offered = {
        protocol.strip()
        for protocol in websocket.headers.get(
            "sec-websocket-protocol", ""
        ).split(",")
    }
    token = next(
        (
            protocol.removeprefix("agentshield.jwt.")
            for protocol in offered
            if protocol.startswith("agentshield.jwt.")
        ),
        None,
    )
    origin = websocket.headers.get("origin")
    if (
        "agentshield.events.v1" not in offered
        or not token
        or (origin and origin not in get_cors_origins())
    ):
        await websocket.close(code=4403)
        return

    try:
        principal = get_current_user(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
        )
        require_reviewer(principal)
    except HTTPException as error:
        await websocket.close(code=4401 if error.status_code == 401 else 4403)
        return

    await websocket.accept(subprotocol="agentshield.events.v1")
    try:
        async with event_stream.subscribe() as queue:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20)
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "heartbeat"})
                else:
                    await websocket.send_json(event)
    except WebSocketDisconnect:
        return


@app.get("/security/summary")
def security_summary(
    hours: int = Query(default=24, ge=1, le=720),
    credentials=Depends(security),
):
    user = get_current_user(credentials)
    require_reviewer(user)

    db = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=hours)
        counts = db.query(
            AuditLog.decision,
            func.count(AuditLog.id)
        ).filter(AuditLog.timestamp >= cutoff).group_by(AuditLog.decision).all()
        severity_counts = db.query(
            AuditLog.severity,
            func.count(AuditLog.id),
        ).filter(
            AuditLog.timestamp >= cutoff,
        ).group_by(AuditLog.severity).all()
        recent_anomalies = db.query(AuditLog).filter(
            AuditLog.anomaly_detected.is_(True),
            AuditLog.timestamp >= cutoff,
        ).order_by(AuditLog.timestamp.desc()).limit(25).all()
        daily_events = db.query(
            func.date(AuditLog.timestamp),
            func.count(AuditLog.id),
        ).filter(
            AuditLog.timestamp >= cutoff,
        ).group_by(func.date(AuditLog.timestamp)).order_by(
            func.date(AuditLog.timestamp).asc()
        ).all()
        agents = db.query(Agent).all()
        agent_identities = db.query(User).filter(
            User.role == "agent",
            User.username.in_([agent.name for agent in agents] or [""]),
        ).all()
        active_agents = sum(identity.is_active for identity in agent_identities)
        pending_approvals = db.query(ApprovalRequest).filter(
            ApprovalRequest.status == "PENDING"
        ).count()
        total_events = sum(count for _, count in counts)
        return {
            "hours": hours,
            "agents": {
                "total": len(agents),
                "active": active_agents,
                "inactive": len(agents) - active_agents,
            },
            "total_events": total_events,
            "decisions": {decision: count for decision, count in counts},
            "severities": {
                (severity or "UNCLASSIFIED"): count
                for severity, count in severity_counts
            },
            "blocked_actions": sum(
                count for decision, count in counts if decision == "BLOCK"
            ),
            "pending_approvals": pending_approvals,
            "events_over_time": [
                {"date": str(day), "count": count} for day, count in daily_events
            ],
            "recent_anomalies": [
                {
                    "id": item.id,
                    "timestamp": item.timestamp.isoformat(),
                    "agent": item.agent,
                    "action": item.action,
                    "risk_score": item.risk_score,
                    "decision": item.decision,
                }
                for item in recent_anomalies
            ],
        }
    finally:
        db.close()


@app.get("/security/anomaly/evaluation")
def evaluate_anomaly_model(credentials=Depends(security)):
    user = get_current_user(credentials)
    require_reviewer(user)
    from security.anomaly_detection import evaluate_synthetic_benchmark

    return evaluate_synthetic_benchmark()


@app.post("/security/benchmark")
def run_security_benchmark(credentials=Depends(security)):
    user = get_current_user(credentials)
    require_reviewer(user)

    from attack_benchmark.runner import run_benchmark

    report = run_benchmark(write_output=False)
    db = SessionLocal()
    try:
        run = BenchmarkRun(
            actor=user["username"],
            summary_json=json.dumps(report["summary"], separators=(",", ":")),
            scenarios_json=json.dumps(report["scenarios"], separators=(",", ":")),
            methodology_json=json.dumps(report["methodology"], separators=(",", ":")),
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        return {
            "run_id": run.id,
            "started_at": run.started_at.isoformat(),
            "summary": report["summary"],
            "scenarios": report["scenarios"],
            "methodology": report["methodology"],
        }
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@app.get("/security/benchmark/runs")
def list_benchmark_runs(credentials=Depends(security)):
    user = get_current_user(credentials)
    require_reviewer(user)
    db = SessionLocal()
    try:
        runs = db.query(BenchmarkRun).order_by(
            BenchmarkRun.started_at.desc()
        ).limit(50).all()
        return {
            "runs": [
                {
                    "run_id": item.id,
                    "started_at": item.started_at.isoformat(),
                    "actor": item.actor,
                    "summary": json.loads(item.summary_json),
                }
                for item in runs
            ]
        }
    finally:
        db.close()


@app.get("/security/benchmark/runs/{run_id}")
def get_benchmark_run(run_id: int, credentials=Depends(security)):
    user = get_current_user(credentials)
    require_reviewer(user)
    db = SessionLocal()
    try:
        run = db.query(BenchmarkRun).filter(BenchmarkRun.id == run_id).first()
        if not run:
            raise HTTPException(status_code=404, detail="Benchmark run not found")
        return {
            "run_id": run.id,
            "started_at": run.started_at.isoformat(),
            "actor": run.actor,
            "summary": json.loads(run.summary_json),
            "scenarios": json.loads(run.scenarios_json),
            "methodology": json.loads(run.methodology_json),
        }
    finally:
        db.close()

@app.get("/security/policies")
def get_security_policies(credentials=Depends(security)):
    user = get_current_user(credentials)
    require_reviewer(user)

    return {
        **get_active_policy_document(),
    }


@app.get("/security/policies/history")
def get_policy_history(credentials=Depends(security)):
    user = get_current_user(credentials)
    require_reviewer(user)
    db = SessionLocal()
    try:
        versions = db.query(PolicyVersion).order_by(
            PolicyVersion.version.desc()
        ).limit(50).all()
        return {
            "versions": [
                {
                    "version": item.version,
                    "changed_at": item.changed_at.isoformat(),
                    "changed_by": item.changed_by,
                }
                for item in versions
            ]
        }
    finally:
        db.close()


@app.post("/security/policies")
def update_security_policies(
    request: PolicyDocumentUpdate,
    credentials=Depends(security),
):
    user = get_current_user(credentials)
    if user["role"] != "security_admin":
        raise HTTPException(status_code=403, detail="Security administrator privileges required")
    current = get_active_policy_document()
    if request.expected_version != current["version"]:
        raise HTTPException(
            status_code=409,
            detail=f"Policy changed; current version is {current['version']}",
        )
    document = {
        "version": current["version"] + 1,
        "default_decision": request.default_decision,
        "required_subject_roles": request.required_subject_roles,
        "rules": request.rules,
    }
    try:
        document = validate_policy_document(document)
    except RuntimeError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error

    db = SessionLocal()
    try:
        latest_version = db.query(func.max(PolicyVersion.version)).scalar() or current["version"]
        if latest_version != request.expected_version:
            raise HTTPException(
                status_code=409,
                detail=f"Policy changed; current version is {latest_version}",
            )
        version = PolicyVersion(
            version=document["version"],
            changed_by=user["username"],
            document_json=json.dumps(document, sort_keys=True, separators=(",", ":")),
        )
        db.add(version)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    log_event(
        ActionRequest(
            agent="agentshield",
            user=user["username"],
            tool="policy.management",
            action="update",
            resource="security_policy",
            environment="system",
        ),
        "ALLOW",
        f"Policy updated to version {document['version']}",
        event_type="policy_change",
        evidence=f"Version {current['version']} -> {document['version']}",
    )
    return document


@app.post("/security/policies/dry-run")
def dry_run_policy(
    request: ActionRequest,
    credentials=Depends(security),
):
    user = get_current_user(credentials)
    if user["role"] != "security_admin":
        raise HTTPException(status_code=403, detail="Security administrator privileges required")
    result = check_action_policy(
        request.agent,
        request.resource,
        request.action,
        request.environment,
        request.records,
        tool=request.tool,
    )
    return {**result, "dry_run": True, "executed": False}


@app.get("/agents")
def list_agents(credentials=Depends(security)):
    user = get_current_user(credentials)
    require_reviewer(user)
    active_policy = get_active_policy_document()

    db = SessionLocal()
    try:
        agents = db.query(Agent).order_by(Agent.name.asc()).all()
        result = []
        for agent in agents:
            identity = db.query(User).filter(
                User.username == agent.name
            ).first()
            last_event = db.query(AuditLog).filter(
                AuditLog.agent == agent.name
            ).order_by(AuditLog.timestamp.desc()).first()
            result.append({
                "name": agent.name,
                "description": agent.description,
                "active": bool(identity and identity.is_active and identity.role == "agent"),
                "last_seen": (
                    last_event.timestamp.isoformat()
                    if last_event else None
                ),
                "last_decision": last_event.decision if last_event else None,
                "usage": {
                    "total_actions": db.query(AuditLog).filter(
                        AuditLog.agent == agent.name
                    ).count(),
                    "blocked_actions": db.query(AuditLog).filter(
                        AuditLog.agent == agent.name,
                        AuditLog.decision == "BLOCK",
                    ).count(),
                    "anomalies": db.query(AuditLog).filter(
                        AuditLog.agent == agent.name,
                        AuditLog.anomaly_detected.is_(True),
                    ).count(),
                },
                "permissions": [
                    {
                        "rule_id": rule["id"],
                        "tool": rule.get("match", {}).get("tool", "*"),
                        "resource": rule.get("match", {}).get("resource", "*"),
                        "action": rule.get("match", {}).get("action", "*"),
                        "environments": rule.get("match", {}).get(
                            "environment", ["*"]
                        ),
                        "decision": rule["decision"],
                        "max_records": rule.get("match", {}).get("max_records"),
                        "rate_limit": rule.get("rate_limit"),
                    }
                    for rule in active_policy["rules"]
                    if rule.get("match", {}).get("agent", "*")
                    in ("*", agent.name)
                ],
            })
        return {"agents": result}
    finally:
        db.close()


@app.post("/agents", status_code=201)
def register_agent(
    request: AgentRegistration,
    credentials=Depends(security),
):
    actor = get_current_user(credentials)
    if actor["role"] != "security_admin":
        raise HTTPException(status_code=403, detail="Security administrator privileges required")
    try:
        password_hash = hash_password(request.password)
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    db = SessionLocal()
    try:
        if db.query(Agent).filter(Agent.name == request.name).first():
            raise HTTPException(status_code=409, detail="Agent identity already exists")
        agent = Agent(name=request.name, description=request.description)
        identity = User(
            username=request.name,
            password_hash=password_hash,
            role="agent",
            is_active=True,
        )
        db.add_all([agent, identity])
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(status_code=409, detail="Agent identity already exists") from error
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    log_event(
        ActionRequest(
            agent=request.name,
            user=actor["username"],
            tool="agent.registry",
            action="register",
            resource=request.name,
            environment="system",
        ),
        "ALLOW",
        "Agent registered by security administrator",
        event_type="agent_lifecycle",
    )
    return {
        "name": request.name,
        "description": request.description,
        "active": True,
    }


@app.patch("/agents/{agent_name}/status")
def update_agent_status(
    agent_name: str,
    request: AgentStatusUpdate,
    credentials=Depends(security),
):
    actor = get_current_user(credentials)
    if actor["role"] != "security_admin":
        raise HTTPException(status_code=403, detail="Security administrator privileges required")
    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(Agent.name == agent_name).first()
        identity = db.query(User).filter(
            User.username == agent_name,
            User.role == "agent",
        ).first()
        if not agent or not identity:
            raise HTTPException(status_code=404, detail="Registered agent account not found")
        identity.is_active = request.active
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    status = "active" if request.active else "suspended"
    log_event(
        ActionRequest(
            agent=agent_name,
            user=actor["username"],
            tool="agent.registry",
            action="reactivate" if request.active else "suspend",
            resource=agent_name,
            environment="system",
        ),
        "ALLOW",
        f"Agent {status} by security administrator",
        event_type="agent_lifecycle",
    )
    return {"name": agent_name, "active": request.active, "status": status}


@app.get("/settings/preferences")
def get_dashboard_preferences(credentials=Depends(security)):
    principal = get_current_user(credentials)
    db = SessionLocal()
    try:
        identity = db.query(User).filter(User.username == principal["username"]).one()
        preference = db.query(UserPreference).filter(
            UserPreference.user_id == identity.id
        ).first()
        values = (
            json.loads(preference.preferences_json)
            if preference
            else DashboardPreferences().model_dump()
        )
        return DashboardPreferences.model_validate(values).model_dump()
    finally:
        db.close()


@app.put("/settings/preferences")
def put_dashboard_preferences(
    request: DashboardPreferences,
    credentials=Depends(security),
):
    principal = get_current_user(credentials)
    db = SessionLocal()
    try:
        identity = db.query(User).filter(User.username == principal["username"]).one()
        preference = db.query(UserPreference).filter(
            UserPreference.user_id == identity.id
        ).first()
        serialized = json.dumps(request.model_dump(), sort_keys=True)
        if preference:
            preference.preferences_json = serialized
        else:
            db.add(UserPreference(
                user_id=identity.id,
                preferences_json=serialized,
            ))
        db.commit()
        return request.model_dump()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()