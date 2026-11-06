from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    CheckConstraint,
    Integer,
    String,
    ForeignKey,
    Boolean,
    DateTime,
    UniqueConstraint,
    Index,
    Float,
    text,
    Text,
)

from database.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    username = Column(
        String,
        unique=True,
        nullable=False
    )

    password_hash = Column(
        String,
        nullable=False
    )

    role = Column(
        String,
        nullable=False,
        default="user"
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False
    )


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)

    name = Column(
        String,
        unique=True,
        nullable=False
    )

    description = Column(String)


class Permission(Base):
    __tablename__ = "permissions"
    __table_args__ = (
        UniqueConstraint(
            "agent_id",
            "resource",
            "action",
            name="uq_permission_agent_resource_action"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    agent_id = Column(
        Integer,
        ForeignKey("agents.id"),
        nullable=False
    )

    resource = Column(
        String,
        nullable=False
    )

    action = Column(
        String,
        nullable=False
    )


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (
        UniqueConstraint(
            "permission_id",
            "environment",
            name="uq_policy_permission_environment"
        ),
        CheckConstraint(
            "max_records IS NULL OR max_records >= 0",
            name="ck_policy_nonnegative_max_records"
        ),
        CheckConstraint(
            "max_requests_per_minute IS NULL OR max_requests_per_minute > 0",
            name="ck_policy_positive_rate_limit"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    permission_id = Column(
        Integer,
        ForeignKey("permissions.id"),
        nullable=False
    )

    environment = Column(
        String,
        nullable=False,
        default="*"
    )

    max_records = Column(
        Integer,
        nullable=True
    )

    max_requests_per_minute = Column(
        Integer,
        nullable=True
    )

    requires_approval = Column(
        Boolean,
        default=False
    )

    sandbox = Column(
        Boolean,
        default=False
    )


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"
    __table_args__ = (
        CheckConstraint("records >= 0", name="ck_approval_nonnegative_records"),
        Index("ix_approval_status_created", "status", "id"),
        Index(
            "uq_pending_approval_action",
            "agent",
            "user",
            "tool",
            "action",
            "resource",
            "environment",
            "records",
            unique=True,
            postgresql_where=text("status = 'PENDING'"),
            sqlite_where=text("status = 'PENDING'"),
        ),
    )

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    agent = Column(
        String,
        nullable=False
    )

    user = Column(
        String,
        nullable=False
    )

    tool = Column(
        String,
        nullable=False
    )

    action = Column(
        String,
        nullable=False
    )

    resource = Column(
        String,
        nullable=False
    )

    environment = Column(
        String,
        nullable=False
    )

    records = Column(
        Integer,
        default=0,
        nullable=False
    )

    status = Column(
        String,
        nullable=False,
        default="PENDING"
    )

    reason = Column(
        String,
        nullable=False
    )

    approved_by = Column(
        String,
        nullable=True
    )

    reviewed_at = Column(
        DateTime,
        nullable=True
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("records >= 0", name="ck_audit_nonnegative_records"),
        Index("ix_audit_timestamp", "timestamp"),
        Index("uq_audit_event_id", "event_id", unique=True),
    )

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        nullable=False
    )

    agent = Column(
        String,
        nullable=False
    )

    user = Column(
        String,
        nullable=False
    )

    tool = Column(
        String,
        nullable=False
    )

    action = Column(
        String,
        nullable=False
    )

    resource = Column(
        String,
        nullable=False
    )

    environment = Column(
        String,
        nullable=False
    )

    records = Column(
        Integer,
        default=0,
        nullable=False
    )

    decision = Column(
        String,
        nullable=False
    )

    reason = Column(
        String,
        nullable=False
    )

    approval_id = Column(
        Integer,
        ForeignKey("approval_requests.id"),
        nullable=True
    )

    risk_score = Column(Float, nullable=True)

    anomaly_detected = Column(Boolean, default=False, nullable=False)

    event_id = Column(String(36), nullable=True)

    previous_hash = Column(String(64), nullable=True)

    event_hash = Column(String(64), nullable=True)

    event_type = Column(String(64), nullable=True)

    severity = Column(String(16), nullable=True)

    evidence = Column(Text, nullable=True)


class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"
    __table_args__ = (
        Index("ix_benchmark_started_at", "started_at"),
    )

    id = Column(Integer, primary_key=True, index=True)
    started_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        nullable=False,
    )
    actor = Column(String(128), nullable=False)
    summary_json = Column(Text, nullable=False)
    scenarios_json = Column(Text, nullable=False)
    methodology_json = Column(Text, nullable=False)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    __table_args__ = (UniqueConstraint("version", name="uq_policy_version"),)

    id = Column(Integer, primary_key=True, index=True)
    version = Column(Integer, nullable=False)
    changed_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc).replace(tzinfo=None),
        nullable=False,
    )
    changed_by = Column(String(128), nullable=False)
    document_json = Column(Text, nullable=False)


class UserPreference(Base):
    __tablename__ = "user_preferences"
    __table_args__ = (
        UniqueConstraint("user_id", name="uq_user_preference_user"),
    )

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    preferences_json = Column(Text, nullable=False)