import hashlib
import json
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session


_AUDIT_FIELDS = (
    "id",
    "event_id",
    "timestamp",
    "agent",
    "user",
    "tool",
    "action",
    "resource",
    "environment",
    "records",
    "decision",
    "reason",
    "approval_id",
    "risk_score",
    "anomaly_detected",
    "event_type",
    "severity",
    "evidence",
    "previous_hash",
)


def _normalize_timestamp(value: datetime | str | None) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def audit_payload(record: Any) -> dict[str, Any]:
    return {
        field: (
            _normalize_timestamp(getattr(record, field))
            if field == "timestamp"
            else getattr(record, field)
        )
        for field in _AUDIT_FIELDS
    }


def calculate_audit_hash(record: Any) -> str:
    encoded = json.dumps(
        audit_payload(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def ensure_sqlite_audit_columns(database_engine: Engine) -> None:
    if database_engine.dialect.name != "sqlite":
        raise RuntimeError("SQLite audit schema migration requires SQLite")

    columns = {
        column["name"]
        for column in inspect(database_engine).get_columns("audit_logs")
    }
    definitions = {
        "event_id": "VARCHAR(36)",
        "previous_hash": "VARCHAR(64)",
        "event_hash": "VARCHAR(64)",
        "event_type": "VARCHAR(64)",
        "severity": "VARCHAR(16)",
        "evidence": "TEXT",
    }
    with database_engine.begin() as connection:
        for name, sql_type in definitions.items():
            if name not in columns:
                connection.execute(
                    text(f"ALTER TABLE audit_logs ADD COLUMN {name} {sql_type}")
                )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_event_id "
                "ON audit_logs (event_id)"
            )
        )


def backfill_audit_chain(database_engine: Engine) -> None:
    from database.models import AuditLog

    with Session(database_engine) as db:
        if not inspect(database_engine).has_table(AuditLog.__tablename__):
            return
        rows = db.query(AuditLog).order_by(AuditLog.id.asc()).all()
        previous_hash = None
        changed = False
        for row in rows:
            if row.event_hash:
                previous_hash = row.event_hash
                continue
            row.event_id = row.event_id or str(uuid.uuid4())
            row.previous_hash = previous_hash
            row.event_hash = calculate_audit_hash(row)
            previous_hash = row.event_hash
            changed = True
        if changed:
            db.commit()
