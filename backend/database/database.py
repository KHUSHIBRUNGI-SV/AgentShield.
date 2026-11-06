import logging
import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from config import BACKEND_DIR, ENV_FILE, load_environment

logger = logging.getLogger(__name__)


def get_database_configuration() -> tuple[str, str]:
    load_environment()
    mode = os.getenv("AGENTSHIELD_DATABASE_MODE", "").strip().lower()
    environment = os.getenv("AGENTSHIELD_ENVIRONMENT", "development").strip().lower()

    if mode == "sqlite-dev":
        if environment in {"production", "prod"}:
            raise RuntimeError(
                "sqlite-dev database mode is not permitted in production. "
                "Configure AGENTSHIELD_DATABASE_MODE=postgres and DATABASE_URL."
            )
        configured_url = os.getenv("DATABASE_URL", "").strip()
        if configured_url.lower().startswith("sqlite:"):
            database_url = _resolve_sqlite_url(configured_url)
        else:
            sqlite_path = Path(
                os.getenv(
                    "AGENTSHIELD_SQLITE_PATH",
                    str(BACKEND_DIR / "data" / "agentshield-dev.sqlite3"),
                )
            ).expanduser()
            if not sqlite_path.is_absolute():
                sqlite_path = BACKEND_DIR / sqlite_path
            sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            database_url = f"sqlite:///{sqlite_path.resolve().as_posix()}"
        return mode, database_url

    if mode not in {"", "postgres"}:
        raise RuntimeError(
            "AGENTSHIELD_DATABASE_MODE must be 'postgres' or the "
            "development-only 'sqlite-dev'."
        )

    database_url = os.getenv("DATABASE_URL", "").strip()
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL is not configured. Set it in "
            f"{ENV_FILE}; if the file does not exist, copy "
            f"{BACKEND_DIR / '.env.example'} to backend/.env and configure it."
        )

    if mode == "postgres" and not database_url.lower().startswith(
        ("postgresql://", "postgresql+")
    ):
        raise RuntimeError(
            "AGENTSHIELD_DATABASE_MODE=postgres requires a PostgreSQL DATABASE_URL."
        )

    if environment in {"production", "prod"} and database_url.lower().startswith(
        "sqlite:"
    ):
        raise RuntimeError("SQLite is not permitted for production database storage.")

    if not database_url.lower().startswith(
        ("postgresql://", "postgresql+", "sqlite:")
    ):
        raise RuntimeError(
            "DATABASE_URL must use PostgreSQL or SQLite. SQLite is intended "
            "for local development and tests only."
        )

    resolved_mode = mode or (
        "sqlite-dev" if database_url.lower().startswith("sqlite:") else "postgres"
    )
    if resolved_mode == "sqlite-dev":
        database_url = _resolve_sqlite_url(database_url)
    return resolved_mode, database_url


def _resolve_sqlite_url(database_url: str) -> str:
    parsed_url = make_url(database_url)
    if not parsed_url.drivername.startswith("sqlite"):
        raise ValueError("Expected a SQLite database URL")

    database_path = parsed_url.database
    if not database_path or database_path == ":memory:":
        return database_url

    path = Path(database_path).expanduser()
    if not path.is_absolute():
        path = BACKEND_DIR / path
    return parsed_url.set(database=str(path.resolve())).render_as_string(
        hide_password=False
    )


load_environment()
DATABASE_MODE, DATABASE_URL = get_database_configuration()
IS_SQLITE = DATABASE_URL.lower().startswith("sqlite:")


def create_database_engine(database_url: str):
    sqlite = database_url.lower().startswith("sqlite:")
    if sqlite:
        connect_args = {"check_same_thread": False, "timeout": 5}
        engine_options = {"connect_args": connect_args, "pool_pre_ping": True}
        if database_url.rstrip("/").endswith(":memory:") or database_url == "sqlite://":
            engine_options["poolclass"] = StaticPool
    else:
        engine_options = {
            "connect_args": {"connect_timeout": 5},
            "pool_pre_ping": True,
            "pool_recycle": 1800,
        }

    database_engine = create_engine(database_url, **engine_options)

    if sqlite:
        @event.listens_for(database_engine, "connect")
        def enable_sqlite_safety(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    return database_engine


engine = create_database_engine(DATABASE_URL)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False
)

Base = declarative_base()


def initialize_development_schema(database_engine=engine) -> None:
    if DATABASE_MODE != "sqlite-dev":
        return

    from database import models  # noqa: F401

    logger.info("Initializing missing tables in the local SQLite development database")
    Base.metadata.create_all(bind=database_engine)
    from security.audit_integrity import ensure_sqlite_audit_columns, backfill_audit_chain

    ensure_sqlite_audit_columns(database_engine)
    backfill_audit_chain(database_engine)
