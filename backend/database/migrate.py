from pathlib import Path

from sqlalchemy import text

from database.database import DATABASE_MODE, Base, engine
from database import models  # noqa: F401


MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
MIGRATIONS = (
    ("001_security_hardening", MIGRATIONS_DIR / "001_security_hardening.sql"),
    ("002_audit_integrity", MIGRATIONS_DIR / "002_audit_integrity.sql"),
    ("003_dashboard_governance", MIGRATIONS_DIR / "003_dashboard_governance.sql"),
)


def apply_migrations() -> None:
    if DATABASE_MODE != "postgres":
        raise RuntimeError(
            "database.migrate applies PostgreSQL migrations only; "
            "SQLite development tables are initialized by app startup."
        )

    # create_all only creates missing tables; it does not alter existing ones.
    # The versioned SQL migrations below make changes to existing PostgreSQL
    # schemas without dropping or resetting user data.
    Base.metadata.create_all(bind=engine)

    with engine.begin() as connection:
        connection.execute(text(
            """
            CREATE TABLE IF NOT EXISTS agentshield_schema_migrations (
                revision VARCHAR(128) PRIMARY KEY,
                applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        ))
        connection.execute(text("SELECT pg_advisory_xact_lock(:lock_id)"), {
            "lock_id": 729143821,
        })

        for revision, migration_path in MIGRATIONS:
            already_applied = connection.execute(
                text(
                    "SELECT 1 FROM agentshield_schema_migrations "
                    "WHERE revision = :revision"
                ),
                {"revision": revision},
            ).scalar_one_or_none()
            if already_applied:
                continue

            migration_sql = migration_path.read_text(encoding="utf-8")
            connection.exec_driver_sql(migration_sql)
            connection.execute(
                text(
                    "INSERT INTO agentshield_schema_migrations (revision) "
                    "VALUES (:revision)"
                ),
                {"revision": revision},
            )

    print("All pending PostgreSQL migrations were applied.")


if __name__ == "__main__":
    apply_migrations()
