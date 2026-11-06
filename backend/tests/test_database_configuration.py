import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

import database.database as database
from database import models  # noqa: F401
from config import get_cors_origins


class DatabaseConfigurationTests(unittest.TestCase):
    def test_sqlite_development_mode_resolves_a_persistent_absolute_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "agentshield-dev.sqlite3"
            environment = {
                "AGENTSHIELD_DATABASE_MODE": "sqlite-dev",
                "AGENTSHIELD_ENVIRONMENT": "development",
                "AGENTSHIELD_SQLITE_PATH": str(path),
                "DATABASE_URL": "postgresql://configured-url-is-not-used",
            }
            with patch.dict(os.environ, environment, clear=False):
                mode, url = database.get_database_configuration()

        self.assertEqual(mode, "sqlite-dev")
        self.assertTrue(url.startswith("sqlite:///"))
        self.assertTrue(Path(url.removeprefix("sqlite:///")).is_absolute())

    def test_sqlite_mode_is_rejected_in_production(self):
        with patch.dict(
            os.environ,
            {
                "AGENTSHIELD_DATABASE_MODE": "sqlite-dev",
                "AGENTSHIELD_ENVIRONMENT": "production",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "not permitted in production"):
                database.get_database_configuration()

    def test_relative_sqlite_url_resolves_from_backend_directory(self):
        with patch.dict(
            os.environ,
            {
                "AGENTSHIELD_DATABASE_MODE": "sqlite-dev",
                "AGENTSHIELD_ENVIRONMENT": "development",
                "DATABASE_URL": "sqlite:///local-relative-test.sqlite3",
            },
            clear=False,
        ):
            _, url = database.get_database_configuration()

        self.assertEqual(
            Path(url.removeprefix("sqlite:///")),
            Path(database.BACKEND_DIR / "local-relative-test.sqlite3").resolve(),
        )

    def test_sqlite_engine_enables_foreign_keys_and_creates_model_tables(self):
        test_engine = database.create_database_engine("sqlite://")
        try:
            with patch.object(database, "DATABASE_MODE", "sqlite-dev"):
                database.initialize_development_schema(test_engine)

            with test_engine.connect() as connection:
                self.assertEqual(
                    connection.execute(text("PRAGMA foreign_keys")).scalar_one(),
                    1,
                )
                self.assertIn("users", inspect(connection).get_table_names())
                self.assertIn("approval_requests", inspect(connection).get_table_names())
        finally:
            test_engine.dispose()

    def test_existing_sqlite_audit_rows_are_additively_hash_chained(self):
        from security.audit_integrity import (
            backfill_audit_chain,
            ensure_sqlite_audit_columns,
        )

        test_engine = database.create_database_engine("sqlite://")
        try:
            with test_engine.begin() as connection:
                connection.exec_driver_sql(
                    """
                    CREATE TABLE audit_logs (
                        id INTEGER PRIMARY KEY,
                        timestamp DATETIME NOT NULL,
                        agent VARCHAR NOT NULL,
                        "user" VARCHAR NOT NULL,
                        tool VARCHAR NOT NULL,
                        action VARCHAR NOT NULL,
                        resource VARCHAR NOT NULL,
                        environment VARCHAR NOT NULL,
                        records INTEGER NOT NULL,
                        decision VARCHAR NOT NULL,
                        reason VARCHAR NOT NULL,
                        approval_id INTEGER,
                        risk_score FLOAT,
                        anomaly_detected BOOLEAN NOT NULL
                    )
                    """
                )
                connection.execute(
                    text(
                        """
                        INSERT INTO audit_logs
                            (timestamp, agent, "user", tool, action, resource,
                             environment, records, decision, reason,
                             anomaly_detected)
                        VALUES
                            ('2026-01-01 00:00:00', 'agent-a', 'agent-a',
                             'lookup', 'read', 'records', 'test', 0,
                             'ALLOW', 'existing record', FALSE)
                        """
                    )
                )

            ensure_sqlite_audit_columns(test_engine)
            backfill_audit_chain(test_engine)
            with Session(test_engine) as db:
                record = db.query(models.AuditLog).one()
                event_id = record.event_id
                event_hash = record.event_hash
                self.assertIsNotNone(event_id)
                self.assertIsNotNone(event_hash)
                self.assertIsNone(record.previous_hash)

            backfill_audit_chain(test_engine)
            with Session(test_engine) as db:
                record = db.query(models.AuditLog).one()
                self.assertEqual(record.event_id, event_id)
                self.assertEqual(record.event_hash, event_hash)
                self.assertEqual(record.reason, "existing record")
        finally:
            test_engine.dispose()

    def test_postgres_migration_runner_rejects_sqlite_development_mode(self):
        from database.migrate import apply_migrations

        with patch.object(database, "DATABASE_MODE", "sqlite-dev"):
            with patch("database.migrate.DATABASE_MODE", "sqlite-dev"):
                with self.assertRaisesRegex(RuntimeError, "PostgreSQL migrations only"):
                    apply_migrations()

    def test_cors_origins_use_only_explicit_http_origins(self):
        with patch.dict(
            os.environ,
            {"AGENTSHIELD_CORS_ORIGINS": "https://console.example.com, http://localhost:5173/"},
            clear=False,
        ):
            self.assertEqual(
                get_cors_origins(),
                ["https://console.example.com", "http://localhost:5173"],
            )

    def test_cors_wildcard_is_rejected(self):
        with patch.dict(
            os.environ,
            {"AGENTSHIELD_CORS_ORIGINS": "*"},
            clear=False,
        ):
            with self.assertRaisesRegex(RuntimeError, "explicit origins"):
                get_cors_origins()

    def test_local_development_cors_defaults_cover_vite_hosts(self):
        with patch.dict(
            os.environ,
            {
                "AGENTSHIELD_ENVIRONMENT": "development",
                "AGENTSHIELD_CORS_ORIGINS": "",
            },
            clear=False,
        ):
            self.assertEqual(
                get_cors_origins(),
                ["http://localhost:5173", "http://127.0.0.1:5173"],
            )

    def test_production_cors_does_not_use_development_defaults(self):
        with patch.dict(
            os.environ,
            {
                "AGENTSHIELD_ENVIRONMENT": "production",
                "AGENTSHIELD_CORS_ORIGINS": "",
            },
            clear=False,
        ):
            self.assertEqual(get_cors_origins(), [])
