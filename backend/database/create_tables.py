from database.database import (
    DATABASE_MODE,
    engine,
    Base,
    initialize_development_schema,
)
from database import models  # noqa: F401


if DATABASE_MODE == "sqlite-dev":
    initialize_development_schema(engine)
    print("Missing tables created in the local SQLite development database.")
else:
    Base.metadata.create_all(bind=engine)
    from database.migrate import apply_migrations

    apply_migrations()
    from security.audit_integrity import backfill_audit_chain

    backfill_audit_chain(engine)
    print("Missing tables created and pending PostgreSQL migrations applied.")