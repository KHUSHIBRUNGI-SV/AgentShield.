import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import os

os.environ["AGENTSHIELD_ENVIRONMENT"] = "development"
os.environ["AGENTSHIELD_DATABASE_MODE"] = "sqlite-dev"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["AGENTSHIELD_SECRET_KEY"] = (
    "isolated-e2e-only-secret-key-with-at-least-32-bytes"
)
os.environ["AGENTSHIELD_CORS_ORIGINS"] = "http://127.0.0.1:5173"

import uvicorn

import database.models  # noqa: F401
import main
from auth.auth import hash_password
from database.database import Base, SessionLocal, engine
from database.models import Agent, User

Base.metadata.create_all(engine)
with SessionLocal() as db:
    db.add_all(
        [
            User(
                username="e2e_reviewer",
                password_hash=hash_password("e2e-reviewer-password"),
                role="security_admin",
                is_active=True,
            ),
            Agent(name="customer_support_bot", description="Isolated E2E agent"),
            User(
                username="customer_support_bot",
                password_hash=hash_password("e2e-agent-password"),
                role="agent",
                is_active=True,
            ),
        ]
    )
    db.commit()

# The E2E server runs without Redis; this test-only limiter preserves routing
# behavior while live Redis semantics are covered by isolated unit tests.
main.check_rate_limit = lambda *_: (True, "test-only rate limit allowed")

if __name__ == "__main__":
    port = int(os.getenv("AGENTSHIELD_E2E_PORT", "8765"))
    uvicorn.run(main.app, host="127.0.0.1", port=port, log_level="warning")
