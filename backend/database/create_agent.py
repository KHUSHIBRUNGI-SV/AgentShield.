import os

from auth.auth import hash_password
from database.database import SessionLocal
from database.models import Agent, User


def create_agent_user():
    username = os.getenv("AGENTSHIELD_AGENT_USERNAME")
    password = os.getenv("AGENTSHIELD_AGENT_PASSWORD")

    if not username or not password:
        raise RuntimeError(
            "Set AGENTSHIELD_AGENT_USERNAME and "
            "AGENTSHIELD_AGENT_PASSWORD before provisioning an agent"
        )

    db = SessionLocal()
    try:
        agent = db.query(Agent).filter(
            Agent.name == username
        ).first()
        if not agent:
            raise RuntimeError(
                "The agent must be registered before its credentials are provisioned"
            )

        existing_user = db.query(User).filter(
            User.username == username
        ).first()
        if existing_user:
            raise RuntimeError(
                "A user account already exists for this agent"
            )

        db.add(User(
            username=username,
            password_hash=hash_password(password),
            role="agent",
            is_active=True
        ))
        db.commit()
        print("Agent credentials created successfully.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    create_agent_user()
