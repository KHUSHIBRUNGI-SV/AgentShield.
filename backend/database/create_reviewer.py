import os
import getpass

from database.database import SessionLocal
from database.models import User

from auth.auth import hash_password


def create_reviewer(username=None, password=None):
    username = username or os.getenv("AGENTSHIELD_REVIEWER_USERNAME")
    password = password or os.getenv("AGENTSHIELD_REVIEWER_PASSWORD")

    if not username:
        username = input("Reviewer username: ").strip()
    if not password:
        password = getpass.getpass("Reviewer password (12-72 UTF-8 bytes): ")
        confirmation = getpass.getpass("Confirm reviewer password: ")
        if password != confirmation:
            raise ValueError("Reviewer passwords do not match")
    if not username:
        raise ValueError("Reviewer username must not be empty")

    db = SessionLocal()
    try:
        existing_user = db.query(User).filter(
            User.username == username
        ).first()

        if existing_user:
            print(f"User '{username}' already exists.")
            return

        user = User(
            username=username,
            password_hash=hash_password(password),
            role="security_admin",
            is_active=True
        )

        db.add(user)
        db.commit()
        print(f"Reviewer '{username}' created successfully.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    create_reviewer()