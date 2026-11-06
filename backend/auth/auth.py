import os

import bcrypt
import jwt
import logging
from config import get_secret_key, load_environment
from sqlalchemy.exc import SQLAlchemyError

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


# =========================================================
# CONFIGURATION
# =========================================================

load_environment()

ALGORITHM = "HS256"
JWT_ISSUER = os.getenv("AGENTSHIELD_JWT_ISSUER", "agentshield")
JWT_AUDIENCE = os.getenv("AGENTSHIELD_JWT_AUDIENCE", "agentshield-api")

TOKEN_EXPIRATION_MINUTES = 15


security = HTTPBearer()
logger = logging.getLogger(__name__)


# =========================================================auth
# PASSWORD HASHING
# =========================================================

def hash_password(password: str):

    password_bytes = password.encode("utf-8")
    if len(password_bytes) < 12 or len(password_bytes) > 72:
        raise ValueError("Password must contain 12 to 72 UTF-8 bytes")

    salt = bcrypt.gensalt(rounds=12)

    hashed = bcrypt.hashpw(
        password_bytes,
        salt
    )

    return hashed.decode("utf-8")


def verify_password(
    password: str,
    password_hash: str
):

    password_bytes = password.encode("utf-8")
    if len(password_bytes) < 12 or len(password_bytes) > 72:
        return False

    try:
        return bcrypt.checkpw(
            password_bytes,
            password_hash.encode("utf-8")
        )
    except ValueError:
        return False


# =========================================================
# JWT CREATION
# =========================================================

def create_access_token(
    username: str,
    role: str
):

    expiration = (
        datetime.now(timezone.utc)
        + timedelta(
            minutes=TOKEN_EXPIRATION_MINUTES
        )
    )

    payload = {
        "sub": username,
        "role": role,
        "exp": expiration,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid4()),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE
    }

    token = jwt.encode(
        payload,
        get_secret_key(),
        algorithm=ALGORITHM
    )

    return token


# =========================================================
# JWT VERIFICATION
# =========================================================

def get_current_user(
    credentials: HTTPAuthorizationCredentials
):

    token = credentials.credentials

    try:

        payload = jwt.decode(
            token,
            get_secret_key(),
            algorithms=[ALGORITHM],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={"require": ["exp", "iat", "sub", "jti", "iss", "aud"]}
        )

    except jwt.ExpiredSignatureError:

        raise HTTPException(
            status_code=401,
            detail="Token has expired"
        )

    except jwt.InvalidTokenError:

        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token"
        )

    username = payload.get("sub")

    if not username:

        raise HTTPException(
            status_code=401,
            detail="Invalid token payload"
        )

    from database.database import SessionLocal
    from database.models import User

    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.username == username
        ).first()
        if not user or not user.is_active:
            raise HTTPException(
                status_code=401,
                detail="User account is unavailable"
            )

        return {
            "username": user.username,
            "role": user.role
        }
    except SQLAlchemyError as error:
        db.rollback()
        logger.error(
            "Authenticated account lookup failed (%s)",
            type(error).__name__,
        )
        raise HTTPException(
            status_code=503,
            detail="Authentication database is unavailable. Check GET /health and backend database configuration.",
        ) from error
    finally:
        db.close()


def require_agent(user):

    if user["role"] != "agent":

        raise HTTPException(
            status_code=403,
            detail="Agent privileges required"
        )

    return {
        "username": user["username"],
        "role": user["role"]
    }


# =========================================================
# ROLE AUTHORIZATION
# =========================================================

def require_reviewer(user):

    if user["role"] not in [
        "reviewer",
        "security_admin"
    ]:

        raise HTTPException(
            status_code=403,
            detail="Reviewer privileges required"
        )

    return user