import os
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import dotenv_values, load_dotenv


BACKEND_DIR = Path(__file__).resolve().parent
ENV_FILE = BACKEND_DIR / ".env"
PLACEHOLDER_SECRETS = {
    "",
    "paste_your_generated_key_here",
    "changeme",
    "change-me",
    "your-secret-here",
}


def load_environment() -> None:
    load_dotenv(ENV_FILE, override=False)
    for key, value in dotenv_values(ENV_FILE).items():
        if value is not None and not os.getenv(key, "").strip():
            os.environ[key] = value


def get_secret_key() -> str:
    load_environment()
    secret_key = os.getenv("AGENTSHIELD_SECRET_KEY", "").strip()
    if secret_key.lower() in PLACEHOLDER_SECRETS:
        raise RuntimeError(
            "AGENTSHIELD_SECRET_KEY is missing or still a placeholder. "
            f"Set a unique secret of at least 32 bytes in {ENV_FILE}. "
            f"If the file does not exist, copy {BACKEND_DIR / '.env.example'} "
            "to backend/.env and replace the placeholder."
        )
    if len(secret_key.encode("utf-8")) < 32:
        raise RuntimeError(
            "AGENTSHIELD_SECRET_KEY must contain at least 32 UTF-8 bytes. "
            f"Configure it in {ENV_FILE}; do not use a placeholder."
        )
    return secret_key


def get_cors_origins() -> list[str]:
    load_environment()
    origins = []
    for configured_origin in os.getenv("AGENTSHIELD_CORS_ORIGINS", "").split(","):
        origin = configured_origin.strip()
        if not origin:
            continue
        if origin == "*":
            raise RuntimeError(
                "AGENTSHIELD_CORS_ORIGINS must list explicit origins; '*' is not allowed."
            )
        try:
            parsed = urlsplit(origin)
            parsed.port
        except ValueError as error:
            raise RuntimeError(
                "AGENTSHIELD_CORS_ORIGINS contains an invalid origin."
            ) from error
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or not parsed.hostname
            or parsed.hostname == "*"
            or parsed.port == 0
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise RuntimeError(
                "AGENTSHIELD_CORS_ORIGINS must contain comma-separated HTTP(S) origins "
                "without paths, credentials, query strings, or fragments."
            )
        normalized_origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
        if normalized_origin not in origins:
            origins.append(normalized_origin)
    if not origins and os.getenv(
        "AGENTSHIELD_ENVIRONMENT", "development"
    ).strip().lower() not in {"production", "prod"}:
        return [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    return origins


def validate_runtime_configuration() -> None:
    load_environment()
    from database.database import get_database_configuration

    environment = os.getenv("AGENTSHIELD_ENVIRONMENT", "development").strip().lower()
    cors_origins = get_cors_origins()
    if environment in {"production", "prod"}:
        if not cors_origins:
            raise RuntimeError(
                "AGENTSHIELD_CORS_ORIGINS must configure at least one trusted "
                "dashboard origin in production."
            )
        redis_url = os.getenv("REDIS_URL", "").strip()
        redis_parts = urlsplit(redis_url)
        if (
            redis_parts.scheme not in {"redis", "rediss"}
            or not redis_parts.hostname
            or not redis_parts.password
        ):
            raise RuntimeError(
                "An authenticated REDIS_URL is required in production for rate limiting."
            )
        sandbox_token = os.getenv("AGENTSHIELD_SANDBOX_TOKEN", "")
        if len(sandbox_token.encode("utf-8")) < 32:
            raise RuntimeError(
                "AGENTSHIELD_SANDBOX_TOKEN must contain at least 32 bytes in production."
            )

    get_database_configuration()
    get_secret_key()


load_environment()
