import os

import pytest
import redis
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError


pytestmark = pytest.mark.integration


def _require_integration_opt_in() -> None:
    if os.getenv("AGENTSHIELD_RUN_INTEGRATION_TESTS") != "1":
        pytest.skip(
            "Set AGENTSHIELD_RUN_INTEGRATION_TESTS=1 to enable live-service tests"
        )


def test_postgresql_is_reachable():
    _require_integration_opt_in()
    database_url = os.getenv("AGENTSHIELD_TEST_DATABASE_URL", "").strip()
    if not database_url:
        pytest.skip("AGENTSHIELD_TEST_DATABASE_URL is not configured")
    if not database_url.startswith(("postgresql://", "postgresql+")):
        pytest.skip("Live PostgreSQL test requires a PostgreSQL test URL")

    engine = create_engine(database_url, pool_pre_ping=True, connect_args={"connect_timeout": 2})
    try:
        try:
            with engine.connect() as connection:
                assert connection.execute(text("SELECT 1")).scalar_one() == 1
        except OperationalError as error:
            pytest.skip(f"PostgreSQL test service is unavailable: {error}")
    finally:
        engine.dispose()


def test_redis_is_reachable():
    _require_integration_opt_in()
    redis_url = os.getenv("AGENTSHIELD_TEST_REDIS_URL", "").strip()
    if not redis_url:
        pytest.skip("AGENTSHIELD_TEST_REDIS_URL is not configured")

    client = redis.Redis.from_url(
        redis_url,
        socket_connect_timeout=2,
        socket_timeout=2,
    )
    try:
        try:
            assert client.ping() is True
        except redis.RedisError as error:
            pytest.skip(f"Redis test service is unavailable: {error}")
    finally:
        client.close()
