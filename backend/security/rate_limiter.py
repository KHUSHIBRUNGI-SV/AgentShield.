import os
import hashlib

import redis
from fastapi import HTTPException
from config import load_environment


load_environment()

redis_client = redis.Redis.from_url(
    os.getenv("REDIS_URL") or "redis://localhost:6379/0",
    decode_responses=True,
    socket_connect_timeout=1,
    socket_timeout=1
)

INCREMENT_WITH_EXPIRY = """
local count = redis.call('INCR', KEYS[1])
if count == 1 or redis.call('TTL', KEYS[1]) == -1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
"""


def check_rate_limit(agent_name, limit):
    if limit <= 0:
        raise ValueError("Rate limit must be a positive integer")

    identity_hash = hashlib.sha256(
        agent_name.encode("utf-8")
    ).hexdigest()
    key = f"agentshield:rate_limit:{identity_hash}"

    try:
        current_count = redis_client.eval(
            INCREMENT_WITH_EXPIRY,
            1,
            key,
            60
        )
    except redis.RedisError as error:
        raise HTTPException(
            status_code=503,
            detail="Rate limiting is unavailable; action was not processed"
        ) from error

    if current_count > limit:

        return (
            False,
            f"Rate limit exceeded: maximum {limit} requests per minute"
        )

    return True, "Rate limit allowed"