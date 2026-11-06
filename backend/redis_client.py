import json
import os
import redis
from config import load_environment


load_environment()

redis_client = redis.Redis.from_url(
    os.getenv("REDIS_URL") or "redis://localhost:6379/0",
    decode_responses=True,
    socket_connect_timeout=1,
    socket_timeout=1,
)


def save_audit_event(event):
    # Convert Pydantic objects such as ActionRequest into dictionaries
    event_json = json.dumps(
        event,
        default=lambda obj: obj.model_dump()
        if hasattr(obj, "model_dump")
        else str(obj)
    )

    redis_client.lpush(
        "agentshield:audit_logs",
        event_json
    )


def get_audit_events():
    events = redis_client.lrange(
        "agentshield:audit_logs",
        0,
        -1
    )

    return [json.loads(event) for event in events]