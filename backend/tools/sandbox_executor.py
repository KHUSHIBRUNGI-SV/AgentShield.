import json
import os
import subprocess
import urllib.error
import urllib.request

from fastapi import HTTPException

from security.policy_engine import check_action_policy


SANDBOX_IMAGE = os.getenv(
    "AGENTSHIELD_SANDBOX_IMAGE",
    "agentshield-sandbox:local"
)
SANDBOX_TIMEOUT_SECONDS = 10
SANDBOX_URL = os.getenv("AGENTSHIELD_SANDBOX_URL")
SANDBOX_TOKEN = os.getenv("AGENTSHIELD_SANDBOX_TOKEN")
ALLOWED_SANDBOX_ACTIONS = {("demo", "preview")}


def execute_in_sandbox(request):
    authorization = check_action_policy(
        request.agent,
        request.resource,
        request.action,
        request.environment,
        request.records,
        tool=request.tool,
    )
    if authorization["decision"] != "SANDBOX":
        raise PermissionError(
            "Sandbox dispatch requires a matching deterministic SANDBOX policy"
        )
    if (request.resource, request.action.lower()) not in ALLOWED_SANDBOX_ACTIONS:
        raise PermissionError("No tool is registered for sandbox execution")

    payload = json.dumps({
        "action": request.action.lower(),
        "resource": request.resource,
        "records": request.records,
    })
    if SANDBOX_URL:
        if not SANDBOX_TOKEN or len(SANDBOX_TOKEN.encode("utf-8")) < 32:
            raise HTTPException(
                status_code=503,
                detail="Sandbox authentication is not configured",
            )
        sandbox_request = urllib.request.Request(
            f"{SANDBOX_URL.rstrip('/')}/run",
            data=payload.encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "X-AgentShield-Sandbox-Token": SANDBOX_TOKEN,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                sandbox_request,
                timeout=SANDBOX_TIMEOUT_SECONDS,
            ) as response:
                result = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
            raise HTTPException(
                status_code=503,
                detail="Isolated Docker sandbox is unavailable; action was not processed",
            ) from error
        if not isinstance(result, dict) or result.get("executed") is not True:
            raise HTTPException(
                status_code=503,
                detail="Sandbox did not confirm successful isolated execution",
            )
        return result

    command = [
        "docker", "run", "--rm", "-i", "--pull=never",
        "--network=none",
        "--read-only",
        "--memory=64m",
        "--cpus=0.5",
        "--pids-limit=32",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m",
        SANDBOX_IMAGE,
    ]
    try:
        completed = subprocess.run(
            command,
            input=payload,
            capture_output=True,
            text=True,
            timeout=SANDBOX_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HTTPException(
            status_code=503,
            detail="Isolated Docker sandbox is unavailable; action was not processed",
        ) from error

    if completed.returncode != 0:
        raise HTTPException(
            status_code=503,
            detail="Isolated Docker sandbox failed; action was not processed",
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise HTTPException(
            status_code=503,
            detail="Sandbox returned an invalid response",
        ) from error
    if not isinstance(result, dict) or result.get("executed") is not True:
        raise HTTPException(
            status_code=503,
            detail="Sandbox did not confirm successful isolated execution",
        )
    return result
