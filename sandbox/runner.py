import json
import sys


def run_action(request):
    if not isinstance(request, dict):
        raise ValueError("Request must be an object")
    if request.get("action") != "preview" or request.get("resource") != "demo":
        raise ValueError("Action is not allow-listed")
    records = request.get("records")
    if not isinstance(records, int) or isinstance(records, bool) or records < 0:
        raise ValueError("Invalid record count")
    return {
        "status": "SIMULATED",
        "message": "Demo preview ran in an isolated Docker container; no external system was contacted.",
        "executed": True,
        "isolation": "docker-no-network-readonly",
    }


def main():
    try:
        request = json.load(sys.stdin)
        print(json.dumps(run_action(request)))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
