import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
BACKEND_ROOT = PROJECT_ROOT / "backend"

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from config import load_environment

load_environment()

# Never let the developer's local .env database or credentials leak into tests.
os.environ["AGENTSHIELD_ENVIRONMENT"] = "test"
os.environ["AGENTSHIELD_DATABASE_MODE"] = "sqlite-dev"
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["AGENTSHIELD_SECRET_KEY"] = (
    "pytest-only-secret-key-with-at-least-32-bytes"
)
os.environ.pop("AGENTSHIELD_SQLITE_PATH", None)
