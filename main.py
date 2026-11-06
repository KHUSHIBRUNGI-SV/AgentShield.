"""Root-level ASGI entry point for the backend application."""

import importlib
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent / "backend"
backend_path = str(BACKEND_DIR)
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

backend_module = importlib.import_module("backend.main")
sys.modules[__name__] = backend_module
