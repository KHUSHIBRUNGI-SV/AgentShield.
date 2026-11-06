"""Compatibility entry point for the AgentShield attack benchmark CLI."""

import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
backend_path = str(BACKEND_DIR)
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from attack_benchmark.cli import main


if __name__ == "__main__":
    main()
