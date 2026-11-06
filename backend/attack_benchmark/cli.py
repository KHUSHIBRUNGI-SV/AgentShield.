import argparse
import json
from pathlib import Path

from attack_benchmark.runner import run_benchmark


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run AgentShield's isolated attack and legitimate-action benchmark."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for generated JSON and CSV reports.",
    )
    args = parser.parse_args()
    report = run_benchmark(report_dir=args.output_dir)
    print(json.dumps({
        "summary": report["summary"],
        "report_files": report["report_files"],
    }, indent=2))


if __name__ == "__main__":
    main()
