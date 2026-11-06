import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def write_reports(
    report: dict[str, Any],
    output_dir: Path,
) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    json_path = output_dir / f"benchmark-{timestamp}.json"
    csv_path = output_dir / f"benchmark-{timestamp}.csv"
    report_files = {
        "json": str(json_path.resolve()),
        "csv": str(csv_path.resolve()),
    }
    report["report_files"] = report_files

    json_path.write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    columns = [
        "scenario_id",
        "attempt",
        "category",
        "is_attack",
        "authenticated_identity",
        "agent_identity",
        "tool",
        "action",
        "resource",
        "environment",
        "records",
        "expected_security_outcome",
        "decision",
        "dispatch_attempted",
        "http_status",
        "latency_ms",
        "reason",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(report["observations"])
    return report_files
