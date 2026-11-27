"""Combine the replay report and GitHub's step outcomes into one public snapshot."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    report_path = Path("reports/replay.json")
    replay = json.loads(report_path.read_text(encoding="utf-8")) if report_path.exists() else None
    baseline_path = Path("reports/benign-baseline.json")
    baseline = None
    if os.environ.get("CHECK_BASELINE") == "success" and baseline_path.exists():
        measured = json.loads(baseline_path.read_text(encoding="utf-8"))
        # Only publish counts for this curated dataset. Local Splunk reports stay on the PC.
        baseline = {
            "event_count": measured["event_count"],
            "any_rule_matches": measured["any_rule_matches"],
            "rules": [
                {"id": row["id"], "matched_count": row["matched_count"]}
                for row in measured["rules"]
            ],
        }
    checks = {
        name: os.environ.get(f"CHECK_{name.upper()}") or "unknown"
        for name in ("sigma", "splunk", "pytest", "replay", "baseline", "healer", "draft_pr")
    }
    job = os.environ.get("JOB_STATUS")
    if job == "failure" or (replay and replay["status"] in {"fail", "error"}):
        status = "fail"
    elif job == "success" and replay and replay["status"] == "pass" and baseline and all(
        checks[name] == "success" for name in ("sigma", "splunk", "pytest", "replay", "baseline")
    ):
        status = "pass"
    else:
        status = "unknown"

    snapshot = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "commit": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "run_number": os.environ.get("GITHUB_RUN_NUMBER"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "pipeline_status": status,
        "checks": checks,
        "replay": replay,
        "benign_baseline": baseline,
    }
    out = Path("dashboard/data.json")
    out.write_text(json.dumps(snapshot, indent=2, allow_nan=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
