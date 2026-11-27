"""Create two inert copies of the recorded PowerShell events for a Splunk upload."""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from run_replay_suite import get_rule_entry, parse_sysmon_events

RULE_PATH = "rules/windows/proc_creation_encoded_powershell.yml"
INDEX = "driftguard_replay"
SCENARIOS = {"healthy": "driftguardhealthy", "renamed": "driftguardrenamed"}
# Only copy switch names. Never include command arguments, encoded text or child commands.
SWITCH = re.compile(r"(?:-|/)(?:windowstyle|ep|enc|encodedcommand|ec|e|c)", re.IGNORECASE)


def load_recording():
    entry = get_rule_entry(RULE_PATH)
    events = parse_sysmon_events(Path(entry["log_path"]), entry["event_id"])
    ids = [event["EventRecordID"] for event in events]
    positives = set(entry["expected_positive_record_ids"])
    if (
        len(ids) != entry["expected_event_count"]
        or len(set(ids)) != len(ids)
        or not positives
        or not positives.issubset(ids)
        or not all(re.fullmatch(r"[0-9]+", item) for item in ids)
    ):
        raise ValueError("The PowerShell recording and the expected record IDs disagree.")
    return entry, events


def prepare(output_dir: Path) -> dict:
    _, events = load_recording()
    batch = f"driftguard{uuid4().hex}"
    prepared = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines = []
    for event in events:
        image = event["Image"]
        switches = [word for word in event["CommandLine"].split() if SWITCH.fullmatch(word)]
        command = f'"{image}"' + "".join(f" {flag} [removed]" for flag in switches)
        for scenario, marker in SCENARIOS.items():
            row = {
                "time": prepared,
                "driftguard_batch": batch,
                "driftguard_case": marker,
                "EventID": event["EventID"],
                "EventRecordID": event["EventRecordID"],
                "Image": image,
                "CommandLine" if scenario == "healthy" else "OriginalCommandText": command,
            }
            lines.append(json.dumps(row))
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{batch}.json"
    with path.open("x", encoding="utf-8") as stream:
        stream.write("\n".join(lines) + "\n")
    return {"batch": batch, "path": str(path.resolve()), "events_per_case": len(events)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    print(json.dumps(prepare(parser.parse_args().output_dir)))
