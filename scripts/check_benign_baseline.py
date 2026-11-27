"""Measure which separately recorded normal Windows processes the current rules flag."""

import argparse
import json
import re
import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.matching import EventLogSource, SigmaMatcher

from run_replay_suite import load_manifest, matches, write_report


def measure_baseline(capture: dict, entries: list[dict]) -> dict:
    source = capture.get("source")
    events = capture.get("events")
    if not isinstance(source, str) or not source.strip() or not isinstance(events, list) or not events:
        raise ValueError("The baseline needs a source and at least one observed event.")

    ids = set()
    for event in events:
        if not isinstance(event, dict) or set(event) != {"case_id", "Image", "CommandLine"}:
            raise ValueError("Each captured event needs only case_id, Image and CommandLine.")
        case_id = event["case_id"]
        if not isinstance(case_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,99}", case_id):
            raise ValueError("Expected a short non-sensitive case ID.")
        if case_id in ids:
            raise ValueError(f"Duplicate baseline case ID: {case_id}.")
        ids.add(case_id)
        if not all(isinstance(event[k], str) and event[k].strip() for k in ("Image", "CommandLine")):
            raise ValueError(f"Missing process data in baseline case {case_id}.")

    logsource = EventLogSource(product="windows", category="process_creation")
    rules = []
    all_hits = set()
    for entry in entries:
        collection = SigmaCollection.from_yaml(Path(entry["rule_path"]).read_text(encoding="utf-8-sig"))
        matcher = SigmaMatcher(collection)
        hits = [
            event["case_id"] for event in events
            if matches(matcher, logsource, {"Image": event["Image"], "CommandLine": event["CommandLine"]})
        ]
        rules.append({"id": entry["id"], "matched_count": len(hits), "matched_case_ids": hits})
        all_hits.update(hits)

    return {"source": source, "event_count": len(events), "any_rule_matches": len(all_hits), "rules": rules}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Sanitized capture JSON.")
    parser.add_argument("--json-out", type=Path, required=True, help="Output matched case IDs and counts.")
    args = parser.parse_args()
    try:
        capture = json.loads(args.input.read_text(encoding="utf-8-sig"))
        if not isinstance(capture, dict):
            raise ValueError("The capture must be a JSON object.")
        report = measure_baseline(capture, load_manifest())
        write_report(args.json_out, report)
    except (OSError, ValueError, SigmaError) as exc:
        print(f"Could not measure the benign baseline: {exc}", file=sys.stderr)
        return 1
    print(f"Normal process records flagged: {report['any_rule_matches']}/{report['event_count']}.")
    for row in report["rules"]:
        print(f"{row['id']}: {row['matched_count']} matched ({', '.join(row['matched_case_ids']) or 'none'}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
