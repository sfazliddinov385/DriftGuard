import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.matching import Event, EventLogSource, SigmaMatcher

MANIFEST_PATH = Path("tests/manifest.yml")


def load_manifest(manifest_path: Path = MANIFEST_PATH) -> list[dict]:
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8-sig"))
    return data.get("rules", [])


def get_rule_entry(rule_path: str, manifest_path: Path = MANIFEST_PATH) -> dict:
    target = Path(rule_path).as_posix()
    for entry in load_manifest(manifest_path):
        if Path(entry["rule_path"]).as_posix() == target:
            return entry
    raise KeyError(f"Rule '{target}' not found in {manifest_path}")


def parse_sysmon_events(log_path: Path, event_id: str | None = None) -> list[dict]:
    raw = log_path.read_text(encoding="utf-8-sig", errors="ignore").strip()
    events: list[dict] = []

    xml_blocks = re.findall(r"<Event\b.*?</Event>", raw, flags=re.DOTALL)
    if xml_blocks:
        for block in xml_blocks:
            root = ET.fromstring(block)
            ev: dict[str, str] = {}
            for elem in root.iter():
                tag = elem.tag.split("}")[-1]
                if tag in {"EventID", "EventRecordID"} and elem.text:
                    ev[tag] = elem.text.strip()
                elif tag == "Data" and "Name" in elem.attrib:
                    ev[elem.attrib["Name"]] = (elem.text or "").strip()
            if ev:
                events.append(ev)
    elif raw.startswith("["):
        events = json.loads(raw)
    else:
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("{"):
                events.append(json.loads(line))

    if event_id is not None:
        events = [ev for ev in events if str(ev.get("EventID", "")) == str(event_id)]
    return events


def matches(matcher: SigmaMatcher, source: EventLogSource, fields: dict) -> bool:
    event_time = str(fields.get("UtcTime", "2026-01-01 00:00:00"))
    try:
        timestamp = datetime.fromisoformat(event_time)
    except ValueError:
        timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    event = Event(timestamp=timestamp, logsource=source, data=fields)
    return bool(list(matcher.match(event)))


def check_rule_entry(
    rule_yaml: str,
    entry: dict,
    events: list[dict] | None = None,
) -> tuple[bool, str]:
    if events is None:
        events = parse_sysmon_events(Path(entry["log_path"]), entry.get("event_id"))

    expected_count = entry.get("expected_event_count")
    if expected_count is not None and len(events) != expected_count:
        return (
            False,
            f"Expected {expected_count} filtered events in {entry['log_path']}, found {len(events)}.",
        )

    expected_pos = {str(rid) for rid in entry.get("expected_positive_record_ids", [])}
    ids = [str(ev.get("EventRecordID", "")) for ev in events]
    missing_expected = expected_pos - set(ids)
    if missing_expected:
        return False, f"Recording is missing expected record IDs: {sorted(missing_expected)}"

    ls_cfg = entry.get("logsource", {})
    source = EventLogSource(
        product=ls_cfg.get("product", "windows"),
        category=ls_cfg.get("category", "process_creation"),
        service=ls_cfg.get("service"),
    )

    withheld_events = entry.get("withheld_positive_events", [])
    benign_events = entry.get("benign_events", [])

    try:
        matcher = SigmaMatcher(SigmaCollection.from_yaml(rule_yaml))
        observed_pos = {
            rid for rid, ev in zip(ids, events) if matches(matcher, source, ev)
        }
        withheld_hits = sum(matches(matcher, source, ev) for ev in withheld_events)
        benign_hits = sum(matches(matcher, source, ev) for ev in benign_events)
    except (SigmaError, ValueError, TypeError) as exc:
        return False, f"Sigma replay could not evaluate the rule: {exc}"

    missed_pos = sorted(expected_pos - observed_pos)
    unexpected_pos = sorted(observed_pos - expected_pos)

    passed = (
        not missed_pos
        and not unexpected_pos
        and withheld_hits == len(withheld_events)
        and benign_hits == 0
    )

    summary = (
        f"Recorded matches: {len(observed_pos)}/{len(events)} (expected {len(expected_pos)}); "
        f"withheld positives: {withheld_hits}/{len(withheld_events)}; "
        f"benign false positives: {benign_hits}/{len(benign_events)}."
    )
    if missed_pos:
        summary += " Missed positive IDs: " + ", ".join(missed_pos)
    if unexpected_pos:
        summary += " Unexpected positive IDs: " + ", ".join(unexpected_pos)
    return passed, summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Run DriftGuard pySigma replay suite.")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH), help="Path to manifest.yml")
    parser.add_argument("--rule", help="Optional single rule path to test")
    parser.add_argument("--failed-out", help="Write failing rule paths (one per line) to this file")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    entries = [get_rule_entry(args.rule, manifest_path)] if args.rule else load_manifest(manifest_path)

    failed_rules: list[str] = []
    for entry in entries:
        rule_path = Path(entry["rule_path"])
        rule_yaml = rule_path.read_text(encoding="utf-8-sig")
        passed, summary = check_rule_entry(rule_yaml, entry)

        print(f"=== {entry['id']} ===")
        print(f"Rule:   {rule_path.as_posix()}")
        print(f"Source: {entry['log_path']}")
        print(summary)
        print("RESULT: PASS" if passed else "RESULT: FAIL")
        if not passed:
            failed_rules.append(rule_path.as_posix())

    if args.failed_out:
        out_path = Path(args.failed_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            ("\n".join(failed_rules) + "\n") if failed_rules else "",
            encoding="utf-8",
        )

    print(f"\nSuite summary: {len(entries) - len(failed_rules)}/{len(entries)} rules passed.")
    return 0 if not failed_rules else 1


if __name__ == "__main__":
    sys.exit(main())