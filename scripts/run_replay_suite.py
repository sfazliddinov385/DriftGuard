import argparse
import json
import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.matching import Event, EventLogSource, SigmaMatcher

MANIFEST_PATH = Path("tests/manifest.yml")


def load_manifest(manifest_path: Path = MANIFEST_PATH) -> list[dict]:
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8-sig"))
    entries = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(entries, list) or not entries:
        raise ValueError("The manifest must contain a nonempty list of rules.")
    for entry in entries:
        if not isinstance(entry, dict) or not all(
            isinstance(entry.get(key), str) and entry[key] for key in ("id", "rule_path", "log_path")
        ):
            raise ValueError("Each manifest entry needs an id, rule_path and log_path.")
    return entries


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


@dataclass
class Cases:
    hits: int | None = None
    total: int | None = None


@dataclass
class RecordedCases(Cases):
    expected: int | None = None
    matched_ids: list[str] | None = None
    missed_ids: list[str] | None = None
    unexpected_ids: list[str] | None = None


@dataclass
class RuleResult:
    id: str
    rule_path: str
    fixture_path: str
    title: str | None = None
    technique: str | None = None
    status: str = "error"
    summary: str = ""
    recorded: RecordedCases = field(default_factory=RecordedCases)
    withheld: Cases = field(default_factory=Cases)
    benign: Cases = field(default_factory=Cases)


def evaluate_rule(
    entry: dict,
    rule_yaml: str | None = None,
    events: list[dict] | None = None,
) -> RuleResult:
    result = RuleResult(entry["id"], entry["rule_path"], entry["log_path"])
    try:
        if rule_yaml is None:
            rule_yaml = Path(result.rule_path).read_text(encoding="utf-8-sig")
        collection = SigmaCollection.from_yaml(rule_yaml)
        rule = collection.rules[0]
        result.title = str(rule.title)
        for tag in rule.tags:
            if tag.namespace == "attack" and re.fullmatch(
                r"t[0-9]{4}(?:\.[0-9]{3})?", tag.name, re.I
            ):
                result.technique = tag.name.upper()
                break
        matcher = SigmaMatcher(collection)

        expected_pos = {str(rid) for rid in entry.get("expected_positive_record_ids", [])}
        withheld_events = entry.get("withheld_positive_events", [])
        benign_events = entry.get("benign_events", [])
        result.recorded.expected = len(expected_pos)
        result.withheld.total = len(withheld_events)
        result.benign.total = len(benign_events)
        if events is None:
            events = parse_sysmon_events(Path(result.fixture_path), entry.get("event_id"))
        result.recorded.total = len(events)
        expected_count = entry.get("expected_event_count")
        if expected_count is not None and len(events) != expected_count:
            result.summary = f"Expected {expected_count} filtered events, found {len(events)}."
            return result

        ids = [str(ev.get("EventRecordID", "")) for ev in events]
        # Sysmon record IDs are numeric. Never copy an arbitrary event field into a public report.
        if not events or not all(re.fullmatch(r"[0-9]+", rid) for rid in ids):
            result.summary = "The recording has no usable events or contains an invalid record ID."
            return result
        if len(ids) != len(set(ids)):
            result.summary = "The recording contains duplicate event record IDs."
            return result
        if not expected_pos.issubset(ids):
            result.summary = "The recording is missing expected positive record IDs."
            return result

        ls_cfg = entry.get("logsource", {})
        source = EventLogSource(
            product=ls_cfg.get("product", "windows"),
            category=ls_cfg.get("category", "process_creation"),
            service=ls_cfg.get("service"),
        )
        observed = {rid for rid, ev in zip(ids, events) if matches(matcher, source, ev)}
        withheld_hits = sum(matches(matcher, source, ev) for ev in withheld_events)
        benign_hits = sum(matches(matcher, source, ev) for ev in benign_events)
    except (
        OSError, ValueError, TypeError, IndexError, KeyError, AttributeError,
        SigmaError, ET.ParseError, yaml.YAMLError,
    ) as exc:
        # Parser errors can contain snippets of the recording. Publish only the error type.
        result.summary = f"Could not evaluate the rule or its fixtures ({type(exc).__name__})."
        return result

    result.recorded.hits = len(observed)
    result.recorded.matched_ids = sorted(observed)
    result.recorded.missed_ids = sorted(expected_pos - observed)
    result.recorded.unexpected_ids = sorted(observed - expected_pos)
    result.withheld.hits = withheld_hits
    result.benign.hits = benign_hits
    passed = observed == expected_pos and withheld_hits == len(withheld_events) and benign_hits == 0
    result.status = "pass" if passed else "fail"
    result.summary = (
        f"Recorded matches: {len(observed)}/{len(events)} (expected {len(expected_pos)}); "
        f"withheld positives: {withheld_hits}/{len(withheld_events)}; "
        f"benign false positives: {benign_hits}/{len(benign_events)}."
    )
    if result.recorded.missed_ids:
        result.summary += " Missed positive IDs: " + ", ".join(result.recorded.missed_ids)
    if result.recorded.unexpected_ids:
        result.summary += " Unexpected positive IDs: " + ", ".join(result.recorded.unexpected_ids)
    return result


def check_rule_entry(
    rule_yaml: str,
    entry: dict,
    events: list[dict] | None = None,
) -> tuple[bool, str]:
    result = evaluate_rule(entry, rule_yaml, events)
    return result.status == "pass", result.summary


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # The temporary file and destination share a filesystem, so readers see a whole report.
    with tempfile.TemporaryDirectory(dir=path.parent) as staging:
        staged = Path(staging) / "report.json"
        staged.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        staged.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run DriftGuard pySigma replay suite.")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH), help="Path to manifest.yml")
    parser.add_argument("--rule", help="Optional single rule path to test")
    parser.add_argument("--failed-out", help="Write failing rule paths (one per line) to this file")
    parser.add_argument("--json-out", type=Path, help="Write replay evidence as a JSON report")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    error = None
    try:
        entries = [get_rule_entry(args.rule, manifest_path)] if args.rule else load_manifest(manifest_path)
    except (OSError, UnicodeError, KeyError, ValueError, yaml.YAMLError) as exc:
        error = f"Cannot load the requested rule manifest ({type(exc).__name__})."
        print(error, file=sys.stderr)
        entries = []

    results = []
    failed_rules = []
    for entry in entries:
        result = evaluate_rule(entry)
        results.append(result)
        print(f"=== {result.id} ===")
        print(f"Rule:   {result.rule_path}")
        print(f"Source: {result.fixture_path}")
        print(result.summary)
        print("RESULT: PASS" if result.status == "pass" else "RESULT: FAIL")
        if result.status != "pass":
            failed_rules.append(result.rule_path)

    if args.failed_out:
        out_path = Path(args.failed_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            ("\n".join(failed_rules) + "\n") if failed_rules else "",
            encoding="utf-8",
        )

    status = "fail" if failed_rules else "pass"
    if error or any(result.status == "error" for result in results):
        status = "error"
    if args.json_out:
        write_report(
            args.json_out,
            {
                "schema_version": 1,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "commit": os.getenv("GITHUB_SHA"),
                "run_id": os.getenv("GITHUB_RUN_ID"),
                "run_number": os.getenv("GITHUB_RUN_NUMBER"),
                "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
                "status": status,
                "error": error,
                "rules": [asdict(result) for result in results],
            },
        )

    print(f"\nSuite summary: {len(results) - len(failed_rules)}/{len(results)} rules passed.")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
