import json
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.matching import Event, EventLogSource, SigmaMatcher

RULE_PATH = Path("rules/windows/proc_creation_encoded_powershell.yml")
LOG_PATH = Path("tests/fixtures/encoded_powershell/splunk-sysmon.log")

# Independent Sysmon record labels for this specific Splunk recording.
EXPECTED_RECORDS = {"5613964": True, "5597245": False, "5585441": True, "5575766": False}
SOURCE = EventLogSource(product="windows", category="process_creation")
POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

# Synthetic telemetry only. Keep the standalone switch cases out of the model prompt.
STANDALONE_EVENTS = [
    {"EventID": "1", "Image": POWERSHELL, "CommandLine": "powershell.exe -enc SABpAA=="},
    {"EventID": "1", "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
     "CommandLine": "pwsh.exe -EncodedCommand SABpAA=="},
]

BENIGN_EVENTS = [
    {
        "EventID": "1",
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": r"powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\Scripts\healthcheck.ps1",
    },
    {
        "EventID": "1",
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
    },
    {
        "EventID": "1",
        "Image": POWERSHELL,
        "CommandLine": "powershell.exe -ep RemoteSigned -File healthcheck.ps1",
    },
    {
        "EventID": "1",
        "Image": r"C:\Lab\tool.exe",
        "CommandLine": "tool.exe -enc example",
    },
]


def parse_sysmon_events(log_path: Path) -> list[dict]:
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
        return events

    if raw.startswith("["):
        return json.loads(raw)
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            events.append(json.loads(line))
    return events


def matches(matcher: SigmaMatcher, fields: dict) -> bool:
    event_time = fields.get("UtcTime", "2026-01-01 00:00:00")
    timestamp = datetime.fromisoformat(event_time)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    event = Event(timestamp=timestamp, logsource=SOURCE, data=fields)
    return bool(list(matcher.match(event)))


def check_rule_replay(rule_yaml: str, events: list[dict]) -> tuple[bool, str]:
    ids = [str(event.get("EventRecordID", "")) for event in events]
    if len(ids) != len(EXPECTED_RECORDS) or set(ids) != set(EXPECTED_RECORDS):
        return False, "Recording is missing or differs from the four labeled Sysmon records."

    try:
        matcher = SigmaMatcher(SigmaCollection.from_yaml(rule_yaml))
        observed = {record: matches(matcher, event) for record, event in zip(ids, events)}
        standalone = sum(matches(matcher, event) for event in STANDALONE_EVENTS)
        benign = sum(matches(matcher, event) for event in BENIGN_EVENTS)
    except (SigmaError, ValueError, TypeError) as exc:
        return False, f"Sigma replay could not evaluate the rule: {exc}"

    mismatches = [record for record in observed if observed[record] != EXPECTED_RECORDS[record]]
    passed = not mismatches and standalone == len(STANDALONE_EVENTS) and benign == 0
    summary = (
        f"Recorded matches: {sum(observed.values())}/{len(events)}; "
        f"standalone encoded switches: {standalone}/{len(STANDALONE_EVENTS)}; "
        f"benign false positives: {benign}/{len(BENIGN_EVENTS)}."
    )
    if mismatches:
        summary += " Incorrect record labels: " + ", ".join(mismatches)
    return passed, summary


def main() -> int:
    rule = RULE_PATH.read_text(encoding="utf-8-sig")
    events = parse_sysmon_events(LOG_PATH)
    passed, summary = check_rule_replay(rule, events)
    print(f"Rule: {RULE_PATH}")
    print(f"Source: {LOG_PATH}")
    print(summary)
    print("RESULT: PASS" if passed else "RESULT: FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
