import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
import yaml

RULE_PATH = Path("rules/windows/proc_creation_encoded_powershell.yml")
LOG_PATH = Path("tests/fixtures/encoded_powershell/splunk-sysmon.log")

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
                if tag == "EventID" and elem.text:
                    ev["EventID"] = elem.text.strip()
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


def match_field(event_val: str, pattern: str, modifier: str) -> bool:
    ev = event_val.lower()
    pat = str(pattern).lower()
    if modifier == "endswith":
        return ev.endswith(pat)
    if modifier == "startswith":
        return ev.startswith(pat)
    if modifier == "contains":
        return pat in ev
    return ev == pat


def match_selection(event: dict, selection: dict) -> bool:
    for key, expected in selection.items():
        parts = key.split("|")
        field = parts[0]
        modifier = parts[1] if len(parts) > 1 else "exact"
        val = str(event.get(field, ""))
        patterns = expected if isinstance(expected, list) else [expected]
        if not any(match_field(val, p, modifier) for p in patterns):
            return False
    return True


def evaluate_rule(event: dict, rule: dict) -> bool:
    detection = rule["detection"]
    selections = {k: v for k, v in detection.items() if k != "condition"}
    return all(match_selection(event, sel) for sel in selections.values())


def main() -> int:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8-sig"))
    events = parse_sysmon_events(LOG_PATH)

    if not events:
        print(f"FAIL: No events parsed from {LOG_PATH}")
        return 1

    attack_matches = [ev for ev in events if evaluate_rule(ev, rule)]
    benign_matches = [ev for ev in BENIGN_EVENTS if evaluate_rule(ev, rule)]

    print(f"Rule:   {rule['title']}")
    print(f"Source: {LOG_PATH}")
    print(f"Recorded events parsed: {len(events)}")
    print(f"Attack matches:         {len(attack_matches)} / {len(events)}")
    print(f"Benign false positives: {len(benign_matches)} / {len(BENIGN_EVENTS)}")

    for idx, ev in enumerate(attack_matches, start=1):
        print(f"  [Match {idx}] EventID={ev.get('EventID')} Image={ev.get('Image')}")
        print(f"             CommandLine={ev.get('CommandLine', '')[:120]}")

    if len(attack_matches) == 0 or len(benign_matches) > 0:
        print("RESULT: FAIL (Detection drift or false positive detected)")
        return 1

    print("RESULT: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())