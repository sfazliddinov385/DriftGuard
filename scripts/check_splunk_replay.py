"""Check the indexed PowerShell demo with Splunk's own search engine."""

import argparse
import json
import re
from collections import Counter
from pathlib import Path

from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.splunk import splunk_windows_pipeline

from prepare_splunk_replay import INDEX, RULE_PATH, SCENARIOS, load_recording
from splunk_search import SplunkSearchError, splunk_results


def compile_predicate() -> str:
    backend = SplunkBackend(processing_pipeline=splunk_windows_pipeline())
    queries = backend.convert(SigmaCollection.from_yaml(Path(RULE_PATH).read_text(encoding="utf-8-sig")))
    if len(queries) != 1 or not isinstance(queries[0], str) or not queries[0].strip():
        raise ValueError("The test requires a single compiled PowerShell search predicate.")
    # Keep this replay scoped to one index. Pipelines, subsearches and macros need their own review.
    if re.search(r"[|\[\]`\r\n]", queries[0]):
        raise ValueError("This check only supports a compiled event filter.")
    return queries[0]


def aggregate(query: str) -> tuple[dict, list[str], int]:
    results = splunk_results(query)
    if len(results) != 1:
        raise SplunkSearchError("Splunk did not return exactly one stats result.")
    row = results[0]
    total = count_field(row, "total")
    raw_ids = row.get("ids", [])
    ids = [raw_ids] if isinstance(raw_ids, str) else raw_ids
    if not isinstance(ids, list) or not all(isinstance(item, str) and re.fullmatch(r"[0-9]+", item) for item in ids):
        raise SplunkSearchError("The search returned unreadable event record IDs.")
    return row, ids, total


def count_field(row: dict, name: str) -> int:
    value = str(row.get(name, ""))
    if not re.fullmatch(r"[0-9]+", value):
        raise SplunkSearchError(f"Splunk did not return a valid {name} count.")
    return int(value)


def check(batch: str, scenario: str, max_age_minutes: int) -> dict:
    if not re.fullmatch(r"driftguard[0-9a-f]{32}", batch) or scenario not in SCENARIOS or max_age_minutes < 1:
        raise ValueError("Use a generated batch ID, a supported scenario and a positive maximum age.")
    entry, events = load_recording()
    expected_source = Counter(str(e["EventRecordID"]) for e in events)
    expected_matches = Counter(str(rid) for rid in entry["expected_positive_record_ids"])
    predicate = compile_predicate()
    # Use raw marker terms so a broken field extraction doesn't make the events invisible here.
    scope = f'search index={INDEX} "{batch}" "{SCENARIOS[scenario]}"'
    health_query = (
        f"{scope} | stats count AS total list(EventRecordID) AS ids "
        'count(eval(EventID="1")) AS process_events '
        'count(eval(len(trim(Image))>0)) AS image_present '
        'count(eval(len(trim(CommandLine))>0)) AS command_present '
        f"count(eval(_indextime>=now()-{max_age_minutes * 60} AND _indextime<=now())) AS fresh"
    )
    health, source_ids, total = aggregate(health_query)
    _, matched_ids, matched_total = aggregate(f"{scope} | search {predicate} | stats count AS total list(EventRecordID) AS ids")
    observed_source = Counter(source_ids)
    observed_matches = Counter(matched_ids)
    report = {
        "index": INDEX,
        "batch": batch,
        "scenario": scenario,
        "max_age_minutes": max_age_minutes,
        "source_events": total,
        "missing_input_ids": sorted((expected_source - observed_source).elements()),
        "extra_input_ids": sorted((observed_source - expected_source).elements()),
        "expected_record_ids": sorted(expected_matches),
        "returned_record_ids": sorted(matched_ids),
        "missed_ids": sorted((expected_matches - observed_matches).elements()),
        "extra_ids": sorted((observed_matches - expected_matches).elements()),
    }
    if total == 0:
        report["status"] = "no_events_visible"
        return report
    found = {field: count_field(health, key) for field, key in (
        ("EventID=1", "process_events"), ("Image", "image_present"), ("CommandLine", "command_present")
    )}
    fresh = count_field(health, "fresh")
    report["field_counts"] = found
    report["freshly_indexed"] = fresh
    if any(n > total for n in [fresh, *found.values()]):
        raise SplunkSearchError("Splunk returned inconsistent field or freshness counts.")
    if total != sum(expected_source.values()) or observed_source != expected_source:
        report["status"] = "incomplete_or_duplicate_input"
    elif any(n != total for n in found.values()):
        report["status"] = "missing_required_fields"
    elif fresh != total:
        report["status"] = "stale_input"
    elif matched_total != len(matched_ids):
        raise SplunkSearchError("The detection search returned incomplete record IDs.")
    elif observed_matches != expected_matches:
        report["status"] = "rule_mismatch"
    else:
        report["status"] = "pass"
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch", required=True, help="ID printed by prepare_splunk_replay.py")
    parser.add_argument("--scenario", choices=SCENARIOS, default="healthy")
    parser.add_argument("--max-age-minutes", type=int, default=60, help="Maximum age since indexing. Default: 60.")
    args = parser.parse_args()
    try:
        report = check(args.batch, args.scenario, args.max_age_minutes)
    except (SplunkSearchError, OSError, ValueError, KeyError, SigmaError) as exc:
        print(json.dumps({"status": "unverified", "reason": str(exc)}))
        return 2
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
