"""Prove that Splunk's scheduler fired on a fresh, harmless Windows clock check."""

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests

from check_splunk_replay import INDEX, compile_predicate
from run_replay_suite import write_report
from splunk_search import splunk_results

MAPPINGS = ("original", "renamed", "restored")
ENCODED = "read-clock-encoded"
BASE = "https://127.0.0.1:18089"
APP = "/servicesNS/admin/search"


def clock_ids(capture: dict) -> dict[str, str]:
    events = capture["events"]
    records = {row["case_id"]: str(row["EventRecordID"]) for row in events}
    if (len(events) != 2 or set(records) != {"read-clock", ENCODED}
            or len(set(records.values())) != 2
            or not all(rid.isdecimal() for rid in records.values())
            or not all(row["EventID"] == 4688 for row in events)):
        raise ValueError("Expected two distinct Windows Security 4688 clock records.")
    return records


def visible_fields(scope: str, records: dict[str, str]) -> int:
    # Do this as the search-only account. A silent alert alone cannot explain why it missed.
    query = (scope + " | table case_id EventRecordID Image CommandLine")
    deadline = time.monotonic() + 120
    while True:
        rows = splunk_results(query)
        seen = {row.get("case_id"): str(row.get("EventRecordID")) for row in rows}
        if len(rows) == len(records) and seen == records and all(row.get("Image") for row in rows):
            return sum(bool(str(row.get("CommandLine") or "").strip()) for row in rows)
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Could not verify both input IDs for {scope}. Visible IDs: {seen}")
        time.sleep(4)


def api(client, method, path, *, empty_on_404=False, **kwargs):
    # This demo administers only the throwaway loopback instance created by the CI script.
    params = {"output_mode": "json"}
    if method == "GET":
        params["count"] = 100
    response = client.request(method, BASE + path, params=params,
                              timeout=(5, 30), allow_redirects=False, **kwargs)
    if empty_on_404 and response.status_code == 404:
        return {"entry": []}
    if not response.ok:
        raise RuntimeError(f"Splunk {method} {path} returned {response.status_code}: {response.text[:500]}")
    return response.json()


def completed_sids(entries) -> list[str]:
    sids = []
    for entry in entries:
        job = entry["content"]
        sid = str(job.get("sid") or entry["name"])
        if sid.startswith("scheduler_") and str(job.get("isDone")).lower() in {"1", "true"}:
            if any(str(job.get(flag, "0")).lower() in {"1", "true"}
                   for flag in ("isFailed", "isZombie", "isFinalized")):
                raise RuntimeError(f"Scheduled search failed: {sid}")
            sids.append(sid)
    return sids


def verify(capture, client) -> dict:
    records = clock_ids(capture)
    predicate = compile_predicate()
    names = {m: "DriftGuard_Clock_" + m for m in MAPPINGS}
    counts = {}
    for mapping, name in names.items():
        scope = f'search index={INDEX} source="driftguard_clock_{mapping}" EventID=4688'
        counts[mapping] = visible_fields(scope, records)
        expected = 0 if mapping == "renamed" else 2
        if counts[mapping] != expected:
            raise RuntimeError(f"{mapping}: expected {expected} command lines, found {counts[mapping]}")
        search = scope + " | search " + predicate + " | table case_id EventRecordID"
        expected_cases = [] if mapping == "renamed" else [(ENCODED, records[ENCODED])]
        actual_cases = [(r["case_id"], str(r["EventRecordID"])) for r in splunk_results(search, "-30m")]
        print(f"{mapping}: field count {counts[mapping]}, direct Splunk matches {actual_cases}", flush=True)
        if actual_cases != expected_cases:
            raise RuntimeError(f"{mapping}: compiled search returned {actual_cases}, expected {expected_cases}")
        # The export endpoint requires the generating "search" command. A saved
        # search uses the same expression format as the Splunk Web search bar.
        api(client, "POST", APP + "/saved/searches", data={
            "name": name, "search": search.removeprefix("search "),
            "is_scheduled": 1, "cron_schedule": "* * * * *", "dispatch.earliest_time": "-30m",
            "dispatch.latest_time": "now", "dispatch.ttl": "600", "alert_type": "number of events",
            "alert_comparator": "greater than", "alert_threshold": 0, "alert.track": "true",
            "actions": "logevent", "action.logevent.param.index": INDEX,
            "action.logevent.param.event": "DriftGuard clock alert $name$ job $job.sid$",
            "action.logevent.param.sourcetype": "driftguard:triggered",
        })
        saved = api(client, "GET", APP + f"/saved/searches/{name}")["entry"][0]["content"]
        settings = {k: saved.get(k) for k in ("is_scheduled", "alert_type", "alert.track", "actions")}
        print(f"{name}: {settings}", flush=True)
    print("The two Windows events are visible in each field mapping. Waiting for Splunk's scheduler.", flush=True)

    measured = {}
    deadline = time.monotonic() + 300
    last_state = {}
    verified_jobs = {}
    while time.monotonic() < deadline:
        for mapping, name in names.items():
            if mapping in measured:
                continue
            alerts = api(client, "GET", APP + f"/alerts/fired_alerts/{name}", empty_on_404=True)["entry"]
            fired = {e["content"]["sid"] for e in alerts if e["content"].get("savedsearch_name") == name}
            history = api(client, "GET", APP + f"/saved/searches/{name}/history")["entry"]
            done = completed_sids(history)
            summary = {"scheduled_jobs_done": len(done), "tracked_alerts": len(fired),
                       "latest_result_count": history[0]["content"].get("resultCount") if history else None}
            if summary != last_state.get(mapping):
                print(f"{mapping}: {summary}", flush=True)
                last_state[mapping] = summary
            if mapping == "renamed" and fired:
                raise RuntimeError("Splunk fired an unexpected alert for the renamed field.")
            if not done:
                continue
            sid = next((s for s in done if s in fired), done[0])
            if sid not in verified_jobs:
                job_path = "/services/search/v2/jobs/" + quote(sid, safe="")
                rows = api(client, "GET", job_path + "/results")["results"]
                cases = [(r.get("case_id"), str(r.get("EventRecordID"))) for r in rows]
                print(f"{mapping}: scheduled results {cases}, job {sid}", flush=True)
                if cases != ([] if mapping == "renamed" else [(ENCODED, records[ENCODED])]):
                    job = api(client, "GET", "/services/search/jobs/" + quote(sid, safe=""))["entry"][0]["content"]
                    detail = {k: job.get(k) for k in ("eventSearch", "earliestTime", "latestTime", "resultCount")}
                    raise RuntimeError(f"Unexpected scheduled results for {mapping}: {cases}. Job: {detail}")
                verified_jobs[sid] = cases
            cases = verified_jobs[sid]
            if mapping != "renamed" and sid not in fired:
                continue
            measured[mapping] = {"events_indexed": 2, "command_lines_visible": counts[mapping],
                                 "field_check": "missing_command_line" if counts[mapping] == 0 else "present",
                                 "scheduled_job": sid, "tracked_alert": sid in fired,
                                 "matched_record_ids": [rid for _, rid in cases]}
            print(mapping, json.dumps(measured[mapping]), flush=True)
        if len(measured) == len(MAPPINGS):
            return {"verified_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "github_run_id": os.environ.get("GITHUB_RUN_ID"), "commit": os.environ.get("GITHUB_SHA"),
                    "windows_event_id": 4688, "captured_record_ids": records, "outcomes": measured}
        time.sleep(5)
    raise RuntimeError(f"Could not verify a completed scheduled job and its alert status: {last_state}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    with requests.Session() as client:
        client.trust_env = False
        client.auth = ("admin", os.environ["SPLUNK_PASSWORD"])
        client.verify = os.environ["SPLUNK_CA_BUNDLE"]
        report = verify(json.loads(args.capture.read_text(encoding="utf-8-sig")), client)
    write_report(args.report, report)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as out:
            out.write("### Scheduled PowerShell alert on fresh Windows events\n\n")
            out.write("| Field mapping | Events indexed | Command lines visible | Scheduled alert | Matched Windows record ID |\n")
            out.write("| --- | ---: | ---: | --- | --- |\n")
            for mapping in MAPPINGS:
                row = report["outcomes"][mapping]
                out.write(f"| {mapping} | {row['events_indexed']} | {row['command_lines_visible']} | "
                          f"{'Fired' if row['tracked_alert'] else 'Silent'} | "
                          f"{', '.join(row['matched_record_ids']) or 'None'} |\n")
            out.write("\nBoth Windows tasks read the clock. Only one used an encoded command. "
                      "Splunk completed a scheduled search in every row.\n\n")


if __name__ == "__main__":
    main()
