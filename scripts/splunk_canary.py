"""Install the reviewed lab alert and verify one fresh replay batch in the scheduler."""
import argparse
import json
import os
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

import requests

from check_splunk_alert_demo import ENCODED, clock_ids, completed_sids
from check_splunk_replay import INDEX, compile_predicate
from run_replay_suite import write_report

CONFIG = Path("config/splunk-command-fields.json")
REPORT = Path("reports/splunk-canary.json")
STANDARD = "CommandLine"
ALTERNATE = "OriginalCommandText"
SOURCE = "driftguard_managed_clock"
NAME = "DriftGuard_Managed_PowerShell_Canary"
MARKER = "DriftGuard managed clock canary / "
SCOPE = f'index={INDEX} source="{SOURCE}" | fields _raw | spath'


def fields_from(config):
    fields = config.get("command_line_fields")
    if set(config) != {"command_line_fields"} or fields not in ([STANDARD], [STANDARD, ALTERNATE]):
        raise ValueError("Unsupported managed field mapping.")
    return fields


def expression(fields):
    fields_from({"command_line_fields": fields})
    alias = "" if len(fields) == 1 else f" | eval CommandLine=coalesce({','.join(fields)})"
    return SCOPE + alias + " | search " + compile_predicate() + " | table batch case_id EventRecordID"


class Splunk:
    def __init__(self):
        self.url = os.environ.get("SPLUNK_URL", "https://localhost:8089").rstrip("/")
        parts = urlsplit(self.url)
        if (parts.scheme != "https" or parts.hostname not in {"localhost", "127.0.0.1", "::1"}
                or parts.path or parts.username or parts.password or parts.query or parts.fragment):
            raise ValueError("Run this lab deployment on the Splunk machine using its HTTPS loopback URL.")
        self.client = requests.Session()
        self.client.trust_env = False
        self.client.verify = os.getenv("SPLUNK_CA_BUNDLE") or True
        if os.getenv("SPLUNK_TOKEN"):
            self.client.headers["Authorization"] = "Bearer " + os.environ["SPLUNK_TOKEN"]
        else:
            self.client.auth = (os.environ["SPLUNK_USERNAME"], os.environ["SPLUNK_PASSWORD"])
        context = self.request("GET", "/services/authentication/current-context")
        owner = context["entry"][0]["content"]["username"]
        self.namespace = "/servicesNS/" + quote(owner, safe="") + "/search"

    def request(self, method, path, data=None, *, params=None, missing=False, raw=False):
        reply = self.client.request(method, self.url + path, params={"output_mode": "json", **(params or {})},
                                    data=data, timeout=(5, 75), allow_redirects=False)
        if missing and reply.status_code == 404:
            return {}
        if not 200 <= reply.status_code < 300:
            raise RuntimeError(f"Splunk {method} {path}: HTTP {reply.status_code}")
        return {} if raw else reply.json()

    def search(self, search):
        return self.request("POST", "/services/search/jobs", data={
            "search": "search " + search, "exec_mode": "oneshot",
            "earliest_time": "-30m", "latest_time": "now", "count": 1000})["results"]

    def deploy(self, name, query, sha):
        path = self.namespace + "/saved/searches"
        description = MARKER + sha
        spec = {"description": description, "search": query, "is_scheduled": "1", "disabled": "0",
                "cron_schedule": "* * * * *", "dispatch.earliest_time": "-10m", "dispatch.latest_time": "now",
                "dispatch.ttl": "600", "alert_type": "number of events", "alert_comparator": "greater than",
                "alert_threshold": "0", "alert.track": "true", "actions": "logevent",
                "action.logevent.param.index": INDEX, "action.logevent.param.sourcetype": "driftguard:triggered",
                "action.logevent.param.event": "DriftGuard canary $name$ fired for job $job.sid$"}
        previous = self.request("GET", path + "/" + name, missing=True)
        if not previous.get("entry"):
            self.request("POST", path, data=dict(spec, name=name))
        else:
            existing = previous["entry"][0]["content"]
            if not existing["description"].startswith(MARKER):
                raise RuntimeError("Saved search name already belongs to another administrator.")
            self.request("POST", path + "/" + name, data=spec)
        saved = self.request("GET", path + "/" + name)["entry"][0]["content"]
        if saved["search"] != query or saved["description"] != description or not saved["is_scheduled"]:
            raise RuntimeError("Splunk did not confirm the scheduled search configuration.")

    def inject(self, capture, batch, field):
        for r in capture["events"]:
            # New replay timestamps keep original record IDs and isolate this batch from historical jobs.
            event = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "batch": batch,
                     "EventRecordID": str(r["EventRecordID"]), "case_id": r["case_id"],
                     "EventID": 4688, "Image": r["Image"], field: r["CommandLine"]}
            self.request("POST", "/services/receivers/simple", data=json.dumps(event).encode(),
                         params={"index": INDEX, "source": SOURCE, "sourcetype": "driftguard:canary"}, raw=True)

    def scheduled(self, name, ready, batch, expected):
        awaiting_tracking = {}
        check = self.namespace + "/saved/searches/" + name + "/history"
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            done = completed_sids(self.request("GET", check)["entry"])
            alerts = self.request("GET", self.namespace + "/alerts/fired_alerts/" + name, missing=True)
            fired = {e["content"]["sid"] for e in alerts.get("entry", [])}
            for sid in done:
                stamp = re.search(r"_at_(\d+)_[^/]+$", sid)
                if not stamp or int(stamp[1]) <= ready:
                    continue
                rows = self.request("GET", "/services/search/v2/jobs/" + quote(sid, safe="") + "/results",
                                    params={"count": 0})["results"]
                matches = [(str(r.get("case_id")), str(r.get("EventRecordID"))) for r in rows if r.get("batch") == batch]
                if matches == expected and expected and sid not in fired:
                    first_seen = awaiting_tracking.setdefault(sid, time.monotonic())
                    if time.monotonic() - first_seen < 30:
                        continue
                return {"scheduled_job": sid, "batch_matches": matches, "job_fired": sid in fired}
            time.sleep(4)
        raise RuntimeError("No verified, completed scheduled alert within five minutes.")


def check(service, capture, wire, sha):
    ids = clock_ids(capture)
    expected = [(ENCODED, ids[ENCODED])]
    fields = fields_from(json.loads(CONFIG.read_text()))
    query = expression(fields)
    service.deploy(NAME, query, sha)
    batch = uuid.uuid4().hex
    service.inject(capture, batch, wire)
    cohort = f' | search batch="{batch}"'
    until = time.monotonic() + 90
    while True:
        rows = service.search(SCOPE + cohort + " | table case_id EventRecordID Image CommandLine OriginalCommandText")
        if len(rows) == 2 and {r["case_id"]: str(r["EventRecordID"]) for r in rows} == ids:
            break
        if time.monotonic() > until:
            raise RuntimeError("Could not verify both source records. Check indexing and extraction.")
        time.sleep(3)
    def matched(q):
        return [(r.get("case_id"), str(r.get("EventRecordID"))) for r in service.search(q + cohort)]
    direct = matched(query)
    if direct not in ([], expected):
        raise RuntimeError("Unexpected or benign event matched. Inspect the detection.")
    ready = int(time.time())
    actual = service.scheduled(NAME, ready, batch, direct)
    passed = actual["batch_matches"] == expected and actual["job_fired"]
    report = {"status": "pass" if passed else "drift", "sha": sha, "batch": batch, "events_indexed": len(rows),
              "record_ids": ids, "command_lines_visible": sum(bool(r.get(STANDARD)) for r in rows),
              "scheduled": actual, "repair": None}
    if (not direct and not actual["batch_matches"] and fields == [STANDARD] and all(not r.get(STANDARD) and r.get(ALTERNATE) for r in rows)
            and matched(expression([STANDARD, ALTERNATE])) == expected):
        # Preview executes in a distinct saved search. The deployed alert stays on the reviewed configuration.
        candidate = [STANDARD, ALTERNATE]
        service.deploy(NAME + "_Preview", expression(candidate), sha)
        report["preview"] = service.scheduled(NAME + "_Preview", int(time.time()), batch, expected)
        if report["preview"]["batch_matches"] == expected and report["preview"]["job_fired"]:
            report["repair"] = {"command_line_fields": candidate}
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture", type=Path, default=Path("tests/baselines/clock-pair.json"))
    parser.add_argument("--source-field", choices=(STANDARD, ALTERNATE), default=STANDARD)
    args = parser.parse_args()
    REPORT.unlink(missing_ok=True)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    capture = json.loads(args.capture.read_text(encoding="utf-8-sig"))
    service = Splunk()
    try:
        result = check(service, capture, args.source_field, sha)
    finally:
        service.client.close()
    write_report(REPORT, result)
    print(json.dumps(result))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
