"""Read recent Sysmon field counts from Splunk and report source health locally."""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from run_replay_suite import write_report
from splunk_search import SplunkSearchError, splunk_results


def source_name(value: str) -> str:
    # An exact index, source or sourcetype. No wildcards, quotes or SPL operators.
    if not re.fullmatch(r"[A-Za-z0-9_/][A-Za-z0-9_.:/-]{0,190}", value):
        raise argparse.ArgumentTypeError("use an exact Splunk name, such as XmlWinEventLog:Sysmon")
    return value


def health_search(index: str, sourcetype: str, source: str | None, host: str | None = None) -> str:
    selection = f'search index="{source_name(index)}" sourcetype="{source_name(sourcetype)}"'
    if source:
        selection += f' source="{source_name(source)}"'
    if host:
        selection += f' host="{source_name(host)}"'
    return selection + (
        ' | eval dg_code=coalesce(nullif(trim(tostring(EventID)),""),trim(tostring(EventCode)))'
        ' | eval dg_process=if(dg_code="1",1,0)'
        ' | stats count AS total count(eval(len(dg_code)>0 AND dg_code!="-")) AS identified'
        ' count(eval(dg_process=1)) AS processes'
        ' count(eval(dg_process=1 AND len(trim(Image))>0 AND trim(Image)!="-")) AS images'
        ' count(eval(dg_process=1 AND len(trim(CommandLine))>0 AND trim(CommandLine)!="-")) AS commands'
        ' max(_time) AS last_event max(eval(if(dg_process=1,_time,null()))) AS last_process'
    )


def timestamp(value: object, required: bool, end: int) -> int | None:
    if value in (None, "") and not required:
        return None
    seconds = float(value)
    if not 0 < seconds <= end:
        raise ValueError("Unexpected event time")
    return int(seconds)


def read_counts(rows: list[dict], end: int, window: int) -> dict:
    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise ValueError("Expected one summary")
    row = rows[0]
    names = ("total", "identified", "processes", "images", "commands")
    if not all(re.fullmatch(r"[0-9]+", str(row.get(key, ""))) for key in names):
        raise ValueError("Invalid counts")
    counts = {key: int(row[key]) for key in names}
    if not (counts["commands"] <= counts["processes"] <= counts["identified"] <= counts["total"]
            and counts["images"] <= counts["processes"]):
        raise ValueError("Inconsistent counts")
    for name, count in (("last_event", counts["total"]), ("last_process", counts["processes"])):
        epoch = timestamp(row.get(name), bool(count), end)
        if epoch is not None and (not count or epoch < end - 60 * window):
            raise ValueError("Event time does not match the search window")
        counts[name] = epoch
    if counts["processes"] and counts["last_process"] > counts["last_event"]:
        raise ValueError("Inconsistent event times")
    return counts


def verdict(counts: dict, end: int, max_age: int, minimum: int) -> tuple[str, list[str]]:
    if not counts["total"]:
        return "unhealthy", ["no_recent_source_events"]
    reasons = []
    if end - counts["last_event"] > max_age * 60:
        reasons.append("source_is_stale")
    if counts["identified"] < counts["total"]:
        reasons.append("missing_event_id")
    if counts["images"] < counts["processes"]:
        reasons.append("missing_image")
    if counts["commands"] < counts["processes"]:
        reasons.append("missing_command_line")
    if counts["processes"] and end - counts["last_process"] > max_age * 60:
        reasons.append("process_events_are_stale")
    if reasons:
        return "unhealthy", reasons
    if counts["processes"] < minimum:
        return "insufficient_data", ["too_few_process_events"]
    return "healthy", []


def utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", required=True, type=source_name)
    parser.add_argument("--sourcetype", required=True, type=source_name)
    parser.add_argument("--source", type=source_name, help="Exact Sysmon source for a shared sourcetype")
    parser.add_argument("--host", type=source_name, help="Exact Splunk host to check one endpoint separately")
    parser.add_argument("--window-minutes", type=int, default=60)
    parser.add_argument("--max-age-minutes", type=int, default=30)
    parser.add_argument("--min-process-events", type=int, default=5)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    if not 1 <= args.max_age_minutes <= args.window_minutes <= 10080 or args.min_process_events < 1:
        parser.error("choose 1 <= max-age-minutes <= window-minutes <= 10080 and a positive minimum count")

    end = int(datetime.now(timezone.utc).timestamp())
    start = end - 60 * args.window_minutes
    report = {"check": "sysmon_source_health", "start_utc": utc(start), "end_utc": utc(end),
              "max_age_minutes": args.max_age_minutes, "minimum_process_events": args.min_process_events}
    try:
        rows = splunk_results(health_search(args.index, args.sourcetype, args.source, args.host), str(start), str(end))
        counts = read_counts(rows, end, args.window_minutes)
        status, reasons = verdict(counts, end, args.max_age_minutes, args.min_process_events)
        report.update(source_events=counts["total"], events_with_id=counts["identified"],
                      process_events=counts["processes"], processes_with_image=counts["images"],
                      processes_with_command_line=counts["commands"],
                      newest_event_utc=utc(counts["last_event"]) if counts["last_event"] else None,
                      newest_process_utc=utc(counts["last_process"]) if counts["last_process"] else None)
    except SplunkSearchError:
        status, reasons = "unknown", ["search_unavailable"]
    except (TypeError, ValueError, OverflowError):
        status, reasons = "unknown", ["invalid_search_summary"]
    report.update(status=status, reasons=reasons)
    print(json.dumps(report, indent=2))
    if args.json_out:
        write_report(args.json_out, report)
    return {"healthy": 0, "unhealthy": 1, "insufficient_data": 2, "unknown": 2}[status]


if __name__ == "__main__":
    sys.exit(main())
