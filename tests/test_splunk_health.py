import argparse
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_splunk_health as health


END = 1_700_000_000


def summary(**changes):
    data = dict(total="12", identified="12", processes="8", images="8", commands="8",
                last_event=str(END - 40), last_process=str(END - 55))
    data.update(changes)
    return data


@pytest.mark.parametrize(("row", "expected"), [
    (summary(), ("healthy", [])),
    (summary(commands="7"), ("unhealthy", ["missing_command_line"])),
    (summary(images="0", commands="0"), ("unhealthy", ["missing_image", "missing_command_line"])),
    (summary(identified="9"), ("unhealthy", ["missing_event_id"])),
    (summary(last_event=str(END - 2000), last_process=str(END - 2100)),
     ("unhealthy", ["source_is_stale", "process_events_are_stale"])),
    (summary(processes="2", images="2", commands="2"), ("insufficient_data", ["too_few_process_events"])),
    (summary(total="0", identified="0", processes="0", images="0", commands="0", last_event=None,
             last_process=None), ("unhealthy", ["no_recent_source_events"])),
])
def test_health_verdict(row, expected):
    assert health.verdict(health.read_counts([row], END, 60), END, 30, 5) == expected


@pytest.mark.parametrize("rows", [
    [], [{}], [summary(), summary()], [summary(identified="1")], [summary(commands="-1")],
    [summary(last_event=None)], [summary(last_event=END - 3700)], [summary(last_process=END + 1)],
])
def test_incomplete_or_inconsistent_rows_cannot_pass(rows):
    with pytest.raises((ValueError, TypeError)):
        health.read_counts(rows, END, 60)


def test_scope_and_output(tmp_path, monkeypatch, capsys):
    def search(query, earliest, latest):
        assert query.startswith('search index="lab" sourcetype="XmlWinEventLog" source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"')
        assert "_raw" not in query and " | stats " in query
        assert int(latest) - int(earliest) == 3600
        end = int(latest)
        return [summary(commands="7", last_event=end-10, last_process=end-10, extra="PRIVATE")]

    monkeypatch.setattr(health, "splunk_results", search)
    output = tmp_path / "health.json"
    assert health.main(["--index", "lab", "--sourcetype", "XmlWinEventLog", "--source",
                        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "--json-out", str(output)]) == 1
    text = output.read_text()
    assert json.loads(text)["processes_with_command_line"] == 7
    assert "PRIVATE" not in text and "PRIVATE" not in capsys.readouterr().out
    with pytest.raises(argparse.ArgumentTypeError):
        health.health_search("lab*", "x", None)
    assert ' host="lab-endpoint"' in health.health_search("lab", "sysmon", None, "lab-endpoint")
    assert ' source="/tmp/sysmon.json"' in health.health_search("lab", "sysmon", "/tmp/sysmon.json")


def test_failed_search_replaces_older_output(tmp_path, monkeypatch):
    def search(*args):
        raise health.SplunkSearchError("never print a raw service reply")

    monkeypatch.setattr(health, "splunk_results", search)
    output = tmp_path / "health.json"
    output.write_text('{"status": "healthy"}')
    assert health.main(["--index", "lab", "--sourcetype", "sysmon", "--json-out", str(output)]) == 2
    report = json.loads(output.read_text())
    assert report["status"] == "unknown"
    assert "source_events" not in report
    assert "raw service reply" not in output.read_text()
