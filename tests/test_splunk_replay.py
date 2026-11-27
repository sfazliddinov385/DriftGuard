import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import check_splunk_replay as replay
import splunk_search
from prepare_splunk_replay import SCENARIOS, prepare
from run_replay_suite import evaluate_rule

IDS = ["5613964", "5597245", "5585441", "5575766"]
HITS = ["5613964", "5585441"]
BATCH = "driftguard" + "a" * 32


def test_preparer_keeps_labeled_events_and_strips_payloads(tmp_path, reference_powershell):
    first = prepare(tmp_path)
    second = prepare(tmp_path)
    assert first["path"] != second["path"]
    lines = [json.loads(line) for line in Path(first["path"]).read_text().splitlines()]
    normal = [row for row in lines if row["driftguard_case"] == SCENARIOS["healthy"]]
    changed = [row for row in lines if row["driftguard_case"] == SCENARIOS["renamed"]]
    assert sorted(e["EventRecordID"] for e in normal) == sorted(IDS)
    assert {e["driftguard_batch"] for e in lines} == {first["batch"]}
    assert all(len(e["CommandLine"]) < 180 and "User" not in e for e in normal)
    assert all("CommandLine" not in e for e in changed)
    assert [e["OriginalCommandText"] for e in changed] == [e["CommandLine"] for e in normal]
    assert evaluate_rule(reference_powershell, events=normal).status == "pass"
    assert evaluate_rule(reference_powershell, events=changed).recorded.hits == 0


def run_check(monkeypatch, *, health=None, hits=None, scenario="healthy"):
    base = {"total": "4", "ids": IDS, "process_events": "4", "image_present": "4", "command_present": "4", "fresh": "4"}
    hitlist = HITS if hits is None else hits
    responses = iter([[{**base, **(health or {})}], [{"total": str(len(hitlist)), "ids": hitlist}]])
    queries = []

    def search(query):
        queries.append(query)
        return next(responses)

    monkeypatch.setattr(replay, "splunk_results", search)
    result = replay.check(BATCH, scenario, 60)
    assert len(queries) == 2 and all(q.startswith("search index=driftguard_replay ") for q in queries)
    assert all(BATCH in q and SCENARIOS[scenario] in q for q in queries)
    assert "_indextime" in queries[0]
    assert f"| search {replay.compile_predicate()} |" in queries[1]
    return result


def test_returns_actual_match_ids(monkeypatch):
    row = run_check(monkeypatch)
    assert row["status"] == "pass" and row["returned_record_ids"] == sorted(HITS)


@pytest.mark.parametrize(("health", "hits", "expected"), [
    ({"total": "0", "ids": []}, [], "no_events_visible"),
    ({"command_present": "0"}, [], "missing_required_fields"),
    ({"fresh": "3"}, HITS, "stale_input"),
    ({"ids": [*IDS[:3], IDS[0]]}, HITS, "incomplete_or_duplicate_input"),
    ({}, [HITS[0], HITS[0]], "rule_mismatch"),
    ({}, [IDS[1], HITS[1]], "rule_mismatch"),
])
def test_explains_failure(monkeypatch, health, hits, expected):
    row = run_check(monkeypatch, health=health, hits=hits, scenario="renamed" if "command_present" in health else "healthy")
    assert row["status"] == expected
    if expected == "missing_required_fields":
        assert row["missed_ids"] == sorted(HITS) and row["field_counts"]["CommandLine"] == 0
    if expected == "incomplete_or_duplicate_input":
        assert row["missing_input_ids"] == [IDS[3]] and row["extra_input_ids"] == [IDS[0]]


def test_rest_checks_completed_results_and_tls(monkeypatch):
    class Response:
        status_code = 200
        text = '{"messages":[], "results":[{"total":"2"}]}'

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

    def post(url, **args):
        assert url == "https://localhost:8089/services/search/jobs"
        assert args["headers"]["Authorization"] == "Bearer mock-token"
        assert args["data"]["exec_mode"] == "oneshot" and args["data"]["earliest_time"] == "-15m"
        assert args["allow_redirects"] is False and args["verify"] is True
        return Response()

    monkeypatch.delenv("SPLUNK_URL", raising=False)
    monkeypatch.delenv("SPLUNK_CA_BUNDLE", raising=False)
    monkeypatch.delenv("SPLUNK_SESSION_KEY", raising=False)
    monkeypatch.setenv("SPLUNK_TOKEN", "mock-token")
    monkeypatch.setattr(splunk_search.requests, "post", post)
    assert splunk_search.splunk_results("search index=driftguard_replay | stats count AS total", "-15m") == [{"total": "2"}]
    for body in ['{"messages":[{"type":"WARN","text":"partial"}],"results":[]}', "not json", "", '{"preview":true,"result":{}}']:
        Response.text = body
        with pytest.raises(splunk_search.SplunkSearchError):
            splunk_search.splunk_results("search index=driftguard_replay | stats count", "-15m")
    Response.status_code = 403
    with pytest.raises(splunk_search.SplunkSearchError, match="HTTP 403"):
        splunk_search.splunk_results("search index=driftguard_replay | stats count", "-15m")


def test_unverified_errors_exit_two(monkeypatch, capsys):
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    monkeypatch.delenv("SPLUNK_SESSION_KEY", raising=False)
    monkeypatch.setattr(sys, "argv", ["check", "--batch", BATCH])
    assert replay.main() == 2
    assert json.loads(capsys.readouterr().out)["status"] == "unverified"
