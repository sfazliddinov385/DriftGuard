import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from attack_layer import build_layer
from review_splunk_drift import candidate
from splunk_canary import fields_from
from verify_gateway import evidence
import pytest


def test_navigator_groups_shared_techniques_conservatively():
    rows = [{"id": str(i), "technique": "T1059.001", "status": s} for i, s in enumerate(["pass", "fail"])]
    layer = build_layer({"rules": rows}, "")
    assert len(layer["techniques"]) == 1
    assert layer["techniques"][0]["color"] == "#df7777"
    assert not build_layer(None, "")["techniques"]


def test_config_does_not_accept_extra_spl():
    with pytest.raises(ValueError):
        fields_from({"command_line_fields": ["CommandLine", "x | search *"]})


def test_draft_requires_a_real_scheduled_positive_and_both_inputs():
    r = {"status":"drift", "scheduled":{"scheduled_job":"scheduler_old","batch_matches":[]},
         "record_ids":{"read-clock":"1","read-clock-encoded":"2"}, "command_lines_visible":0,
         "events_indexed":2, "repair":{"command_line_fields":["CommandLine","OriginalCommandText"]},
         "preview":{"scheduled_job":"scheduler_new","job_fired":True,"batch_matches":[["read-clock-encoded","2"]]}}
    assert json.loads(candidate(r)) == r["repair"]
    r["preview"]["batch_matches"][0][1] = "1"
    assert candidate(r) is None


def test_dlp_flag_is_distinct_from_block():
    class Reply:
        status_code = 200
        headers = {"cf-aig-dlp": json.dumps({"action":"FLAG","findings":[{"check":"REQUEST"}]})}
        def json(self):
            return {"choices":[]}
    assert evidence(Reply())["request_block"] is False


@pytest.mark.parametrize("status,body,header,expected", [
    (424, {"name": "AiGatewayError", "internalCode": 2030,
           "error": [{"code": 2030, "message": "Request content blocked due to DLP policy violations"}]},
     {}, True),
    (424, {"errors": [{"code": 2030, "message": "Request content blocked due to DLP policy violations"}]},
     {}, True),
    (424, {"error": {"code": 2030, "message": "Response content blocked due to DLP policy violations"}},
     {}, False),
    (424, {"errors": [{"code": 2030}]}, {}, False),
    (400, {"errors": [{"code": 2029}]}, {}, True),
    (400, {}, {"action": "BLOCK", "findings": [{"check": "REQUEST"}]}, True),
    (424, {"errors": [{"code": 2030, "message": "Request content blocked due to DLP policy violations"}]},
     {"action": "BLOCK", "findings": [{"check": "RESPONSE"}]}, False),
    (200, {"errors": [{"code": 2030, "message": "Request content blocked due to DLP policy violations"}]},
     {}, False),
])
def test_gateway_request_block_evidence(status, body, header, expected):
    class Reply:
        status_code = status
        headers = {"cf-aig-dlp": json.dumps(header)}

        def json(self):
            return body

    assert evidence(Reply())["request_block"] is expected
