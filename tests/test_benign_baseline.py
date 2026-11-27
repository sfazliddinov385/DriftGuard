import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from check_benign_baseline import measure_baseline


def test_legitimate_encoded_admin_case_is_reported_as_noise(reference_powershell):
    event = {"case_id": "maintenance-clock", "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
             "CommandLine": "powershell.exe -EncodedCommand RwBlAHQALQBEAGEAdABlAA=="}
    ordinary = {**event, "case_id": "ordinary-clock", "CommandLine": "powershell.exe Get-Date"}
    sample = {"source": "Unit test, not measured evidence", "events": [event, ordinary]}
    result = measure_baseline(sample, [reference_powershell])
    assert result["event_count"] == 2 and result["any_rule_matches"] == 1
    assert result["rules"][0]["matched_case_ids"] == ["maintenance-clock"]
    assert "CommandLine" not in result


def test_unusable_baseline_cannot_report_zero_alerts():
    with pytest.raises(ValueError, match="at least one observed event"):
        measure_baseline({"source": "Unit test", "events": []}, [])
    with pytest.raises(ValueError, match="Missing process data"):
        measure_baseline({"source": "Unit test", "events": [
            {"case_id": "empty-command", "Image": "program.exe", "CommandLine": ""}
        ]}, [])
