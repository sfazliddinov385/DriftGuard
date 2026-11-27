import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_replay_suite import load_manifest, main


def test_report_follows_real_replay_and_replaces_stale_results(tmp_path, monkeypatch):
    entry = load_manifest()[0]
    rule = tmp_path / "rule.yml"
    source_rule = Path(entry["rule_path"]).read_text()
    rule.write_text(source_rule)
    entry["rule_path"] = str(rule)
    manifest = tmp_path / "manifest.yml"
    manifest.write_text(yaml.safe_dump({"rules": [entry]}))
    output = tmp_path / "reports" / "report.json"
    monkeypatch.setenv("GITHUB_RUN_ID", "12345")
    monkeypatch.setattr(sys, "argv", ["replay", "--manifest", str(manifest), "--json-out", str(output)])

    assert main() == 0
    report = json.loads(output.read_text())
    assert report["status"] == "pass" and report["run_id"] == "12345"
    row = report["rules"][0]
    labels = sorted(entry["expected_positive_record_ids"])
    assert row["recorded"] == {
        "hits": 2, "total": 4, "expected": 2, "matched_ids": labels,
        "missed_ids": [], "unexpected_ids": [],
    }
    assert row["technique"] == "T1059.001"
    assert row["withheld"] == {"hits": 2, "total": 2}
    assert row["benign"] == {"hits": 0, "total": 4}

    # The broader condition matches both expected records and an unintended third.
    rule.write_text(source_rule.replace("selection_img and selection_flags", "selection_img"))
    assert main() == 1
    report = json.loads(output.read_text())
    assert report["status"] == "fail"
    row = report["rules"][0]
    assert row["status"] == "fail"
    assert row["recorded"]["hits"] == 3
    assert len(row["recorded"]["unexpected_ids"]) == 1
    assert row["recorded"]["missed_ids"] == []
    assert row["benign"]["hits"] == 2

    # A corrupt fixture is unknown evidence. Parser errors must not leak its contents.
    broken = tmp_path / "broken.log"
    broken.write_text('{"PRIVATE_FIXTURE_TEXT"}')
    entry["log_path"] = str(broken)
    manifest.write_text(yaml.safe_dump({"rules": [entry]}))
    assert main() == 1
    raw = output.read_text()
    assert "PRIVATE_FIXTURE_TEXT" not in raw
    report = json.loads(raw)
    assert report["status"] == "error"
    row = report["rules"][0]
    assert row["status"] == "error"
    assert row["recorded"]["hits"] is None
    assert row["withheld"]["hits"] is None
    assert row["benign"]["hits"] is None
    assert row["summary"]

    manifest.write_text("rules: []")
    assert main() == 1
    report = json.loads(output.read_text())
    assert report["status"] == "error" and report["rules"] == []
