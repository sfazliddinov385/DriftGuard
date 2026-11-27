import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_replay_suite import ManifestError, check_manifest_coverage, evaluate_rule, load_manifest, main


def test_full_suite_requires_a_replay_entry_for_each_rule(tmp_path, monkeypatch):
    entry = load_manifest()[0]
    entry["log_path"] = str(Path(entry["log_path"]).resolve())
    source = Path(entry["rule_path"]).read_text()
    monkeypatch.chdir(tmp_path)
    rule = Path("rules/windows/powershell.yml")
    rule.parent.mkdir(parents=True)
    rule.write_text(source)
    extra_rule = rule.with_name("new-rule.yaml")
    extra_rule.write_text(source)
    entry["rule_path"] = rule.as_posix()
    manifest = Path("custom.yml")
    manifest.write_text(yaml.safe_dump({"rules": [entry]}))
    report = Path("results.json")
    args = ["replay", "--manifest", str(manifest), "--json-out", str(report)]
    monkeypatch.setattr(sys, "argv", args)

    assert main() == 1
    data = json.loads(report.read_text())
    assert data["status"] == "error" and data["rules"] == []
    assert extra_rule.as_posix() in data["error"]

    monkeypatch.setattr(sys, "argv", [*args, "--rule", str(rule)])
    assert main() == 0
    assert json.loads(report.read_text())["rules"][0]["status"] == "pass"


def test_manifest_cannot_count_a_missing_file_as_a_rule(tmp_path):
    with pytest.raises(ManifestError, match="absent from"):
        check_manifest_coverage([{"rule_path": str(tmp_path / "gone.yml")}], tmp_path)


@pytest.mark.parametrize("duplicate", ["id", "path"])
def test_manifest_requires_distinct_rule_ids_and_paths(tmp_path, duplicate):
    entry = load_manifest()[0]
    other = {**entry, "id": "another", "rule_path": "rules/windows/different.yml"}
    if duplicate == "id":
        other["id"] = entry["id"]
    else:
        other["rule_path"] = str(Path(entry["rule_path"]).resolve())
    manifest = tmp_path / "manifest.yml"
    manifest.write_text(yaml.safe_dump({"rules": [entry, other]}))
    with pytest.raises(ManifestError, match=f"Duplicate rule {duplicate}"):
        load_manifest(manifest)


@pytest.mark.parametrize("field", ["expected_positive_record_ids", "withheld_positive_events", "benign_events"])
def test_each_rule_needs_labeled_examples(tmp_path, field):
    entry = load_manifest()[0]
    entry[field] = []
    manifest = tmp_path / "manifest.yml"
    manifest.write_text(yaml.safe_dump({"rules": [entry]}))
    with pytest.raises(ManifestError, match=field):
        load_manifest(manifest)


def test_each_rule_gets_its_own_replay_result():
    entry = load_manifest()[0]
    rule = Path(entry["rule_path"]).read_text()
    bundled = rule + "\n---\n" + rule.replace("9b2c1a4e", "7b2c1a4e")
    result = evaluate_rule(entry, rule_yaml=bundled)
    assert result.status == "error"
    assert "one Sigma rule per file" in result.summary
