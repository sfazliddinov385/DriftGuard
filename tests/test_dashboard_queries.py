import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_dashboard_data as dashboard
from compile_queries import OUTPUT, compile_all, find_sigma_executable
from run_replay_suite import load_manifest, write_report


def test_every_published_search_is_the_compiler_output_for_its_rule(tmp_path, monkeypatch):
    queries = compile_all()
    for entry in load_manifest():
        path = entry["rule_path"]
        official = subprocess.check_output(
            [find_sigma_executable(), "convert", "-t", "splunk", "-p", "splunk_windows", path], text=True,
        )
        assert queries[path] == official.strip()
    docs = tmp_path / "docs"
    docs.mkdir()
    for name in ("index.html", "app.js", "styles.css", "windows-alert-demo.json"):
        shutil.copyfile(Path("docs") / name, docs / name)
    (docs / "private.txt").write_text("never publish")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CHECK_SPLUNK", "success")
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    write_report(OUTPUT, {"commit": "a" * 40, "queries": queries})
    dashboard.main()
    site = Path("reports/pages")
    assert json.loads((site / "status.json").read_text())["compiled_spl"] == queries
    assert (site / "data.json").read_bytes() == (docs / "status.json").read_bytes()
    assert not (site / "private.txt").exists()
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    with pytest.raises(ValueError, match="this commit"):
        dashboard.main()
    monkeypatch.setenv("CHECK_SPLUNK", "failure")
    dashboard.main()
    assert json.loads((site / "status.json").read_text())["compiled_spl"] == {}
