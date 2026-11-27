"""Compile every tested rule with sigma-cli and retain its exact Splunk search."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

from run_replay_suite import check_manifest_coverage, load_manifest, write_report

OUTPUT = Path("reports/compiled-spl.json")


def find_sigma_executable() -> str:
    found = shutil.which("sigma")
    if found:
        return found
    sibling = Path(sys.executable).with_name("sigma.exe" if os.name == "nt" else "sigma")
    if sibling.is_file():
        return str(sibling)
    raise RuntimeError("sigma CLI executable not found in PATH or active virtualenv")


def compile_all():
    entries = load_manifest()
    check_manifest_coverage(entries, Path("rules"))
    executable = find_sigma_executable()
    queries = {}
    for entry in entries:
        path = entry["rule_path"]
        result = subprocess.run(
            [executable, "convert", "-t", "splunk", "-p", "splunk_windows", path],
            stdout=subprocess.PIPE, encoding="utf-8", check=True,
        )
        query = result.stdout.strip()
        if not query:
            raise ValueError(f"Sigma produced no Splunk search for {path}")
        queries[path] = query
        print(f"{path}\n{query}", flush=True)
    return queries


if __name__ == "__main__":
    OUTPUT.unlink(missing_ok=True)
    write_report(OUTPUT, {"commit": os.getenv("GITHUB_SHA"), "queries": compile_all()})
