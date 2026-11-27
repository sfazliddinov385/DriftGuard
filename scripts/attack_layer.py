"""Export the measured repository replay results to ATT&CK Navigator v4.5."""
import json
import re
from pathlib import Path

COLORS = {"pass": "#67b68a", "fail": "#df7777", "unknown": "#c5cbd1"}


def build_layer(report, run_url):
    groups = {}
    for row in (report or {}).get("rules", []):
        technique = row.get("technique") or ""
        if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
            groups.setdefault(technique, []).append(row)
    techniques = []
    for tid, rows in sorted(groups.items()):
        states = [r.get("status") for r in rows]
        status = "fail" if "fail" in states else "pass" if all(s == "pass" for s in states) else "unknown"
        techniques.append({"techniqueID": tid, "color": COLORS[status], "showSubtechniques": True,
                           "comment": "\n".join(f"{r['id']}: {r.get('summary') or r.get('status')}" for r in rows),
                           "links": [{"label": "Replay run", "url": run_url}] if run_url else []})
    return {"name": "DriftGuard · recorded Windows replay", "domain": "enterprise-attack",
            "description": "Colors describe the rules and examples measured in this GitHub run. Blank techniques are untested.",
            "versions": {"navigator": "4.9.1", "layer": "4.5"}, "techniques": techniques,
            "layout": {"showAggregateScores": False, "expandedSubtechniques": "all"},
            "legendItems": [{"label": k, "color": c} for k, c in COLORS.items()]}


def write_layer(report, run_url):
    Path("dashboard/attack-layer.json").write_text(json.dumps(build_layer(report, run_url), indent=2) + "\n")
