"""Open one human-reviewed change for a field mapping verified by Splunk's scheduler."""
import base64
import json
import os
import subprocess
from pathlib import Path

from splunk_canary import ALTERNATE, CONFIG, REPORT, STANDARD

REPO = "sfazliddinov385/DriftGuard"
BASE = f"repos/{REPO}"
BRANCH = "driftguard/repair-clock-command-field"


def gh(method, endpoint, payload=None):
    args = ["gh", "api", "--method", method, f"{BASE}/{endpoint}"]
    if payload is not None:
        args += ["--input", "-"]
    res = subprocess.run(args, input=json.dumps(payload) if payload is not None else None,
                         text=True, capture_output=True, check=True)
    return json.loads(res.stdout) if res.stdout else None


def candidate(report):
    ids = report["record_ids"]
    preview = report.get("preview", {})
    if (report.get("status") != "drift" or report.get("events_indexed") != 2 or len(set(ids.values())) != 2
            or report.get("command_lines_visible") != 0 or report["scheduled"]["batch_matches"]
            or not report["scheduled"]["scheduled_job"].startswith("scheduler_")
            or not preview.get("scheduled_job", "").startswith("scheduler_") or preview.get("job_fired") is not True
            or preview.get("batch_matches") != [["read-clock-encoded", ids["read-clock-encoded"]]]
            or report.get("repair") != {"command_line_fields": [STANDARD, ALTERNATE]}):
        return None
    return json.dumps(report["repair"], indent=2) + "\n"


def local_git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def cloudflare_note(report):
    if not os.getenv("CLOUDFLARE_API_TOKEN"):
        return ""
    # Only synthetic counts leave the runner. All edits come from Splunk's verified candidate.
    from ai_healer import build_client
    from pydantic import BaseModel, Field
    class Diagnosis(BaseModel):
        summary: str = Field(min_length=1, max_length=400)
    try:
        client, model = build_client()
        reply = client.with_options(max_retries=0, timeout=30).chat.completions.create(
            model=model, max_tokens=256, response_format={"type": "json_object"},
            extra_headers={"cf-aig-skip-cache": "true"},
            messages=[{"role": "system", "content": "Return JSON with one summary sentence for a SOC analyst."},
                      {"role": "user", "content": json.dumps({
                          "events_indexed": report["events_indexed"], "legacy_fields_visible": 0,
                          "scheduled_matches": 0, "preview_behavior": "Using OriginalCommandText restored the one expected alert."
                      })}])
        note = Diagnosis.model_validate_json(reply.choices[0].message.content).summary
        # Avoid generated links, markup or mentions inside a GitHub review.
        import re
        if not re.fullmatch(r"[A-Za-z0-9 .,()'_-]{1,400}", note):
            return ""
        return "\n\nCloudflare's explanation: " + note
    except Exception:
        print("Cloudflare explanation unavailable. The verified Splunk evidence remains attached.")
        return ""


def main():
    report = json.loads(REPORT.read_text())
    if report["status"] == "pass":
        return
    content = candidate(report)
    if content is None:
        raise SystemExit("Splunk missed the canary. No field repair passed verification. Review the job.")
    if report["sha"] != local_git("rev-parse", "HEAD"):
        raise SystemExit("The evidence belongs to another checkout.")
    run = os.getenv("GITHUB_RUN_ID", "")
    evidence = f"https://github.com/{REPO}/actions/runs/{run}" if run.isdecimal() else "Local Windows lab"
    remote_sha = gh("GET", "git/ref/heads/main")["object"]["sha"]
    rule = "rules/windows/proc_creation_encoded_powershell.yml"
    for path in (CONFIG.as_posix(), rule):
        remote = gh("GET", f"contents/{path}?ref={remote_sha}")
        if remote["sha"] != local_git("rev-parse", "HEAD:" + path):
            raise SystemExit("The measured rule or mapping changed on main. Retest before opening a repair.")
    open_prs = gh("GET", f"pulls?state=open&base=main&head=sfazliddinov385:{BRANCH}")
    if open_prs:
        print("Existing review:", open_prs[0]["html_url"])
        return
    branches = gh("GET", "git/matching-refs/heads/" + BRANCH)
    if not any(b["ref"] == "refs/heads/" + BRANCH for b in branches):
        gh("POST", "git/refs", {"ref": "refs/heads/" + BRANCH, "sha": remote_sha})
    file = gh("GET", f"contents/{CONFIG.as_posix()}?ref={BRANCH}")
    previous = base64.b64decode(file["content"]).decode()
    if previous != content:
        if file["sha"] != local_git("rev-parse", "HEAD:" + CONFIG.as_posix()):
            raise SystemExit("The existing repair branch has another proposed mapping. Review it first.")
        gh("PUT", "contents/" + CONFIG.as_posix(), {"branch": BRANCH, "sha": file["sha"],
           "message": "fix: restore the command-line field for the managed Splunk alert",
           "content": base64.b64encode(content.encode()).decode()})
    comparison = gh("GET", f"compare/main...{BRANCH}")
    if [f["filename"] for f in comparison.get("files", [])] != [CONFIG.as_posix()]:
        raise SystemExit("Expected a mapping-only diff before opening the review.")
    body = ("Two Windows replay events reached the dedicated test index. The managed alert missed the encoded clock "
            "check because neither row exposed CommandLine. A separate scheduled preview read OriginalCommandText "
            "as a fallback and fired on the encoded event only.\n\n"
            f"Evidence: {evidence}\n\nMerging updates the managed test alert and starts another Splunk check. "
            "The original failed run stays red.") + cloudflare_note(report)
    result = gh("POST", "pulls", {"title": "Restore the field used by the Splunk PowerShell alert",
                                  "body": body, "head": BRANCH, "base": "main", "draft": True})
    print("Draft repair:", result["html_url"])


if __name__ == "__main__":
    main()
