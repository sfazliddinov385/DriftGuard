import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Literal

import yaml
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, ValidationError

# Reuse the exact Sysmon XML parser and evaluator from replay_rule_01.py
sys.path.insert(0, str(Path(__file__).resolve().parent))
from replay_rule_01 import BENIGN_EVENTS, LOG_PATH, RULE_PATH, evaluate_rule, parse_sysmon_events

ALLOWLIST_PATH = Path("schemas/sysmon_field_allowlist.json")
SUMMARY_PATH = Path("reports/drift_fix_summary.md")
DEFAULT_MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
MAX_RETRIES = 3


class DriftFix(BaseModel):
    root_cause_summary: str
    drift_category: Literal[
        "field_name_change",
        "value_format_shift",
        "overly_strict_filter",
        "telemetry_missing",
    ]
    updated_sigma_yaml: str
    triage_notes: str
    confidence_level: Literal["low", "medium", "high"]


def redact_text(text: str) -> str:
    """Local defense-in-depth redaction before sending sandbox telemetry to Cloudflare."""
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[REDACTED_IP]", text)
    text = re.sub(r"(?i)([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})", "[REDACTED_EMAIL]", text)
    text = re.sub(r"(?i)(User=)([^,\s\"']+)", r"\1[REDACTED_USER]", text)
    text = re.sub(r"\{[0-9A-Fa-f-]{36}\}", "{REDACTED_GUID}", text)
    return text


def summarize_events_for_prompt(events: list[dict], allowed_fields: set[str]) -> list[dict]:
    """Keep only allowlisted fields and redact sensitive tokens to stay lean on Neurons."""
    compact = []
    for ev in events[:10]:
        entry = {}
        for k, v in ev.items():
            if k in allowed_fields and v:
                entry[k] = re.sub(r"[ \t]{2,}", " ", redact_text(str(v)))[:600]
        if entry:
            compact.append(entry)
    return compact


def find_sigma_executable() -> str:
    found = shutil.which("sigma")
    if found:
        return found
    sibling = Path(sys.executable).parent / ("sigma.exe" if os.name == "nt" else "sigma")
    if sibling.exists():
        return str(sibling)
    raise RuntimeError("sigma CLI executable not found in PATH or active virtualenv")


def verify_candidate_rule(
    candidate_yaml: str,
    allowed_fields: set[str],
    attack_events: list[dict],
) -> tuple[bool, str]:
    """Strict automated referee: YAML parse -> allowlist check -> sigma check -> log replay."""
    try:
        parsed = yaml.safe_load(candidate_yaml)
    except yaml.YAMLError as exc:
        return False, f"Invalid YAML syntax: {exc}"

    if not isinstance(parsed, dict) or "detection" not in parsed:
        return False, "Missing required top-level 'detection' block in Sigma YAML."

    # 1. Verify every detection field is in the schema allowlist
    for sel_name, sel_val in parsed["detection"].items():
        if sel_name == "condition":
            continue
        if isinstance(sel_val, dict):
            for key in sel_val.keys():
                field_name = key.split("|")[0]
                if field_name not in allowed_fields:
                    return False, (
                        f"Field '{field_name}' is not in the SIEM allowlist: {sorted(allowed_fields)}"
                    )

    # 2. Validate official Sigma schema via sigma check
    sigma_bin = find_sigma_executable()
    with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False, encoding="utf-8") as tmp:
        tmp.write(candidate_yaml)
        tmp_path = Path(tmp.name)

    try:
        proc = subprocess.run(
            [sigma_bin, "check", "--fail-on-issues", str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return False, f"sigma check failed:\n{proc.stdout}\n{proc.stderr}"
    finally:
        tmp_path.unlink(missing_ok=True)

    # 3. Deterministic replay against attack + benign logs
    attack_matches = [ev for ev in attack_events if evaluate_rule(ev, parsed)]
    benign_matches = [ev for ev in BENIGN_EVENTS if evaluate_rule(ev, parsed)]

    if len(attack_matches) == 0:
        return False, "Candidate rule matched 0 attack events (still missing the attack)."
    if len(benign_matches) > 0:
        return False, (
            f"Candidate rule triggered {len(benign_matches)} false positive(s) on benign baseline logs."
        )

    return True, f"Verified: {len(attack_matches)}/{len(attack_events)} attack matches, 0 benign matches."


def build_client() -> tuple[OpenAI, str]:
    load_dotenv()
    account_id = os.environ["CLOUDFLARE_ACCOUNT_ID"].strip()
    gateway_id = os.environ["CLOUDFLARE_GATEWAY_ID"].strip()
    api_token = os.environ["CLOUDFLARE_API_TOKEN"].strip()
    model = os.getenv("DRIFTGUARD_AI_MODEL", DEFAULT_MODEL).strip()

    client = OpenAI(
        api_key=api_token,
        base_url=f"https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_id}/workers-ai/v1",
    )
    return client, model


def call_workers_ai(client: OpenAI, model: str, messages: list[dict]) -> DriftFix:
    schema = DriftFix.model_json_schema()
    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.1,
            messages=messages,
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "drift_fix", "schema": schema},
            },
        )
    except Exception:
        # Fallback to json_object mode if a specific model rejects json_schema wrapper
        resp = client.chat.completions.create(
            model=model,
            temperature=0.1,
            messages=messages,
            response_format={"type": "json_object"},
        )

    raw_content = (resp.choices[0].message.content or "").strip()
    # Strip markdown code fences if a model wraps JSON in ```json ... ```
    if raw_content.startswith("```"):
        raw_content = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_content, flags=re.DOTALL)
    return DriftFix.model_validate_json(raw_content)


def main() -> int:
    allowed_fields = set(json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))["allowed_fields"])
    broken_rule_text = RULE_PATH.read_text(encoding="utf-8-sig")
    attack_events = parse_sysmon_events(LOG_PATH)
    compact_logs = summarize_events_for_prompt(attack_events, allowed_fields)

    system_prompt = (
        "You are DriftGuard, a senior Blue Team Detection Engineer. "
        "A Sigma detection rule failed automated log replay validation. "
        "Analyze the broken Sigma YAML alongside the redacted attack telemetry and benign baseline logs. "
        "Return ONLY valid JSON matching these exact keys: "
        "root_cause_summary (string), drift_category (one of: field_name_change, value_format_shift, "
        "overly_strict_filter, telemetry_missing), updated_sigma_yaml (complete valid Sigma YAML string), "
        "triage_notes (markdown bullet points for Tier-1 analysts), confidence_level (low, medium, or high). "
        "Rules: Use ONLY field names from the provided allowlist. Keep the existing rule id, title, author, "
        "and tags intact. Only use Sigma modifiers: endswith, startswith, contains, or exact match. "
        "Never write overly broad wildcards that match benign PowerShell healthcheck scripts."
    )

    user_prompt = json.dumps(
        {
            "broken_sigma_yaml": broken_rule_text,
            "allowed_siem_fields": sorted(allowed_fields),
            "captured_attack_events_redacted": compact_logs,
            "benign_baseline_must_not_match": BENIGN_EVENTS,
        },
        indent=2,
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    client, model = build_client()
    print(f"Calling Cloudflare Workers AI ({model}) via AI Gateway...")

    for attempt in range(1, MAX_RETRIES + 1):
        print(f"--- Healing Attempt {attempt}/{MAX_RETRIES} ---")
        try:
            fix = call_workers_ai(client, model, messages)
        except (ValidationError, Exception) as exc:
            print(f"Model response error: {exc}")
            messages.append(
                {
                    "role": "user",
                    "content": f"Your previous output could not be parsed as valid JSON ({exc}). Return ONLY raw JSON with the required schema.",
                }
            )
            continue

        passed, verdict = verify_candidate_rule(fix.updated_sigma_yaml, allowed_fields, attack_events)
        print(f"Referee verdict: {verdict}")

        if passed:
            RULE_PATH.write_text(fix.updated_sigma_yaml.strip() + "\n", encoding="utf-8")
            SUMMARY_PATH.parent.mkdir(parents=True, exist_ok=True)
            SUMMARY_PATH.write_text(
                "\n".join(
                    [
                        "## DriftGuard Automated Healing Report",
                        "",
                        f"- **Rule:** `{RULE_PATH.as_posix()}`",
                        f"- **Drift Category:** `{fix.drift_category}`",
                        f"- **AI Confidence:** `{fix.confidence_level}`",
                        f"- **Model (via Cloudflare AI Gateway):** `{model}`",
                        f"- **Automated Referee Verdict:** {verdict}",
                        "",
                        "### Root Cause Summary",
                        fix.root_cause_summary,
                        "",
                        "### Updated Tier-1 SOC Triage Notes",
                        fix.triage_notes,
                        "",
                        "> *Generated automatically by DriftGuard. Human review and merge required.*",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"SUCCESS: Patched {RULE_PATH} and wrote {SUMMARY_PATH}")
            return 0

        messages.append({"role": "assistant", "content": fix.model_dump_json()})
        messages.append(
            {
                "role": "user",
                "content": f"The automated validator rejected your candidate Sigma YAML:\n{verdict}\nFix the YAML and return valid JSON.",
            }
        )

    print("FAILED: Exhausted max retries without a passing Sigma patch.")
    return 1


if __name__ == "__main__":
    sys.exit(main())