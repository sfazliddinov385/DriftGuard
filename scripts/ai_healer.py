import argparse
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
from sigma.exceptions import SigmaError
from sigma.rule import SigmaYAMLLoader
from sigma.rule.base import check_alias_expansion

sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_replay_suite import (
    MANIFEST_PATH,
    check_rule_entry,
    get_rule_entry,
    parse_sysmon_events,
)

ALLOWLIST_PATH = Path("schemas/sysmon_field_allowlist.json")
SUMMARY_PATH = Path("reports/drift_fix_summary.md")
DEFAULT_RULE = "rules/windows/proc_creation_encoded_powershell.yml"
DEFAULT_MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast"
MAX_RETRIES = 3
MAX_OUTPUT_TOKENS = 2048


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


def summarize_events_for_prompt(
    events: list[dict],
    allowed_fields: set[str],
    expected_positive_ids: set[str] | None = None,
    max_events: int = 10,
) -> list[dict]:
    """Prioritize attack-labeled events + representative background events while redacting tokens."""
    expected_positive_ids = expected_positive_ids or set()
    positives = [ev for ev in events if str(ev.get("EventRecordID", "")) in expected_positive_ids]
    others = [ev for ev in events if str(ev.get("EventRecordID", "")) not in expected_positive_ids]
    selected = positives + others[: max(0, max_events - len(positives))]

    compact = []
    for ev in selected[:max_events]:
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


def detection_only_patch(original_yaml: str, candidate_yaml: str, allowed_fields: set[str]) -> str:
    """Return the original document with just its detection value replaced."""
    bom = "\ufeff" if original_yaml.startswith("\ufeff") else ""
    original_yaml = original_yaml.removeprefix(bom)
    original = yaml.load(original_yaml, Loader=SigmaYAMLLoader)
    proposed = yaml.load(candidate_yaml, Loader=SigmaYAMLLoader)
    for rule in (original, proposed):
        check_alias_expansion(rule)
        if not isinstance(rule, dict) or not isinstance(rule.get("detection"), dict):
            raise ValueError("A rule must contain a top-level detection mapping.")
    protected = (original.keys() | proposed.keys()) - {"detection"}
    changed = [
        str(key) for key in protected if key not in original or key not in proposed
        or yaml.safe_dump(original[key]) != yaml.safe_dump(proposed[key])
    ]
    if changed:
        raise ValueError("Only detection logic may change. Protected fields: " + ", ".join(sorted(changed)))

    selections = [value for key, value in proposed["detection"].items() if key != "condition"]
    while selections:
        selection = selections.pop()
        if isinstance(selection, list):
            selections.extend(selection)
            continue
        if not isinstance(selection, dict):
            raise ValueError("Each automated selection must name an allowlisted field.")
        for key, value in selection.items():
            if not isinstance(key, str):
                raise ValueError("Selection field names must be strings.")
            name, *modifiers = key.split("|")
            if name not in allowed_fields:
                raise ValueError(f"Field '{name}' is not in the SIEM allowlist.")
            if "fieldref" in modifiers:
                refs = value if isinstance(value, list) else [value]
                if not all(isinstance(ref, str) and ref in allowed_fields for ref in refs):
                    raise ValueError("Referenced field is not in the SIEM allowlist.")

    # Keep comments, quoting and line endings outside detection as the author wrote them.
    # A block mapping's end mark can include trailing comments; only replace actual tokens.
    document = yaml.compose(original_yaml, Loader=SigmaYAMLLoader)
    key, block = next(pair for pair in document.value if pair[0].value == "detection")
    start = block.start_mark.index
    if start < key.end_mark.index:
        raise ValueError("The original detection mapping is an alias of a protected field.")
    end = max(
        token.end_mark.index for token in yaml.scan(original_yaml, Loader=SigmaYAMLLoader)
        if start <= token.start_mark.index < block.end_mark.index
        and token.end_mark.index > token.start_mark.index
    )
    newline = "\r\n" if "\r\n" in original_yaml else "\n"
    replacement = yaml.safe_dump(
        proposed["detection"], sort_keys=False, allow_unicode=True, default_flow_style=block.flow_style,
    ).rstrip("\n").replace("\n", newline + " " * block.start_mark.column)
    if original_yaml[start:end].endswith("\n"):
        replacement += newline
    result = original_yaml[:start] + replacement + original_yaml[end:]
    # An alias in the source can link detection to metadata. Refuse ambiguous edits.
    if yaml.load(result, Loader=SigmaYAMLLoader) != proposed:
        raise ValueError("Cannot apply this change without altering the original rule metadata.")
    return bom + result


def verified_repair(
    original_yaml: str,
    candidate_yaml: str,
    allowed_fields: set[str],
    entry: dict,
    attack_events: list[dict],
) -> tuple[str | None, str]:
    try:
        patch = detection_only_patch(original_yaml, candidate_yaml, allowed_fields)
    except (yaml.YAMLError, SigmaError, ValueError, TypeError, RecursionError) as exc:
        return None, f"Invalid Sigma repair: {exc}"

    sigma_bin = find_sigma_executable()
    with tempfile.NamedTemporaryFile("wb", suffix=".yml", delete=False) as tmp:
        tmp.write(patch.encode("utf-8"))
        tmp_path = Path(tmp.name)

    try:
        proc = subprocess.run(
            [sigma_bin, "check", "--fail-on-issues", str(tmp_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return None, f"sigma check failed:\n{proc.stdout}\n{proc.stderr}"
    finally:
        tmp_path.unlink(missing_ok=True)

    passed, verdict = check_rule_entry(patch, entry, attack_events)
    return (patch if passed else None), verdict


def verify_candidate_rule(
    candidate_yaml: str, allowed_fields: set[str], entry: dict, attack_events: list[dict],
) -> tuple[bool, str]:
    original = Path(entry["rule_path"]).read_bytes().decode("utf-8")
    patch, verdict = verified_repair(original, candidate_yaml, allowed_fields, entry, attack_events)
    return patch is not None, verdict


def build_client() -> tuple[OpenAI, str]:
    load_dotenv()
    account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip()
    gateway_id = os.environ.get("CLOUDFLARE_GATEWAY_ID", "").strip()
    api_token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    model = os.getenv("DRIFTGUARD_AI_MODEL", DEFAULT_MODEL).strip()

    acct_ok = bool(re.fullmatch(r"[0-9a-fA-F]{32}", account_id))
    gw_ok = bool(gateway_id) and "/" not in gateway_id and "http" not in gateway_id.lower()
    print(
        f"Config check: account_id_valid_32hex={acct_ok} (len={len(account_id)}), "
        f"gateway_id_valid_slug={gw_ok} (len={len(gateway_id)}), "
        f"api_token_present={len(api_token) > 10}"
    )
    if not acct_ok or not gw_ok or len(api_token) <= 10:
        raise ValueError(
            "Invalid Cloudflare secret format. Ensure CLOUDFLARE_ACCOUNT_ID is a 32-char hex ID "
            "and CLOUDFLARE_GATEWAY_ID is just the gateway slug (e.g. 'driftguard-gateway')."
        )

    client = OpenAI(
        api_key=api_token,
        base_url=f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/v1",
        default_headers={"cf-aig-gateway-id": gateway_id},
    )
    return client, model


def call_workers_ai(client: OpenAI, model: str, messages: list[dict]) -> DriftFix:
    schema = DriftFix.model_json_schema()
    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.1,
            max_tokens=MAX_OUTPUT_TOKENS,
            messages=messages,
            response_format={
                "type": "json_schema",
                "json_schema": {"name": "drift_fix", "schema": schema},
            },
        )
    except Exception:
        resp = client.chat.completions.create(
            model=model,
            temperature=0.1,
            max_tokens=MAX_OUTPUT_TOKENS,
            messages=messages,
            response_format={"type": "json_object"},
        )

    choice = resp.choices[0]
    completion_tokens = resp.usage.completion_tokens if resp.usage else None
    print(
        f"Workers AI response: finish_reason={choice.finish_reason}, "
        f"completion_tokens={completion_tokens}"
    )
    if choice.finish_reason == "length":
        raise ValueError(
            "Response reached the output limit. Shorten the summary and triage notes and return the full rule."
        )
    raw_content = (choice.message.content or "").strip()
    if raw_content.startswith("```"):
        raw_content = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw_content, flags=re.DOTALL)
    return DriftFix.model_validate_json(raw_content)


def heal_rule(rule_path_str: str, manifest_path: Path, summary_path: Path, append_summary: bool) -> int:
    entry = get_rule_entry(rule_path_str, manifest_path)
    rule_path = Path(entry["rule_path"])
    log_path = Path(entry["log_path"])

    allowed_fields = set(json.loads(ALLOWLIST_PATH.read_text(encoding="utf-8"))["allowed_fields"])
    broken_rule_text = rule_path.read_bytes().decode("utf-8")
    attack_events = parse_sysmon_events(log_path, entry.get("event_id"))
    expected_pos = {str(rid) for rid in entry.get("expected_positive_record_ids", [])}
    compact_logs = summarize_events_for_prompt(attack_events, allowed_fields, expected_pos)

    system_prompt = (
        "You are DriftGuard, a senior Blue Team Detection Engineer. "
        "A Sigma detection rule failed automated log replay validation. "
        "Analyze the broken Sigma YAML alongside the redacted attack telemetry and benign baseline logs. "
        "Return ONLY valid JSON matching these exact keys: "
        "root_cause_summary (string), drift_category (one of: field_name_change, value_format_shift, "
        "overly_strict_filter, telemetry_missing), updated_sigma_yaml (complete valid Sigma YAML string), "
        "triage_notes (markdown bullet points for Tier-1 analysts), confidence_level (low, medium, or high). "
        "Rules: Change ONLY the detection block. Keep every other field and value exactly as supplied. "
        "Use only the listed fields and the endswith, startswith, contains, or exact-match operations. "
        "Generalize cleanly across valid attack syntax variants instead of overfitting to incidental flags, "
        "and never match the provided benign baseline logs."
    )

    user_prompt = json.dumps(
        {
            "rule_id": entry["id"],
            "broken_sigma_yaml": broken_rule_text,
            "allowed_siem_fields": sorted(allowed_fields),
            "captured_attack_events_redacted": compact_logs,
            "benign_baseline_must_not_match": entry.get("benign_events", []),
        },
        indent=2,
    )

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    client, model = build_client()
    print(f"Healing {rule_path.as_posix()} using Cloudflare Workers AI ({model}) via AI Gateway...")

    for attempt in range(1, MAX_RETRIES + 1):
        print(f"--- Healing Attempt {attempt}/{MAX_RETRIES} ---")
        try:
            fix = call_workers_ai(client, model, messages)
        except (ValidationError, Exception) as exc:
            print(f"Model response error: {exc} | body={getattr(exc, 'body', None)}")
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Your previous output could not be parsed as valid JSON ({exc}). "
                        "Return ONLY raw JSON with the required schema."
                    ),
                }
            )
            continue

        patch, verdict = verified_repair(
            broken_rule_text, fix.updated_sigma_yaml, allowed_fields, entry, attack_events
        )
        print(f"Referee verdict: {verdict}")

        if patch is not None:
            rule_path.write_bytes(patch.encode("utf-8"))
            report_block = (
                "\n".join(
                    [
                        f"## DriftGuard Automated Healing Report (`{entry['id']}`)",
                        "",
                        f"- **Rule:** `{rule_path.as_posix()}`",
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
                + "\n"
            )
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            if append_summary and summary_path.exists():
                existing = summary_path.read_text(encoding="utf-8")
                summary_path.write_text(existing + "\n---\n\n" + report_block, encoding="utf-8")
            else:
                summary_path.write_text(report_block, encoding="utf-8")
            print(f"SUCCESS: Patched {rule_path} and wrote {summary_path}")
            return 0

        messages.append({"role": "assistant", "content": fix.model_dump_json()})
        messages.append(
            {
                "role": "user",
                "content": (
                    f"The automated validator rejected your candidate Sigma YAML:\n{verdict}\n"
                    "Fix the YAML and return valid JSON."
                ),
            }
        )

    print(f"FAILED: Exhausted max retries for {rule_path.as_posix()} without a passing Sigma patch.")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="DriftGuard Cloudflare Workers AI drift healer.")
    parser.add_argument("--rule", default=DEFAULT_RULE, help="Path to the drifting Sigma rule")
    parser.add_argument("--manifest", default=str(MANIFEST_PATH), help="Path to tests/manifest.yml")
    parser.add_argument("--summary-out", default=str(SUMMARY_PATH), help="Path for markdown report")
    parser.add_argument("--append-summary", action="store_true", help="Append to existing report")
    args = parser.parse_args()

    return heal_rule(
        rule_path_str=args.rule,
        manifest_path=Path(args.manifest),
        summary_path=Path(args.summary_out),
        append_summary=args.append_summary,
    )


if __name__ == "__main__":
    sys.exit(main())