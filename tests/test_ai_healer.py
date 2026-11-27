import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import ai_healer
from run_replay_suite import get_rule_entry, parse_sysmon_events


def test_redact_text_strips_sensitive_tokens():
    sample = (
        "Host 10.24.8.15 ran task as User=CORP\\jsmith "
        "email=analyst@example.com guid={1E460BD7-F1C3-4B2E-88BF-4E770A288AF5}"
    )
    redacted = ai_healer.redact_text(sample)
    assert "10.24.8.15" not in redacted
    assert "analyst@example.com" not in redacted
    assert "CORP\\jsmith" not in redacted
    assert "1E460BD7-F1C3-4B2E-88BF-4E770A288AF5" not in redacted
    assert "[REDACTED_IP]" in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "User=[REDACTED_USER]" in redacted
    assert "{REDACTED_GUID}" in redacted


def test_verify_candidate_rejects_hallucinated_field():
    entry = get_rule_entry("rules/windows/proc_creation_encoded_powershell.yml")
    events = parse_sysmon_events(Path(entry["log_path"]), entry.get("event_id"))
    allowed = set(json.loads(ai_healer.ALLOWLIST_PATH.read_text(encoding="utf-8"))["allowed_fields"])

    hallucinated_rule = """
title: Test Hallucinated Field
id: 9b2c1a4e-5f32-4c11-9d8a-7e6f5c4b3a21
status: test
description: Uses a field not in the SIEM allowlist.
author: DriftGuard
date: 2026-11-26
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    FakeTelemetryField|contains: '-enc'
  condition: selection
level: high
"""
    passed, verdict = ai_healer.verify_candidate_rule(hallucinated_rule, allowed, entry, events)
    assert not passed
    assert "not in the SIEM allowlist" in verdict


def test_verify_candidate_rejects_overfitted_ep_requirement():
    entry = get_rule_entry("rules/windows/proc_creation_encoded_powershell.yml")
    events = parse_sysmon_events(Path(entry["log_path"]), entry.get("event_id"))
    allowed = set(json.loads(ai_healer.ALLOWLIST_PATH.read_text(encoding="utf-8"))["allowed_fields"])

    overfitted_rule = """
title: Suspicious Encoded PowerShell Command Execution
id: 9b2c1a4e-5f32-4c11-9d8a-7e6f5c4b3a21
status: test
description: Overfitted rule requiring both -enc and -ep flags.
author: DriftGuard
date: 2026-11-26
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
  selection_flags:
    CommandLine|contains|all:
      - '-enc'
      - '-ep'
  condition: selection_img and selection_flags
level: high
"""
    passed, verdict = ai_healer.verify_candidate_rule(overfitted_rule, allowed, entry, events)
    assert not passed
    assert "withheld positives: 0/2" in verdict


def test_call_workers_ai_detects_truncated_length_response():
    fake_resp = SimpleNamespace(
        choices=[SimpleNamespace(finish_reason="length", message=SimpleNamespace(content='{"root_cause_summary": "cut off'))],
        usage=SimpleNamespace(completion_tokens=2048),
    )
    fake_client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kwargs: fake_resp))
    )
    with pytest.raises(ValueError, match="output limit"):
        ai_healer.call_workers_ai(fake_client, "test-model", [{"role": "user", "content": "hi"}])


def test_call_workers_ai_fallback_and_fence_stripping():
    payload = json.dumps(
        {
            "root_cause_summary": "Updated switched flags.",
            "drift_category": "value_format_shift",
            "updated_sigma_yaml": "title: Test\n",
            "triage_notes": "- Inspect parent process",
            "confidence_level": "high",
        }
    )
    calls = []

    def fake_create(**kwargs):
        calls.append(kwargs["response_format"]["type"])
        if kwargs["response_format"]["type"] == "json_schema":
            raise RuntimeError("json_schema unsupported")
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    finish_reason="stop",
                    message=SimpleNamespace(content=f"```json\n{payload}\n```"),
                )
            ],
            usage=SimpleNamespace(completion_tokens=120),
        )

    fake_client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=fake_create))
    )
    result = ai_healer.call_workers_ai(fake_client, "test-model", [{"role": "user", "content": "hi"}])
    assert calls == ["json_schema", "json_object"]
    assert result.drift_category == "value_format_shift"
    assert result.confidence_level == "high"