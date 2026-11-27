import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

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


@pytest.fixture
def powershell_case():
    entry = get_rule_entry("rules/windows/proc_creation_encoded_powershell.yml")
    events = parse_sysmon_events(Path(entry["log_path"]), entry.get("event_id"))
    allowed = set(json.loads(ai_healer.ALLOWLIST_PATH.read_text())["allowed_fields"])
    original = Path(entry["rule_path"]).read_text()
    return original, allowed, entry, events


@pytest.mark.parametrize("selection", [
    {"FakeTelemetryField|contains": "-enc"},
    [{"Image|endswith": "pwsh.exe"}, {"FakeTelemetryField|contains": "-enc"}],
    {"Image|fieldref": "FakeTelemetryField"},
])
def test_verify_candidate_rejects_hallucinated_field(powershell_case, selection):
    original, allowed, entry, events = powershell_case
    rule = yaml.safe_load(original)
    rule["detection"]["selection_flags"] = selection
    passed, verdict = ai_healer.verify_candidate_rule(yaml.safe_dump(rule), allowed, entry, events)
    assert not passed
    assert "not in the SIEM allowlist" in verdict


def test_verify_candidate_rejects_overfitted_ep_requirement(powershell_case):
    original, allowed, entry, events = powershell_case
    rule = yaml.safe_load(original)
    rule["detection"]["selection_flags"] = {"CommandLine|contains|all": ["-enc", "-ep"]}
    passed, verdict = ai_healer.verify_candidate_rule(yaml.safe_dump(rule), allowed, entry, events)
    assert not passed
    assert "withheld positives: 0/2" in verdict


@pytest.mark.parametrize(("field", "change"), [
    ("id", "0a2b13bb-fada-4af5-8ebd-978be0d6c54b"),
    ("level", "low"),
    ("tags", ["attack.t1059"]),
    ("logsource", {"product": "linux", "category": "process_creation"}),
    ("falsepositives", None),  # removed metadata
    ("custom_metadata", {"owner": "somebody"}),  # added metadata
])
def test_replay_correct_rule_cannot_change_protected_fields(powershell_case, field, change):
    original, allowed, entry, events = powershell_case
    rule = yaml.safe_load(original)
    if change is None:
        del rule[field]
    else:
        rule[field] = change
    passed, verdict = ai_healer.verify_candidate_rule(yaml.safe_dump(rule), allowed, entry, events)
    assert not passed
    assert "Only detection logic may change" in verdict and field in verdict


def test_duplicate_keys_rejected_even_when_last_value_is_correct(powershell_case):
    original, allowed, entry, events = powershell_case
    proposed = original.replace("level: high", "level: low\nlevel: high")
    passed, verdict = ai_healer.verify_candidate_rule(proposed, allowed, entry, events)
    assert not passed
    assert "Duplicate key" in verdict


def test_heal_applies_only_the_verified_detection(tmp_path, powershell_case, monkeypatch):
    original, _, entry, _ = powershell_case
    prefix_note = "# Keep this local note: édition 1\n"
    suffix_note = "# This explains our local false-positive policy.\n"
    broken = prefix_note + original.replace("falsepositives:", suffix_note + "falsepositives:")
    broken = broken.replace("condition: selection_img and selection_flags",
                            "condition: selection_img and not selection_flags")
    rule_path = tmp_path / "rule.yml"
    rule_path.write_bytes(b"\xef\xbb\xbf" + broken.replace("\n", "\r\n").encode("utf-8"))
    entry["rule_path"] = str(rule_path)
    manifest = tmp_path / "manifest.yml"
    manifest.write_text(yaml.safe_dump({"rules": [entry]}))
    repair = ai_healer.DriftFix(
        root_cause_summary="Fix the selection condition.", drift_category="overly_strict_filter",
        updated_sigma_yaml=yaml.safe_dump(yaml.safe_load(original), sort_keys=True),
        triage_notes="Review the command line.", confidence_level="high",
    )
    monkeypatch.setattr(ai_healer, "build_client", lambda: (None, "offline-test"))
    monkeypatch.setattr(ai_healer, "call_workers_ai", lambda *_: repair)
    before = rule_path.read_bytes()
    summary = tmp_path / "summary.md"
    assert ai_healer.heal_rule(str(rule_path), manifest, summary, False) == 0
    after = rule_path.read_bytes()
    assert before.split(b"detection:\r\n")[0] == after.split(b"detection:\r\n")[0]
    assert after.endswith(before[before.index(suffix_note.strip().encode()):])
    assert yaml.safe_load(after) == yaml.safe_load(original)
    assert summary.is_file()


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


def test_actual_gateway_requests_hide_private_values_through_fallback_and_retry(tmp_path, powershell_case, monkeypatch):
    original, _, entry, events = powershell_case
    guid = "c87a484d-bec7-4b00-ac53-4c3a026eaf0a"
    private = [
        "198.51.100.24", "2001:db8::a", "fe80::8%eth0", "host@example.test",
        "private-user", "profile user", "standalone-user", "retry-secret", guid,
        "LOCAL-METADATA", "WITHHELD-ONLY", "UNLISTED-FIELD-VALUE",
    ]
    correct = yaml.safe_load(original)["detection"]
    broken = yaml.safe_load(original)
    broken["description"] = "LOCAL-METADATA"
    broken["detection"]["selection_flags"]["CommandLine|contains"] = private[:4] + [guid]
    rule = tmp_path / "rule.yml"
    rule.write_text(yaml.safe_dump(broken, sort_keys=False))
    entry["rule_path"] = str(rule)
    entry["benign_events"][0].update({
        "User": "standalone-user", "Unused": "UNLISTED-FIELD-VALUE",
        "CommandLine": r"echo C:\Users\profile user\docs /home/private-user/note standalone-user",
    })
    entry["withheld_positive_events"][0]["PrivateNote"] = "WITHHELD-ONLY"
    events[0].update({"User": r"LAB\private-user", "ParentCommandLine": "send to " + " ".join(private[:4])})
    manifest = tmp_path / "manifest.yml"
    manifest.write_text(yaml.safe_dump({"rules": [entry]}))
    monkeypatch.setattr(ai_healer, "parse_sysmon_events", lambda *_: events)
    calls = []

    def complete(**kwargs):
        calls.append(kwargs)
        if len(calls) == 1:
            raise RuntimeError("json_schema unsupported: retry-secret")
        if len(calls) == 2:
            content = '{"unexpected": "retry-secret"}'
        else:
            content = ai_healer.DriftFix(
                root_cause_summary="Restore encoded switches.", drift_category="value_format_shift",
                updated_sigma_yaml=yaml.safe_dump({"detection": correct}),
                triage_notes="Review the process.", confidence_level="high",
            ).model_dump_json()
        return SimpleNamespace(choices=[SimpleNamespace(finish_reason="stop", message=SimpleNamespace(content=content))], usage=None)

    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=complete)))
    monkeypatch.setattr(ai_healer, "build_client", lambda: (client, "offline-test"))
    assert ai_healer.heal_rule(str(rule), manifest, tmp_path / "summary.md", False) == 0
    assert [c["response_format"]["type"] for c in calls] == ["json_schema", "json_object", "json_schema"]
    for call in calls:
        wire = json.dumps(call["messages"])
        assert not any(value in wire for value in [*private, broken["id"]])
        assert "REDACTED_IP" in wire and "REDACTED_USER" in wire and "REDACTED_GUID" in wire
        assert call["max_tokens"] == 2048
    saved = yaml.safe_load(rule.read_text())
    assert saved["detection"] == correct
    assert saved["description"] == "LOCAL-METADATA" and saved["id"] == broken["id"]


def test_strict_replies_and_redacted_literals_cannot_become_a_repair(powershell_case):
    original, fields, entry, events = powershell_case
    candidate = {"detection": {"selection": {"User": "[REDACTED_USER]"}, "condition": "selection"}}
    assert ai_healer.verified_repair(original, yaml.safe_dump(candidate), fields, entry, events)[0] is None
    assert ai_healer.DriftFix.model_json_schema()["additionalProperties"] is False
