import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from run_replay_suite import get_rule_entry


@pytest.fixture
def reference_powershell():
    """Test the checker against a fixed rule. Repository replay still reads rules/windows."""
    entry = get_rule_entry("rules/windows/proc_creation_encoded_powershell.yml")
    entry["rule_path"] = str(Path(__file__).parent / "fixtures/encoded_powershell/guardrail-control.yml")
    return entry
