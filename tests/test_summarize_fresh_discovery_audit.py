import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "artifacts/fresh_discovery_audit_100_results_20260812/summary.json"


def test_frozen_fresh_discovery_audit_summary() -> None:
    if not SUMMARY.is_file():
        pytest.skip("frozen evaluation outputs are distributed in the artifact")
    summary = json.loads(SUMMARY.read_text())

    assert summary["scope"]["firmwares"] == 20
    assert summary["scope"]["selected_static_alerts"] == 100
    assert summary["review"]["model"] == "gpt-5.6-sol"
    assert summary["review"]["reasoning_effort"] == "medium"
    assert summary["review"]["decisions"] == {
        "TRUPOC": 69,
        "REJECT": 13,
        "UNRESOLVED": 18,
    }
    assert summary["review"]["execution_failures"] == 0
    assert summary["checks"] == {
        "alerts_with_checks": 94,
        "check_candidates": 331,
        "truncated": 38,
    }
    assert summary["scope"]["human_review_status"] == "PENDING"
    assert summary["scope"]["zero_day_claims"] == 0
