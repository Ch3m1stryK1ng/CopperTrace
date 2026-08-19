import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "score_llm_only_baseline.py"
SPEC = importlib.util.spec_from_file_location("score_llm_only_baseline", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_match_requires_function_and_callee():
    report = {
        "vulnerability_class": "OOB_WRITE",
        "sink": {
            "function": "input",
            "operation": "memcpy",
            "expression": "memcpy(dst, src, n)",
        },
    }
    assert MODULE.report_matches_sink(
        report,
        {"function_name": "input", "callee": "memcpy", "label": "COPY_SINK"},
    )
    assert not MODULE.report_matches_sink(
        report,
        {"function_name": "other", "callee": "memcpy", "label": "COPY_SINK"},
    )


def test_match_without_callee_uses_existing_sink_semantics():
    report = {
        "vulnerability_class": "OOB_WRITE",
        "sink": {"function": "advance_buffer", "operation": "state mutation"},
    }
    assert MODULE.report_matches_sink(
        report,
        {"function_name": "advance_buffer", "label": "BUFFER_STATE_SINK"},
    )


def test_aggregate_is_cve_level():
    assert MODULE.aggregate([{"refound": True}, {"refound": False}]) == {
        "cves": 2,
        "cves_refound": 1,
        "cves_missed": 1,
    }
