import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "summarize_original_mango_baseline.py"
SPEC = importlib.util.spec_from_file_location("summarize_original_mango_baseline", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)

endpoint_matches_closure = MODULE.endpoint_matches_closure
has_mango_source = MODULE.has_mango_source
is_mango_trupoc = MODULE.is_mango_trupoc
classify_run_failure = MODULE.classify_run_failure


def test_thumb_callsite_address_is_normalized():
    endpoint = {
        "callee": "memcpy",
        "site_id_regex": r"^site:002079c4:00207a0c:144$",
        "function_name": "uncompress_addr",
    }
    closure = {
        "sink": {"function": "memcpy", "ins_addr": "0x207a0d"},
        "trace": [{"function": "uncompress_addr"}],
    }
    assert endpoint_matches_closure(endpoint, closure)


def test_function_fallback_requires_expected_caller():
    endpoint = {"callee": "memcpy", "function_name": "parse_packet"}
    matching = {
        "sink": {"function": "memcpy", "ins_addr": "0x101"},
        "trace": [{"function": "parse_packet"}],
    }
    unrelated = {
        "sink": {"function": "memcpy", "ins_addr": "0x101"},
        "trace": [{"function": "other"}],
    }
    assert endpoint_matches_closure(endpoint, matching)
    assert not endpoint_matches_closure(endpoint, unrelated)


def test_source_and_native_trupoc_are_separate_properties():
    low_rank_source = {
        "inputs": {"likely": ["recv(...)"], "possibly": []},
        "rank": 0.6,
    }
    high_rank_source = {
        "inputs": {"likely": ["nvram_get(...)"], "possibly": []},
        "rank": 7,
    }
    assert has_mango_source(low_rank_source)
    assert not is_mango_trupoc(low_rank_source)
    assert has_mango_source(high_rank_source)
    assert is_mango_trupoc(high_rank_source)


def test_classifies_angr_calling_convention_failure():
    assert (
        classify_run_failure(
            status={"status": "ANALYSIS_FAILED", "return_code": 1},
            mango_error=None,
            log_text="KeyError: 'Linux'",
        )
        == "ANGR_CALLING_CONVENTION_ERROR"
    )


def test_classifies_wall_timeout_before_log_patterns():
    assert (
        classify_run_failure(
            status={"status": "TIMEOUT", "failure": "wall_timeout_3600s"},
            mango_error=None,
            log_text="",
        )
        == "WALL_TIMEOUT"
    )


def test_missing_status_and_log_is_not_run():
    assert (
        classify_run_failure(status=None, mango_error=None, log_text="")
        == "NOT_RUN"
    )


def test_partial_timeout_result_is_not_promoted_to_completed(tmp_path):
    digest = "a" * 64
    job = tmp_path / "per_elf" / digest[:12] / "memcpy"
    job.mkdir(parents=True)
    (job / "memcpy_results.json").write_text(
        json.dumps({"closures": [{"rank": 9}], "error": None})
    )
    (job / "run_status.json").write_text(
        json.dumps({"status": "TIMEOUT", "failure": "wall_timeout_3600s"})
    )

    results = MODULE.load_results(
        tmp_path,
        {"inventory": [{"binary_sha256": digest}], "categories": ["memcpy"]},
    )

    assert results[(digest, "memcpy")]["status"] == "ANALYSIS_FAILED"
    assert results[(digest, "memcpy")]["closures"] == []
    assert results[(digest, "memcpy")]["failure_reason"] == "WALL_TIMEOUT"
