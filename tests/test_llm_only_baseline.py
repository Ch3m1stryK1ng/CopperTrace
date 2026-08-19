import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "run_llm_only_baseline.py"
SPEC = importlib.util.spec_from_file_location("run_llm_only_baseline", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def make_store(tmp_path):
    code = tmp_path / "decompiled.c"
    code.write_text(
        "int helper(char *dst, char *src, int n)\n{\n  return memcpy(dst, src, n);\n}\n",
        encoding="utf-8",
    )
    return MODULE.CodeStore(code)


def test_code_store_uses_only_text_and_returns_line_anchors(tmp_path):
    store = make_store(tmp_path)
    result = store.search_code({"pattern": "memcpy"})
    assert result["hits"][0]["line"] == 3
    function = store.get_function({"name": "helper"})
    assert function["start_line"] == 1
    assert "memcpy" in function["code"]


def test_sanitize_code_removes_public_identifier():
    assert "CVE-" not in MODULE.sanitize_code("/* CVE-2024-1234 */")


def test_preflight_requires_exact_no_fallback_model(tmp_path):
    path = tmp_path / "preflight.json"
    path.write_text(
        json.dumps(
            {
                "status": "READY",
                "expected_model_alias": "gpt-5.6-sol",
                "exact_model_callable": True,
                "fallback_allowed": False,
            }
        ),
        encoding="utf-8",
    )
    assert MODULE.validate_preflight(path, "gpt-5.6-sol")["status"] == "READY"


def test_validate_empty_report_is_valid():
    result = MODULE.validate_report(
        {
            "schema_version": MODULE.REPORT_SCHEMA_VERSION,
            "firmware_id": "FW001",
            "reports": [],
        },
        "FW001",
        10,
    )
    assert result["reports"] == []


def test_validate_report_rejects_out_of_range_evidence():
    report = {
        "schema_version": MODULE.REPORT_SCHEMA_VERSION,
        "firmware_id": "FW001",
        "reports": [
            {
                "report_id": "R1",
                "vulnerability_class": "OOB_WRITE",
                "source": {},
                "sink": {},
                "vulnerable_parameters": [],
                "path": [],
                "checks": [],
                "dangerous_condition": "n > cap",
                "reason": "test",
                "evidence": [{"start_line": 1, "end_line": 11}],
                "confidence": "HIGH",
            }
        ],
    }
    try:
        MODULE.validate_report(report, "FW001", 10)
    except MODULE.ProtocolError:
        pass
    else:
        raise AssertionError("invalid evidence range was accepted")
