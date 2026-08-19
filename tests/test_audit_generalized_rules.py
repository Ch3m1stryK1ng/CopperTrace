from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from audit_generalized_rules import audit_file  # noqa: E402


def test_audit_rejects_evaluation_tokens(tmp_path: Path) -> None:
    path = tmp_path / "rule.py"
    path.write_text(
        'TOKEN = "CVE-2024-12345"\n'
        'SAMPLE = "sample_one"\n'
        'NAME = "known_vulnerable_parser"\n'
    )

    rows = audit_file(
        path,
        sample_ids={"sample_one"},
        vulnerable_functions={"known_vulnerable_parser"},
    )

    assert {row["kind"] for row in rows} == {
        "CVE_IDENTIFIER",
        "SAMPLE_ID",
        "VULNERABLE_FUNCTION_NAME",
    }


def test_audit_allows_structural_ir_rules(tmp_path: Path) -> None:
    path = tmp_path / "rule.py"
    path.write_text('OPS = {"LOAD", "STORE", "PTRADD"}\n')

    assert audit_file(path, sample_ids=set(), vulnerable_functions=set()) == []
