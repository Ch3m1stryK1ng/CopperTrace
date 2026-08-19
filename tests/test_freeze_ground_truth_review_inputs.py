import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "freeze_ground_truth_review_inputs.py"
SPEC = importlib.util.spec_from_file_location("freeze_ground_truth_review_inputs", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_canonical_rows_prefers_v4_collection():
    rows = MODULE.canonical_rows(
        {
            "canonical_alerts": [
                {"alert_id": "B", "rank": 2},
                {"alert_id": "A", "rank": 1},
            ],
            "selected": [{"alert_id": "legacy"}],
        }
    )
    assert [row["alert_id"] for row in rows] == ["A", "B"]


def test_resolve_decompiled_path_uses_program_facts(tmp_path):
    code = tmp_path / "plain.c"
    code.write_text("void f(void) {}\n", encoding="utf-8")
    facts = tmp_path / "facts.json"
    facts.write_text(json.dumps({"decompiled_c_path": str(code)}), encoding="utf-8")
    assert MODULE.resolve_decompiled_path({"sample_id": "S"}, facts) == code


def test_alert_identity_ignores_order():
    assert MODULE.alert_identity([{"alert_id": "B"}, {"alert_id": "A"}]) == ("A", "B")


def test_empty_canonical_collection_is_a_valid_zero_alert_firmware():
    assert MODULE.canonical_rows({"canonical_alerts": []}) == []
