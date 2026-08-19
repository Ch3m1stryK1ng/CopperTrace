import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "materialize_decompiled_corpus.py"
SPEC = importlib.util.spec_from_file_location("materialize_decompiled_corpus", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_function_rows_are_address_ordered_and_skip_failed_decompilation():
    facts = {
        "functions": [
            {
                "function_id": "fn:00000020",
                "entry": "0x20",
                "name": "later",
                "decompiled_c": "void later(void) {}",
            },
            {
                "function_id": "fn:00000010",
                "entry": "0x10",
                "name": "earlier",
                "decompiled_c": "void earlier(void) {}",
            },
            {
                "function_id": "fn:00000030",
                "entry": "0x30",
                "name": "failed",
                "decompiled_c": "",
            },
        ]
    }

    assert [row["name"] for row in MODULE.function_rows(facts)] == ["earlier", "later"]


def test_cli_materializes_plain_c_and_function_index(tmp_path, monkeypatch):
    facts_path = tmp_path / "program_facts.json"
    facts_path.write_text(
        json.dumps(
            {
                "functions": [
                    {
                        "function_id": "fn:00000010",
                        "entry": "0x10",
                        "end": "0x1f",
                        "name": "example",
                        "signature": "void example(void)",
                        "decompiled_c": "void example(void) {\n}\n",
                    }
                ]
            }
        )
    )
    out_dir = tmp_path / "corpus"
    monkeypatch.setattr(
        "sys.argv",
        [
            str(SCRIPT),
            str(facts_path),
            "--out-dir",
            str(out_dir),
        ],
    )

    assert MODULE.main() == 0
    assert (out_dir / "plain_decompiled.unstripped.c").read_text() == (
        "void example(void) {\n}\n\n"
    )
    row = json.loads(
        (out_dir / "decomp" / "unstripped" / "functions.full.jsonl")
        .read_text()
        .strip()
    )
    assert row["function_id"] == "fn:00000010"
    assert row["addr"] == "0x10"
