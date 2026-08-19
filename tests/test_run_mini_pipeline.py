from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_mini_pipeline", ROOT / "scripts/run_mini_pipeline.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_optional_file_rejects_empty_value_and_directory(tmp_path: Path) -> None:
    assert MODULE.optional_file("") is None
    assert MODULE.optional_file(None) is None
    assert MODULE.optional_file(tmp_path) is None


def test_optional_file_accepts_regular_file(tmp_path: Path) -> None:
    profile = tmp_path / "profile.json"
    profile.write_text("{}\n")
    assert MODULE.optional_file(profile) == profile


def test_materialize_decompiled_c_from_program_facts(tmp_path: Path) -> None:
    facts = tmp_path / "program_facts.json"
    facts.write_text(
        """{
  "binary_sha256": "abc123",
  "functions": [
    {
      "function_id": "fn:00001000",
      "entry": "00001000",
      "name": "receive_byte",
      "decompiled_c": "void receive_byte(void) { return; }"
    }
  ]
}
"""
    )

    result = MODULE.materialize_decompiled_c(
        program_facts=facts,
        out_dir=tmp_path,
    )

    assert result["returncode"] == 0
    output = Path(result["decompiled_c"])
    assert output.is_file()
    assert "void receive_byte(void)" in output.read_text()
    assert result["functions_materialized"] == 1


def test_materialize_decompiled_c_rejects_empty_facts(tmp_path: Path) -> None:
    facts = tmp_path / "empty_program_facts.json"
    facts.write_text('{"functions": []}\n')

    result = MODULE.materialize_decompiled_c(
        program_facts=facts,
        out_dir=tmp_path,
    )

    assert result["returncode"] != 0
    assert result["error"] == "failed_to_materialize_decompiled_c"


def test_full_mode_adds_no_miner_ablation_flags() -> None:
    assert MODULE.source_builder_ablation_args(()) == []
    assert MODULE.sink_builder_ablation_args(()) == []


def test_source_and_sink_ablation_flags_are_independent() -> None:
    source_only = ("mcu-source-recognition",)
    sink_only = ("body-derived-sink-heuristics",)
    combined = tuple(sorted((*source_only, *sink_only)))

    assert MODULE.source_builder_ablation_args(source_only) == [
        "--disable-mcu-source-recognition"
    ]
    assert MODULE.sink_builder_ablation_args(source_only) == []
    assert MODULE.source_builder_ablation_args(sink_only) == []
    assert MODULE.sink_builder_ablation_args(sink_only) == [
        "--disable-body-derived-sink-heuristics"
    ]
    assert MODULE.source_builder_ablation_args(combined) == [
        "--disable-mcu-source-recognition"
    ]
    assert MODULE.sink_builder_ablation_args(combined) == [
        "--disable-body-derived-sink-heuristics"
    ]


def test_public_primitive_effect_maps_to_canonical_wrapper_startpoint() -> None:
    startpoint = {
        "id": "sink:wrapper",
        "label": "COPY_SINK",
        "recognition": "deterministic",
        "decision": "ACCEPT_DETERMINISTIC",
        "function": "caller",
        "callee": "copy_helper",
        "site_id": "site:caller:10:1",
        "effect_site_id": "site:helper:20:2",
        "vulnerable_parameters": [{"role": "len", "value_id": "value:len"}],
    }
    effect = {
        "label": "COPY_SINK",
        "function": "copy_helper",
        "callee": "memcpy",
        "site_id": "site:helper:20:2",
        "effect_site_id": "site:helper:20:2",
        "binding_status": "verified_high_pcode_callsite",
        "vulnerable_parameters": [{"role": "len", "value_id": "value:formal"}],
    }
    expected = {
        "sink_id": "PUBLIC_COPY",
        "pipeline_label_hint": "COPY_SINK",
        "function_name": "copy_helper",
        "callee": "memcpy",
        "site_id_regex": "^site:helper:20:2$",
    }

    match = MODULE.match_sink(
        expected, [startpoint], primitive_effect_sites=[effect]
    )

    assert match["status"] == "DETERMINISTIC_HIT"
    assert match["sink_id"] == "sink:wrapper"
    assert match["sink_ids"] == ["sink:wrapper"]
    assert match["matched_via"] == "body_derived_effect"


def test_chain_evaluation_chooses_source_reaching_canonical_startpoint() -> None:
    sink_matches = [{
        "expected_sink_id": "PUBLIC_COPY",
        "sink_id": "sink:first",
        "sink_ids": ["sink:first", "sink:second"],
    }]
    source_matches = [{"status": "DETERMINISTIC_HIT", "source_id": "SO1"}]
    chains = {
        "chains": [
            {
                "sink_id": "sink:first",
                "status": "GRAPH_INCOMPLETE",
                "parameter_results": [],
            },
            {
                "sink_id": "sink:second",
                "status": "SOURCE_REACHED_HEURISTIC",
                "parameter_results": [{
                    "paths": [{"source_lineage_ids": ["SO1"]}],
                }],
            },
        ]
    }

    result = MODULE.evaluate_chains(sink_matches, source_matches, chains)[0]

    assert result["sink_id"] == "sink:second"
    assert result["status"] == "SOURCE_REACHED_HEURISTIC"
    assert result["matched_public_source"] is True
