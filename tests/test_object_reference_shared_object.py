from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import shared_object_miner as miner  # noqa: E402


def _writer(function_id: str = "fn:producer") -> dict:
    return {
        "fact_id": "write:1",
        "summary_id": "summary:insert",
        "function_id": function_id,
        "callsite_id": "site:producer:put",
        "physical_store_site_id": "site:put:store",
        "payload_actual_atom_id": "atom:payload",
        "region": {
            "base_object_id": "obj:container",
            "offset": 4,
            "extent": 4,
        },
        "source_association_ids": ["association:1"],
        "source_definition_ids": ["definition:1"],
        "source_ids": ["source:1"],
        "analysis_precision": "EXACT",
        "ccc_eligible": True,
    }


def _reader(function_id: str = "fn:consumer") -> dict:
    return {
        "fact_id": "read:1",
        "summary_id": "summary:remove",
        "function_id": function_id,
        "callsite_id": "site:consumer:get",
        "physical_load_site_id": "site:get:load",
        "loaded_result_atom_id": "atom:result",
        "loaded_result_object_id": "reg:consumer:0",
        "region": {
            "base_object_id": "obj:container",
            "offset": 4,
            "extent": 4,
        },
        "analysis_precision": "EXACT",
        "ccc_eligible": True,
    }


def test_object_reference_effects_become_channelgraph_candidate() -> None:
    result = miner.mine_object_reference_effect_objects(
        [_writer()],
        [_reader()],
        [
            {
                "association_id": "association:1",
                "source_definition_id": "definition:1",
                "source_id": "source:1",
                "source_decision": "ACCEPT_DETERMINISTIC",
                "pointee_object_id": "obj:payload",
            }
        ],
        deterministic_contexts={
            "fn:producer": ({"ctx:irq"}, "fixture"),
            "fn:consumer": ({"ctx:task"}, "fixture"),
        },
    )

    assert len(result["shared_objects"]) == 1
    shared = result["shared_objects"][0]
    assert shared["transfer_semantics"] == "OBJECT_REFERENCE"
    assert shared["recognition"] == "deterministic"
    assert shared["reference_binding"]["pointee_object_id"] == "obj:payload"
    edges = miner.materialize_channel_edges(result["shared_objects"])
    assert {edge["edge_kind"] for edge in edges} == {
        "CHANNEL_WRITE",
        "CHANNEL_READ",
    }


def test_same_function_state_is_not_promoted_to_ccc() -> None:
    result = miner.mine_object_reference_effect_objects(
        [_writer("fn:one")],
        [_reader("fn:one")],
        [{"association_id": "association:1"}],
    )

    assert result["shared_objects"] == []
    assert result["rejected_candidates"][0]["admission_blockers"] == [
        "object_reference_same_function_not_ccc"
    ]
