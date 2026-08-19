from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import shared_object_miner  # noqa: E402
import source_association  # noqa: E402
import memory_access_facts  # noqa: E402


class FakeRuntime:
    def __init__(self, functions: list[dict]) -> None:
        self.functions = {
            str(function["function_id"]): function for function in functions
        }

    def resolve(self, node: dict, function_id: str) -> dict | None:
        object_id = str(node.get("resolved_object_id", ""))
        if not object_id:
            return None
        return {
            "object_id": object_id,
            "root_object_id": object_id,
            "access_path": [],
        }


def pointer(value_id: str, object_id: str, *, slot: int | None = None) -> dict:
    return {
        "value_id": value_id,
        "object_id": f"param:{slot}" if slot is not None else value_id,
        "resolved_object_id": object_id,
        "is_parameter": slot is not None,
        "is_input": slot is not None,
        "parameter_slot": slot,
        "index": slot,
        "is_constant": False,
        "size": 4,
        "high_data_type": "void *",
    }


class SourceAssociationVNextTests(unittest.TestCase):
    def test_same_semantic_state_keeps_shortest_channel_witness(self) -> None:
        sources = {
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:1",
                    "source_id": "SO1",
                }
            ]
        }
        common = {
            "source_definition_id": "source-definition:1",
            "source_id": "SO1",
            "state_kind": "VALUE",
            "function_id": "fn:consumer",
            "atom_id": "value:loaded",
            "relation_kind": "CHANNEL_READ_MEMORY_CONTENT",
            "precision": "MAY",
        }
        rows, blockers = source_association.build_source_associations(
            {"functions": []},
            sources,
            value_provenance={},
            channel_edges=[],
            runtime=FakeRuntime([]),
            seed_associations=[
                {
                    **common,
                    "site_id": "site:long",
                    "channel_depth": 3,
                },
                {
                    **common,
                    "site_id": "site:short",
                    "channel_depth": 1,
                },
            ],
        )

        self.assertEqual(blockers, [])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["channel_depth"], 1)
        self.assertEqual(rows[0]["site_id"], "site:short")

    def test_source_formal_output_is_instantiated_at_caller_actual(self) -> None:
        actual = pointer("value:actual", "obj:caller-buffer")
        formal = pointer("value:formal", "obj:callee-formal", slot=0)
        functions = [
            {
                "function_id": "fn:caller",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:source-call",
                        "mnemonic": "CALL",
                        "inputs": [{"is_constant": True}, actual],
                        "call": {
                            "target_function_id": "fn:source",
                            "argument_value_ids": ["value:actual"],
                        },
                    }
                ],
            },
            {
                "function_id": "fn:source",
                "parameters": [formal],
                "pcode_ops": [],
            },
        ]
        sources = {
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:1",
                    "source_id": "SO1",
                    "function_id": "fn:source",
                    "site_id": "site:source",
                    "decision": "ACCEPT_DETERMINISTIC",
                    "outputs": [
                        {
                            "kind": "memory_object",
                            "value_id": "value:formal",
                            "object_id": "obj:callee-formal",
                        }
                    ],
                }
            ]
        }
        rows, _blockers = source_association.build_source_associations(
            {"functions": functions},
            sources,
            value_provenance={},
            channel_edges=[],
            runtime=FakeRuntime(functions),
        )
        caller_rows = [
            row
            for row in rows
            if row.get("relation_kind") == "SOURCE_OUTPUT_ACTUAL_BINDING"
        ]
        self.assertEqual(len(caller_rows), 1)
        self.assertEqual(caller_rows[0]["function_id"], "fn:caller")
        self.assertEqual(caller_rows[0]["object_id"], "obj:caller-buffer")
        self.assertEqual(caller_rows[0]["state_kind"], "MEMORY_CONTENT")

    def test_concrete_load_from_source_memory_becomes_value(self) -> None:
        functions = [
            {
                "function_id": "fn:consumer",
                "parameters": [],
                "pcode_ops": [],
            }
        ]
        sources = {
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:1",
                    "source_id": "SO1",
                }
            ]
        }
        read = memory_access_facts.ReadFact(
            access_kind="READ",
            site_id="site:load",
            function_id="fn:consumer",
            object_id="obj:data",
            aggregate_object_id="obj:data",
            base_object_id="obj:data",
            stored_atom_id="",
            loaded_atom_id="value:loaded",
            region_offset=2,
            region_extent=1,
            selector_terms=(),
            field_path=(),
            address_provenance="HIGH_PCODE_CONCRETE_ACCESS",
            storage_kind="STATIC_WRITABLE_DATA",
            deterministic_context_ids=("ctx:task",),
            context_ids=("ctx:task",),
            access_edge_id="object-read:1",
        )
        rows, blockers = source_association.build_source_associations(
            {"functions": functions},
            sources,
            value_provenance={},
            channel_edges=[
                {
                    "edge_kind": "CHANNEL_WRITE",
                    "src_node_id": "fn:producer",
                    "object_id": "obj:data",
                    "region": {
                        "object_id": "obj:data",
                        "base_object_id": "obj:data",
                        "offset": 0,
                        "extent": 8,
                    },
                    "source_id": "SO1",
                    "analysis_precision": "EXACT",
                    "site_id": "site:write",
                }
            ],
            runtime=FakeRuntime(functions),
            access_index=memory_access_facts.MemoryAccessFactIndex(
                read_facts=[read]
            ),
        )
        self.assertEqual(blockers, [])
        loaded = next(
            row for row in rows if row.get("atom_id") == "value:loaded"
        )
        self.assertEqual(loaded["state_kind"], "VALUE")
        self.assertEqual(
            loaded["relation_kind"], "CONCRETE_LOAD_FROM_SOURCE_MEMORY"
        )
        self.assertEqual(loaded["precision"], "EXACT")

    def test_load_through_source_value_pointer_keeps_lineage(self) -> None:
        source_pointer = pointer("value:source-pointer", "obj:input")
        loaded = {
            "value_id": "value:loaded-byte",
            "object_id": "unique:loaded-byte",
            "is_constant": False,
            "size": 1,
            "high_data_type": "uint8_t",
            "def_site_id": "site:load-byte",
        }
        functions = [
            {
                "function_id": "fn:consumer",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:load-byte",
                        "mnemonic": "LOAD",
                        "inputs": [{"is_constant": True}, source_pointer],
                        "output": loaded,
                    }
                ],
            }
        ]
        sources = {
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:1",
                    "source_id": "SO1",
                    "function_id": "fn:consumer",
                    "site_id": "site:source",
                    "decision": "ACCEPT_HEURISTIC",
                    "outputs": [
                        {
                            "kind": "scalar_value",
                            "value_id": "value:source-pointer",
                            "object_id": "obj:input",
                        }
                    ],
                }
            ]
        }
        rows, _blockers = source_association.build_source_associations(
            {"functions": functions},
            sources,
            value_provenance={
                ("fn:consumer", "value:source-pointer"): {
                    "source-definition:1": {"transfers": []}
                }
            },
            channel_edges=[],
            runtime=FakeRuntime(functions),
        )
        result = next(
            row for row in rows if row.get("atom_id") == "value:loaded-byte"
        )
        self.assertEqual(
            result["relation_kind"], "LOAD_THROUGH_SOURCE_VALUE_POINTER"
        )
        self.assertEqual(result["state_kind"], "VALUE")
        self.assertEqual(result["precision"], "MAY")

    def test_memory_content_becomes_call_reference_and_formal(self) -> None:
        actual = pointer("value:actual", "obj:data")
        formal = pointer("value:formal", "obj:formal:fn:b:0", slot=0)
        functions = [
            {
                "function_id": "fn:a",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:call",
                        "mnemonic": "CALL",
                        "inputs": [{"is_constant": True}, actual],
                        "call": {
                            "target_function_id": "fn:b",
                            "argument_value_ids": ["value:actual"],
                        },
                    }
                ],
            },
            {
                "function_id": "fn:b",
                "parameters": [formal],
                "pcode_ops": [],
            },
        ]
        sources = {
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:1",
                    "source_id": "SO1",
                }
            ]
        }
        rows, blockers = source_association.build_source_associations(
            {"functions": functions},
            sources,
            value_provenance={},
            channel_edges=[
                {
                    "edge_kind": "CHANNEL_WRITE",
                    "src_node_id": "fn:producer",
                    "object_id": "obj:data",
                    "region": {
                        "object_id": "obj:data",
                        "offset": 0,
                        "extent": 8,
                    },
                    "source_id": "SO1",
                    "analysis_precision": "EXACT",
                    "site_id": "site:write",
                }
            ],
            runtime=FakeRuntime(functions),
        )
        self.assertEqual(blockers, [])
        references = [
            row for row in rows if row["state_kind"] == "OBJECT_REFERENCE"
        ]
        self.assertEqual(
            {(row["function_id"], row["atom_id"]) for row in references},
            {("fn:a", "value:actual"), ("fn:b", "value:formal")},
        )
        self.assertTrue(
            all(row["pointee_object_id"] == "obj:data" for row in references)
        )

    def test_shared_object_admission_merges_callsites(self) -> None:
        base = {
            "object_id": "obj:queue",
            "base_object_id": "obj:queue",
            "region": {"object_id": "obj:queue", "offset": 4, "extent": 4},
            "storage_kind": "STATIC_WRITABLE_DATA",
            "transfer_semantics": "OBJECT_REFERENCE",
            "source_lineage_ids": ["source-definition:1"],
            "source_ids": ["SO1"],
            "recognition": "heuristic",
            "analysis_precision": "MAY",
            "readers": [
                {
                    "edge_id": "read:1",
                    "function_id": "fn:reader",
                    "site_id": "site:read",
                }
            ],
        }
        result = shared_object_miner.mine_shared_objects(
            [
                {
                    **base,
                    "candidate_id": "candidate:1",
                    "writers": [
                        {
                            "edge_id": "write:1",
                            "function_id": "fn:writer1",
                            "site_id": "site:write1",
                        }
                    ],
                },
                {
                    **base,
                    "candidate_id": "candidate:2",
                    "writers": [
                        {
                            "edge_id": "write:2",
                            "function_id": "fn:writer2",
                            "site_id": "site:write2",
                        }
                    ],
                },
            ]
        )
        self.assertEqual(len(result["shared_objects"]), 1)
        shared = result["shared_objects"][0]
        self.assertEqual(len(shared["writers"]), 2)
        self.assertEqual(
            {
                edge["edge_kind"]
                for edge in shared_object_miner.materialize_channel_edges(
                    result["shared_objects"]
                )
            },
            {"CHANNEL_WRITE", "CHANNEL_READ"},
        )

    def test_stack_local_is_not_admitted(self) -> None:
        result = shared_object_miner.mine_shared_objects(
            [
                {
                    "candidate_id": "candidate:stack",
                    "object_id": "obj:stack",
                    "storage_kind": "STACK_LOCAL",
                    "transfer_semantics": "MEMORY_CONTENT",
                    "source_lineage_ids": ["source-definition:1"],
                    "writers": [{"site_id": "site:w"}],
                    "readers": [{"site_id": "site:r"}],
                }
            ]
        )
        self.assertEqual(result["shared_objects"], [])
        self.assertIn(
            "source_derived_stack_local_not_shared",
            {row["reason"] for row in result["blockers"]},
        )


if __name__ == "__main__":
    unittest.main()
