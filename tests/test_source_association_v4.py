from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import memory_access_facts  # noqa: E402
import source_association  # noqa: E402


class EmptyRuntime:
    def resolve(self, node: dict, function_id: str) -> dict | None:
        return None


class MappingRuntime:
    def __init__(self, bindings: dict[str, dict]) -> None:
        self.bindings = bindings

    def resolve(self, node: dict, function_id: str) -> dict | None:
        return self.bindings.get(str(node.get("value_id", "")))


def value(value_id: str, *, constant: bool = False) -> dict:
    return {
        "value_id": value_id,
        "object_id": value_id,
        "size": 4,
        "is_constant": constant,
    }


class SourceAssociationV4Tests(unittest.TestCase):
    def test_source_memory_output_crosses_proved_primitive_copy(self) -> None:
        functions = [
            {
                "function_id": "fn:producer",
                "parameters": [
                    {
                        **value("value:source-buffer"),
                        "high_data_type": "uint8_t *",
                    }
                ],
                "pcode_ops": [],
            }
        ]
        runtime = MappingRuntime(
            {
                "value:source-buffer": {
                    "object_id": "obj:stack:rx",
                    "root_object_id": "obj:stack:rx",
                    "storage_kind": "STACK_LOCAL",
                    "precision": "EXACT",
                }
            }
        )
        rows, blockers = source_association.build_source_associations(
            {"functions": functions},
            {
                "source_definitions": [
                    {
                        "source_definition_id": "source-definition:1",
                        "source_id": "SO1",
                        "function_id": "fn:producer",
                        "site_id": "site:receive",
                        "decision": "ACCEPT_DETERMINISTIC",
                        "outputs": [
                            {
                                "kind": "memory_object",
                                "value_id": "value:source-buffer",
                                "object_id": "pointee:value:source-buffer",
                                "binding_status": "exact_call_actual",
                            }
                        ],
                    }
                ]
            },
            value_provenance={},
            channel_edges=[],
            runtime=runtime,
            primitive_memory_effects=[
                {
                    "effect_id": "effect:copy",
                    "effect_kind": "PRIMITIVE_MEMORY_COPY",
                    "function_id": "fn:producer",
                    "site_id": "site:copy",
                    "effect_precision": "MAY_REGION",
                    "source": {
                        "object_id": "obj:stack:rx",
                        "base_object_id": "obj:stack:rx",
                        "atom_id": "value:copy-src",
                    },
                    "destination": {
                        "object_id": "obj:heap-field:payload",
                        "base_object_id": "obj:allocation:packet",
                        "atom_id": "value:copy-dst",
                    },
                }
            ],
        )

        self.assertEqual(blockers, [])
        self.assertTrue(
            any(
                row["state_kind"] == "MEMORY_CONTENT"
                and row["object_id"] == "obj:stack:rx"
                and row["relation_kind"]
                == "SOURCE_DEFINITION_MEMORY_OUTPUT"
                for row in rows
            )
        )
        copied = [
            row
            for row in rows
            if row["object_id"] == "obj:heap-field:payload"
        ]
        self.assertEqual(len(copied), 1)
        self.assertEqual(
            copied[0]["relation_kind"], "PROVED_PRIMITIVE_MEMORY_EFFECT"
        )
        self.assertEqual(
            copied[0]["region"]["base_object_id"],
            "obj:allocation:packet",
        )

    def test_explicit_value_flow_reaches_concrete_store(self) -> None:
        functions = [
            {
                "function_id": "fn:a",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:copy",
                        "mnemonic": "COPY",
                        "inputs": [value("value:source")],
                        "output": value("value:copied"),
                    }
                ],
            }
        ]
        access = memory_access_facts.MemoryAccessFactIndex.from_exact_edges(
            [
                {
                    "edge_id": "access:write",
                    "edge_kind": "OBJECT_WRITE",
                    "site_id": "site:store",
                    "function_id": "fn:a",
                    "object_id": "obj:ram:20000000",
                    "base_object_id": "obj:ram:20000000",
                    "value_id": "value:copied",
                    "access_width": 4,
                    "region_offset": 0,
                    "region_extent": 4,
                    "candidate_class": "EXACT_HIGH_PCODE_MEMORY_ACCESS",
                }
            ],
            [
                {
                    "object_id": "obj:ram:20000000",
                    "storage_kind": "ABSOLUTE_SRAM",
                }
            ],
        )
        rows, blockers = source_association.build_source_associations(
            {"functions": functions},
            {
                "source_definitions": [
                    {
                        "source_definition_id": "source-definition:1",
                        "source_id": "SO1",
                    }
                ]
            },
            value_provenance={
                ("fn:a", "value:source"): {
                    "source-definition:1": {"transfers": []}
                }
            },
            channel_edges=[],
            runtime=EmptyRuntime(),
            access_index=access,
        )

        self.assertEqual(blockers, [])
        self.assertTrue(
            any(
                row["state_kind"] == "MEMORY_CONTENT"
                and row["object_id"] == "obj:ram:20000000"
                and row["relation_kind"] == "CONCRETE_STORE_VALUE"
                for row in rows
            )
        )

    def test_control_dependence_does_not_associate_constant_store(self) -> None:
        functions = [
            {
                "function_id": "fn:a",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:branch",
                        "mnemonic": "CBRANCH",
                        "inputs": [value("value:target", constant=True), value("value:source")],
                        "output": None,
                    }
                ],
            }
        ]
        access = memory_access_facts.MemoryAccessFactIndex.from_exact_edges(
            [
                {
                    "edge_id": "access:write",
                    "edge_kind": "OBJECT_WRITE",
                    "site_id": "site:store",
                    "function_id": "fn:a",
                    "object_id": "obj:ram:20000000",
                    "base_object_id": "obj:ram:20000000",
                    "value_id": "const:1:4",
                    "access_width": 4,
                    "region_offset": 0,
                    "region_extent": 4,
                    "candidate_class": "EXACT_HIGH_PCODE_MEMORY_ACCESS",
                }
            ],
            [
                {
                    "object_id": "obj:ram:20000000",
                    "storage_kind": "ABSOLUTE_SRAM",
                }
            ],
        )
        rows, _ = source_association.build_source_associations(
            {"functions": functions},
            {
                "source_definitions": [
                    {
                        "source_definition_id": "source-definition:1",
                        "source_id": "SO1",
                    }
                ]
            },
            value_provenance={
                ("fn:a", "value:source"): {
                    "source-definition:1": {"transfers": []}
                }
            },
            channel_edges=[],
            runtime=EmptyRuntime(),
            access_index=access,
        )

        self.assertFalse(
            any(row["state_kind"] == "MEMORY_CONTENT" for row in rows)
        )

    def test_object_reference_does_not_cross_comparison(self) -> None:
        functions = [
            {
                "function_id": "fn:a",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:compare",
                        "mnemonic": "INT_EQUAL",
                        "inputs": [
                            value("value:pointer"),
                            value("const:null", constant=True),
                        ],
                        "output": value("value:is_null"),
                    }
                ],
            }
        ]
        rows, blockers = source_association.build_source_associations(
            {"functions": functions},
            {
                "source_definitions": [
                    {
                        "source_definition_id": "source-definition:1",
                        "source_id": "SO1",
                    }
                ]
            },
            value_provenance={},
            channel_edges=[],
            runtime=EmptyRuntime(),
            seed_associations=[
                {
                    "source_definition_id": "source-definition:1",
                    "source_id": "SO1",
                    "state_kind": "OBJECT_REFERENCE",
                    "function_id": "fn:a",
                    "atom_id": "value:pointer",
                    "pointee_object_id": "obj:source-buffer",
                    "relation_kind": "TEST_REFERENCE_SEED",
                    "precision": "EXACT",
                }
            ],
        )

        self.assertEqual(blockers, [])
        self.assertFalse(
            any(
                row["state_kind"] == "OBJECT_REFERENCE"
                and row["atom_id"] == "value:is_null"
                for row in rows
            )
        )

    def test_object_reference_crosses_pointer_arithmetic_from_base(self) -> None:
        functions = [
            {
                "function_id": "fn:a",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:ptradd",
                        "mnemonic": "PTRADD",
                        "inputs": [
                            value("value:pointer"),
                            value("value:index"),
                            value("const:stride", constant=True),
                        ],
                        "output": value("value:element_pointer"),
                    }
                ],
            }
        ]
        rows, blockers = source_association.build_source_associations(
            {"functions": functions},
            {
                "source_definitions": [
                    {
                        "source_definition_id": "source-definition:1",
                        "source_id": "SO1",
                    }
                ]
            },
            value_provenance={},
            channel_edges=[],
            runtime=EmptyRuntime(),
            seed_associations=[
                {
                    "source_definition_id": "source-definition:1",
                    "source_id": "SO1",
                    "state_kind": "OBJECT_REFERENCE",
                    "function_id": "fn:a",
                    "atom_id": "value:pointer",
                    "pointee_object_id": "obj:source-buffer",
                    "relation_kind": "TEST_REFERENCE_SEED",
                    "precision": "EXACT",
                }
            ],
        )

        self.assertEqual(blockers, [])
        derived = [
            row
            for row in rows
            if row["state_kind"] == "OBJECT_REFERENCE"
            and row["atom_id"] == "value:element_pointer"
        ]
        self.assertEqual(len(derived), 1)
        self.assertEqual(derived[0]["pointee_object_id"], "obj:source-buffer")
        self.assertEqual(derived[0]["relation_kind"], "SSA_PTRADD")

    def test_ninth_channel_hop_is_blocked_not_dropped(self) -> None:
        seeds = source_association.channel_relation_seeds(
            [
                {
                    "edge_id": "channel:read",
                    "edge_kind": "CHANNEL_READ",
                    "dst_node_id": "fn:b",
                    "site_id": "site:read",
                    "loaded_atom_id": "value:loaded",
                    "transfer_semantics": "MEMORY_CONTENT",
                    "source_lineage_ids": ["source-definition:1"],
                    "source_ids": ["SO1"],
                    "channel_depth": 8,
                }
            ]
        )
        rows, blockers = source_association.build_source_associations(
            {"functions": []},
            {
                "source_definitions": [
                    {
                        "source_definition_id": "source-definition:1",
                        "source_id": "SO1",
                    }
                ]
            },
            value_provenance={},
            channel_edges=[],
            runtime=EmptyRuntime(),
            seed_associations=seeds,
            max_channel_depth=8,
        )

        self.assertEqual(rows, [])
        self.assertIn(
            "source_association_channel_depth_limit_reached",
            {row["reason"] for row in blockers},
        )


if __name__ == "__main__":
    unittest.main()
