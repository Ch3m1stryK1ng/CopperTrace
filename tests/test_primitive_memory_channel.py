from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_channel_graph_v2 as channel  # noqa: E402
import run_sink_backward_dfa as dfa  # noqa: E402


def value(
    value_id: str,
    object_id: str,
    *,
    space: str = "register",
    high_name: str = "",
) -> dict:
    return {
        "value_id": value_id,
        "object_id": object_id,
        "space": space,
        "offset": "0x0",
        "size": 4,
        "is_constant": False,
        "is_address": False,
        "def_site_id": "",
        "high_name": high_name,
    }


class PrimitiveMemoryChannelTests(unittest.TestCase):
    def test_constant_copy_defines_overlapping_stack_value(self) -> None:
        frame_id = "fn:1000"
        ptr = value("value:dst", "reg:dst")
        ptr["def_site_id"] = "site:1000:1004:1"
        src = {
            **value("value:src", "global:20000000:4", space="ram"),
            "offset": "0x20000000",
            "is_address": True,
        }
        two = {
            "value_id": "const:2:4",
            "object_id": "const:2:4",
            "space": "const",
            "offset": "0x2",
            "size": 4,
            "is_constant": True,
        }
        target = {**two, "value_id": "const:2000:4", "object_id": "const:2000:4", "offset": "0x2000"}
        ptrsub = {
            "site_id": "site:1000:1004:1",
            "instruction_address": "0x1004",
            "mnemonic": "PTRSUB",
            "output": ptr,
            "inputs": [
                value("value:sp", "reg:sp"),
                {
                    **two,
                    "value_id": "const:ffffffdc:4",
                    "object_id": "const:ffffffdc:4",
                    "offset": "0xffffffdc",
                    "high_name": "parsed_header",
                },
            ],
        }
        call = {
            "site_id": "site:1000:1008:2",
            "instruction_address": "0x1008",
            "mnemonic": "CALL",
            "output": None,
            "inputs": [target, ptr, src, two],
            "call": {"target_function": "memcpy", "target_function_id": "fn:2000"},
        }
        indirect_output = {
            **value(
                "value:stack-after",
                "stack:1000:-24:4",
                space="stack",
                high_name="parsed_header",
            ),
            "offset": "0x-24",
            "size": 4,
        }
        indirect = {
            "site_id": "site:1000:1008:3",
            "instruction_address": "0x1008",
            "mnemonic": "INDIRECT",
            "output": indirect_output,
            "inputs": [indirect_output, two],
        }
        facts = {
            "binary": "",
            "functions": [{"function_id": frame_id, "name": "decode", "pcode_ops": [ptrsub, call, indirect]}],
            "memory_blocks": [{"name": ".bss", "start": "0x20000000", "end": "0x200000ff", "write": True}],
            "symbols": [{"address": "0x20000000", "name": "packet", "source": "SYMBOL", "object_id": "global:20000000"}],
        }
        registry = {
            "primitive_sinks": {
                "memcpy": {
                    "kind": "primitive_memory_copy",
                    "dst_arg": 0,
                    "src_arg": 1,
                    "len_arg": 2,
                }
            }
        }
        effects, blockers = channel.primitive_memory_effects(
            facts, registry, channel.DataObjectResolver(facts)
        )
        self.assertEqual(blockers, [])
        self.assertEqual(len(effects), 1)
        self.assertEqual(
            effects[0]["memory_definition_atom_ids"], ["value:stack-after"]
        )
        self.assertEqual(effects[0]["source"]["object_id"], "obj:symbol:20000000:packet")
        self.assertEqual(
            effects[0]["destination"]["object_id"],
            "obj:stack-local:fn:1000:m24",
        )

    def test_distinct_stack_locals_do_not_share_one_frame_object(self) -> None:
        facts = {
            "binary": "",
            "memory_blocks": [],
            "symbols": [],
            "functions": [
                {
                    "function_id": "fn:1000",
                    "name": "decode",
                    "pcode_ops": [
                        {
                            "site_id": "site:a",
                            "mnemonic": "COPY",
                            "output": {
                                **value(
                                    "value:a",
                                    "stack:1000:-20:4",
                                    space="stack",
                                    high_name="header_a",
                                ),
                                "offset": "0x-20",
                                "def_site_id": "site:a",
                            },
                            "inputs": [],
                        },
                        {
                            "site_id": "site:b",
                            "mnemonic": "COPY",
                            "output": {
                                **value(
                                    "value:b",
                                    "stack:1000:-40:4",
                                    space="stack",
                                    high_name="header_b",
                                ),
                                "offset": "0x-40",
                                "def_site_id": "site:b",
                            },
                            "inputs": [],
                        },
                    ],
                }
            ],
        }
        bindings = channel.build_value_object_bindings(
            facts, channel.DataObjectResolver(facts)
        )
        by_value = {row["value_id"]: row["object_id"] for row in bindings}
        self.assertNotEqual(by_value["value:a"], by_value["value:b"])

    def test_source_derived_indexed_region_creates_channel_pair(self) -> None:
        packet = "obj:symbol:20000000:packet"
        slots = "obj:symbol:20001000:slots"
        selector = [{"selector_value_id": "value:index", "stride": 64}]

        def binding(object_id: str, offset: int, terms: list[dict]) -> dict:
            return {
                "atom_id": f"value:{object_id}:{offset}",
                "value_id": f"value:{object_id}:{offset}",
                "value_object_id": "reg:pointer",
                "object_id": object_id,
                "base_object_id": object_id,
                "storage_kind": "STATIC_WRITABLE_DATA",
                "region": {
                    "object_id": object_id,
                    "offset": offset,
                    "size": 1,
                    "selector_terms": terms,
                },
            }

        effects = [
            {
                "effect_id": "effect:write",
                "function_id": "fn:handler",
                "site_id": "site:write",
                "source": binding(packet, 0, []),
                "destination": binding(slots, 12, selector),
            },
            {
                "effect_id": "effect:read",
                "function_id": "fn:handler",
                "site_id": "site:read",
                "source": binding(slots, 12, selector),
                "destination": binding(packet, 0, []),
            },
        ]
        objects = [
            {"object_id": packet, "node_id": packet, "source_evidence_ids": ["SO1"]},
            {"object_id": slots, "node_id": slots, "source_evidence_ids": []},
        ]
        sources = {"source_sites": [{"id": "SO1", "decision": "ACCEPT_DETERMINISTIC"}]}
        edges, shared, blockers = channel.build_primitive_source_channels(
            effects, sources, objects
        )
        self.assertEqual(blockers, [])
        self.assertEqual(shared, {slots})
        self.assertEqual(
            {edge["edge_kind"] for edge in edges},
            {"CHANNEL_READ", "CHANNEL_WRITE"},
        )
        self.assertTrue(all(edge["analysis_precision"] == "MAY" for edge in edges))

    def test_reverse_bfs_can_cross_region_and_reenter_same_function(self) -> None:
        function_id = "fn:handler"
        object_id = "obj:shared"
        common = {
            "object_id": object_id,
            "analysis_precision": "MAY",
            "strict_admissible": True,
            "deterministic": False,
            "evidence_level": "BODY_PROVED_PRIMITIVE_COPY_REGION",
            "region": {"object_id": object_id, "offset": 0, "size": 1},
        }
        graph = {
            "nodes": [
                {"node_id": function_id, "node_kind": "FUNCTION"},
                {"node_id": object_id, "object_id": object_id, "node_kind": "SHARED_OBJECT"},
            ],
            "edges": [
                {**common, "edge_id": "read", "edge_kind": "CHANNEL_READ", "src_node_id": object_id, "dst_node_id": function_id},
                {**common, "edge_id": "write", "edge_kind": "CHANNEL_WRITE", "src_node_id": function_id, "dst_node_id": object_id},
            ],
        }
        unified = dfa.UnifiedGraph(
            {"functions": [{"function_id": function_id, "name": "handler", "pcode_ops": []}]},
            graph,
            strict=True,
            allow_may_channel=True,
        )
        result = unified.reverse_bfs(function_id, max_steps=16)
        self.assertTrue(
            any(
                trace["edge_kinds"] == ["CHANNEL_READ", "CHANNEL_WRITE"]
                for trace in result["candidate_traces"]
            )
        )

    def test_strict_alert_is_existential_over_vulnerable_parameters(self) -> None:
        self.assertEqual(
            dfa.chain_status(
                [
                    {"status": "SOURCE_REACHED_HEURISTIC"},
                    {"status": "GRAPH_INCOMPLETE"},
                ],
                strict=True,
            ),
            "SOURCE_REACHED_HEURISTIC",
        )


if __name__ == "__main__":
    unittest.main()
