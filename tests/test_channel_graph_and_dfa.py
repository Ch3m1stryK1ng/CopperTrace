from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_channel_graph_v2 as channel  # noqa: E402
import run_sink_backward_dfa as dfa  # noqa: E402


def node(
    object_id: str,
    value_id: str,
    *,
    space: str = "register",
    offset: str = "0x0",
    size: int = 1,
    constant: bool = False,
    address: bool = False,
) -> dict:
    return {
        "object_id": object_id,
        "value_id": value_id,
        "space": space,
        "offset": offset,
        "size": size,
        "is_constant": constant,
        "is_address": address,
        "is_parameter": False,
        "parameter_slot": None,
    }


def program_facts() -> dict:
    rx_object = node(
        "global:20000000:1", "value:rx-address", space="ram", offset="0x20000000", address=True
    )
    mmio_address = node(
        "const:40010000:4", "const:40010000:4", space="const", offset="0x40010000", constant=True
    )
    mmio_value = node("reg:isr:0", "value:mmio-byte")
    read_value = node("reg:main:0", "value:rx-byte")
    return {
        "binary": "/tmp/fixture.elf",
        "binary_sha256": "fixture",
        "image_base": "0x8000000",
        "language_id": "ARM:LE:32:Cortex",
        "memory_blocks": [
            {"name": ".text", "start": "0x8000000", "end": "0x8000fff", "read": True, "write": False, "execute": True},
            {"name": ".bss", "start": "0x20000000", "end": "0x200000ff", "read": True, "write": True, "execute": False},
        ],
        "symbols": [
            {
                "name": "rx_ring",
                "address": "0x20000000",
                "size": 256,
                "type": "Object",
                "object_id": "global:20000000",
            }
        ],
        "functions": [
            {
                "function_id": "fn:08000100",
                "name": "USART1_IRQHandler",
                "entry": "0x8000100",
                "is_interrupt_entry": True,
                "decompiled_c": "rx_ring[0] = UART->DR;",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:08000100:08000104:1",
                        "instruction_address": "0x8000104",
                        "mnemonic": "LOAD",
                        "output": mmio_value,
                        "inputs": [node("const:space", "const:space", constant=True), mmio_address],
                    },
                    {
                        "site_id": "site:08000100:08000108:2",
                        "instruction_address": "0x8000108",
                        "mnemonic": "STORE",
                        "output": None,
                        "inputs": [node("const:space2", "const:space2", constant=True), rx_object, mmio_value],
                    },
                ],
            },
            {
                "function_id": "fn:08000200",
                "name": "main",
                "entry": "0x8000200",
                "is_interrupt_entry": False,
                "decompiled_c": "x = rx_ring[0]; memcpy(dst, &x, len);",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:08000200:08000204:1",
                        "instruction_address": "0x8000204",
                        "mnemonic": "LOAD",
                        "output": read_value,
                        "inputs": [node("const:space3", "const:space3", constant=True), rx_object],
                    }
                ],
            },
        ],
    }


def sources() -> dict:
    return {
        "source_sites": [
            {
                "id": "SO1",
                "label": "ISR_MMIO_READ",
                "function": "USART1_IRQHandler",
                "site_id": "site:08000100:08000104:1",
                "source_value_id": "value:mmio-byte",
                "source_object_id": "",
                "decision": "ACCEPT_DETERMINISTIC",
            }
        ]
    }


class ChannelGraphAndDfaTests(unittest.TestCase):
    def build_graph(self) -> dict:
        facts = program_facts()
        mai, memory_map = channel.program_facts_to_mai(facts)
        legacy = channel.build_channel_graph(mai, [], memory_map, top_k=64, binary_sha256="fixture")
        exact_nodes, edges, calls = channel.build_exact_graph(facts)
        objects = channel.merge_legacy_objects(exact_nodes, legacy)
        source_edges = channel.add_source_overlays(
            objects, sources(), facts, channel.DataObjectResolver(facts)
        )
        edges.extend(source_edges)
        channel.classify_shared_objects(objects, edges)
        return {
            "object_nodes": objects,
            "channel_edges": edges,
            "call_edges": calls,
        }

    def test_cross_context_global_has_write_read_edges(self) -> None:
        graph = self.build_graph()
        self.assertEqual(
            {edge["edge_kind"] for edge in graph["channel_edges"]},
            {"OBJECT_WRITE", "OBJECT_READ"},
        )
        shared = [node for node in graph["object_nodes"] if node.get("shared_object")]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0]["identity_kind"], "ELF_OBJECT_SYMBOL_RANGE")

    def test_backward_dfa_crosses_channel_to_mmio_source(self) -> None:
        facts = program_facts()
        graph = self.build_graph()
        index = dfa.ProgramIndex(facts, graph)
        by_value, by_object = dfa.source_index(sources(), graph)
        result = dfa.trace_parameter(
            {"role": "src", "value_id": "value:rx-byte", "object_id": "reg:main:0"},
            index,
            by_value,
            by_object,
            max_steps=50,
        )
        self.assertEqual(result["status"], "SOURCE_REACHED_DETERMINISTIC")
        self.assertEqual(result["paths"][0]["source_id"], "SO1")
        self.assertTrue(
            any(edge["kind"] == "CHANNEL_WRITE_PREDECESSOR" for edge in result["paths"][0]["path"])
        )

    def test_cli_artifacts_are_json_serializable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "facts.json"
            path.write_text(json.dumps(program_facts()))
            self.assertTrue(path.exists())

    def test_chain_status_requires_all_dynamic_parameters_to_reach_source(self) -> None:
        results = [
            {"status": "SOURCE_REACHED_HEURISTIC"},
            {"status": "SOURCE_NOT_RESOLVED"},
        ]
        self.assertEqual(dfa.chain_status(results), "PARTIAL_SOURCE_REACHABILITY")
        self.assertEqual(
            dfa.vulnerability_status_for_chain("GRAPH_INCOMPLETE"),
            "analysis_inconclusive_graph_incomplete",
        )

    def test_source_index_reads_multiple_outputs_and_legacy_single_output(self) -> None:
        artifact = {
            "source_sites": [
                {
                    "id": "SO_MULTI",
                    "source_outputs": [
                        {
                            "kind": "memory_object",
                            "value_id": "value:buffer-pointer",
                            "object_id": "obj:buffer",
                        },
                        {
                            "kind": "scalar_value",
                            "value_id": "value:length",
                            "object_id": "",
                        },
                    ],
                    "decision": "ACCEPT_DETERMINISTIC",
                },
                {
                    "id": "SO_LEGACY",
                    "source_value_id": "value:legacy",
                    "source_object_id": "obj:legacy",
                    "decision": "ACCEPT_HEURISTIC",
                },
            ]
        }
        by_value, by_object = dfa.source_index(artifact)
        self.assertNotIn("value:buffer-pointer", by_value)
        self.assertEqual(by_value["value:length"][0]["id"], "SO_MULTI")
        self.assertEqual(by_value["value:legacy"][0]["id"], "SO_LEGACY")
        self.assertEqual(by_object["obj:buffer"][0]["id"], "SO_MULTI")
        self.assertEqual(by_object["obj:legacy"][0]["id"], "SO_LEGACY")

    def test_same_object_different_sources_cannot_close_with_empty_path(self) -> None:
        facts = {"functions": []}
        graph = {"object_nodes": [], "channel_edges": [], "call_edges": []}
        source_artifact = {
            "source_sites": [
                {
                    "id": "SO_A",
                    "source_object_id": "obj:shared",
                    "decision": "ACCEPT_DETERMINISTIC",
                },
                {
                    "id": "SO_B",
                    "source_object_id": "obj:shared",
                    "decision": "ACCEPT_HEURISTIC",
                },
            ]
        }
        by_value, by_object = dfa.source_index(source_artifact, graph)
        result = dfa.trace_parameter(
            {"role": "src", "value_id": "", "object_id": "obj:shared"},
            dfa.ProgramIndex(facts, graph),
            by_value,
            by_object,
            max_steps=20,
        )
        self.assertEqual(result["status"], "GRAPH_INCOMPLETE")
        self.assertEqual(result["paths"], [])
        self.assertIn("unmodeled_origin", result["blockers"])

    def test_local_alias_path_cannot_select_an_untraversed_object_producer(self) -> None:
        source_pointer = node("obj:shared", "value:source-pointer", size=4)
        sink_pointer = node("obj:shared", "value:sink-pointer", size=4)
        facts = {
            "functions": [
                {
                    "function_id": "fn:sink",
                    "name": "sink_fn",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:sink:copy",
                            "mnemonic": "COPY",
                            "output": sink_pointer,
                            "inputs": [source_pointer],
                        }
                    ],
                }
            ]
        }
        graph = {"object_nodes": [], "channel_edges": [], "call_edges": []}
        source_artifact = {
            "source_sites": [
                {
                    "id": "SO_OTHER_CONTEXT",
                    "source_outputs": [
                        {
                            "kind": "memory_object",
                            "value_id": "value:other-producer-pointer",
                            "object_id": "obj:shared",
                        }
                    ],
                    "decision": "ACCEPT_HEURISTIC",
                }
            ]
        }
        by_value, by_object = dfa.source_index(source_artifact, graph)

        result = dfa.trace_parameter(
            {"role": "src", "value_id": "value:sink-pointer", "object_id": "obj:shared"},
            dfa.ProgramIndex(facts, graph),
            by_value,
            by_object,
            max_steps=20,
        )

        self.assertEqual(result["status"], "GRAPH_INCOMPLETE")
        self.assertEqual(result["paths"], [])

    def test_value_object_binding_is_alias_only_until_writer_path_exists(self) -> None:
        facts = {"functions": []}
        source_artifact = {
            "source_sites": [
                {
                    "id": "SO_ALIAS",
                    "source_object_id": "obj:shared",
                    "source_value_id": "value:producer",
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ]
        }
        alias_only_graph = {
            "object_nodes": [],
            "call_edges": [],
            "channel_edges": [],
            "value_object_bindings": [
                {
                    "value_id": "value:sink",
                    "object_id": "obj:shared",
                    "binding_kind": "POINTER_VALUE_TO_OBJECT_ALIAS",
                }
            ],
        }
        alias_index = dfa.ProgramIndex(facts, alias_only_graph)
        self.assertEqual(alias_index.resolved_object_by_value["value:sink"], "obj:shared")
        by_value, by_object = dfa.source_index(source_artifact, alias_only_graph)
        alias_only = dfa.trace_parameter(
            {"role": "src", "value_id": "value:sink", "object_id": ""},
            alias_index,
            by_value,
            by_object,
            max_steps=20,
        )
        self.assertEqual(alias_only["status"], "GRAPH_INCOMPLETE")
        self.assertEqual(alias_only["paths"], [])

        producer_graph = dict(alias_only_graph)
        producer_graph["channel_edges"] = [
            {
                "edge_id": "channel:producer-write",
                "edge_kind": "OBJECT_WRITE",
                "site_id": "site:producer",
                "object_id": "obj:shared",
                "value_id": "value:producer",
                "value_object_id": "reg:producer:0",
                "source_id": "SO_ALIAS",
            }
        ]
        producer_index = dfa.ProgramIndex(facts, producer_graph)
        reached = dfa.trace_parameter(
            {"role": "src", "value_id": "value:sink", "object_id": ""},
            producer_index,
            by_value,
            by_object,
            max_steps=20,
        )
        self.assertEqual(reached["status"], "SOURCE_REACHED_DETERMINISTIC")
        self.assertEqual(
            [edge["kind"] for edge in reached["paths"][0]["path"]],
            ["CHANNEL_WRITE_PREDECESSOR"],
        )

    def test_conflicting_alias_bindings_do_not_select_first_object(self) -> None:
        graph = {
            "object_nodes": [],
            "call_edges": [],
            "channel_edges": [],
            "value_object_bindings": [
                {"value_id": "value:x", "object_id": "obj:a"},
                {"value_id": "value:x", "object_id": "obj:b"},
            ],
        }

        index = dfa.ProgramIndex({"functions": []}, graph)

        self.assertNotIn("value:x", index.resolved_object_by_value)

    def test_exact_source_value_can_close_without_object_path(self) -> None:
        graph = {"object_nodes": [], "channel_edges": [], "call_edges": []}
        source_artifact = {
            "source_sites": [
                {
                    "id": "SO_EXACT",
                    "source_outputs": [
                        {
                            "kind": "scalar_value",
                            "value_id": "value:exact",
                            "object_id": "obj:x",
                        }
                    ],
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ]
        }
        by_value, by_object = dfa.source_index(source_artifact, graph)
        result = dfa.trace_parameter(
            {"role": "value", "value_id": "value:exact", "object_id": "obj:x"},
            dfa.ProgramIndex({"functions": []}, graph),
            by_value,
            by_object,
            max_steps=20,
        )
        self.assertEqual(result["status"], "SOURCE_REACHED_DETERMINISTIC")
        self.assertEqual([path["source_id"] for path in result["paths"]], ["SO_EXACT"])

    def test_call_return_setter_getter_global_chain_reaches_source(self) -> None:
        global_address = node(
            "obj:global-state",
            "value:global-address",
            space="ram",
            offset="0x20000020",
            size=4,
            address=True,
        )
        source_value = node("reg:main:0", "value:source-return", size=4)
        sink_value = node("reg:main:1", "value:sink-len", size=4)
        setter_parameter = node("param:setter:0", "value:setter:param0", size=4)
        setter_parameter["is_parameter"] = True
        setter_parameter["parameter_slot"] = 0
        getter_load = node("reg:getter:0", "value:getter-load", size=4)
        return_address = node(
            "const:return", "const:return", space="const", constant=True, size=4
        )
        facts = {
            "functions": [
                {
                    "function_id": "fn:main",
                    "name": "main",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:main:receive",
                            "mnemonic": "CALL",
                            "output": source_value,
                            "inputs": [],
                            "call": {"target_function_id": "fn:receive"},
                        },
                        {
                            "site_id": "site:main:setter",
                            "mnemonic": "CALL",
                            "output": None,
                            "inputs": [return_address, source_value],
                            "call": {"target_function_id": "fn:setter"},
                        },
                        {
                            "site_id": "site:main:getter",
                            "mnemonic": "CALL",
                            "output": sink_value,
                            "inputs": [return_address],
                            "call": {"target_function_id": "fn:getter"},
                        },
                    ],
                },
                {
                    "function_id": "fn:setter",
                    "name": "set_state",
                    "parameters": [setter_parameter],
                    "pcode_ops": [
                        {
                            "site_id": "site:setter:store",
                            "mnemonic": "STORE",
                            "output": None,
                            "inputs": [return_address, global_address, setter_parameter],
                        }
                    ],
                },
                {
                    "function_id": "fn:getter",
                    "name": "get_state",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:getter:load",
                            "mnemonic": "LOAD",
                            "output": getter_load,
                            "inputs": [return_address, global_address],
                        },
                        {
                            "site_id": "site:getter:return",
                            "mnemonic": "RETURN",
                            "output": None,
                            "inputs": [return_address, getter_load],
                        },
                    ],
                },
                {
                    "function_id": "fn:receive",
                    "name": "receive",
                    "parameters": [],
                    "pcode_ops": [],
                },
            ]
        }
        graph = {
            "object_nodes": [],
            "call_edges": [
                {
                    "src_node_id": "fn:main",
                    "dst_node_id": "fn:setter",
                    "site_id": "site:main:setter",
                    "argument_value_ids": ["value:source-return"],
                    "argument_object_ids": ["reg:main:0"],
                    "resolved_argument_object_ids": [""],
                }
            ],
            "channel_edges": [
                {
                    "edge_id": "channel:setter-write",
                    "edge_kind": "OBJECT_WRITE",
                    "site_id": "site:setter:store",
                    "object_id": "obj:global-state",
                    "value_id": "value:setter:param0",
                    "value_object_id": "param:setter:0",
                }
            ],
        }
        source_artifact = {
            "source_sites": [
                {
                    "id": "SO_RECEIVE",
                    "source_outputs": [
                        {"value_id": "value:source-return", "object_id": "reg:main:0"}
                    ],
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ]
        }
        by_value, by_object = dfa.source_index(source_artifact, graph)
        result = dfa.trace_parameter(
            {"role": "len", "value_id": "value:sink-len", "object_id": "reg:main:1"},
            dfa.ProgramIndex(facts, graph),
            by_value,
            by_object,
            max_steps=50,
        )
        self.assertEqual(result["status"], "SOURCE_REACHED_DETERMINISTIC")
        path_kinds = [edge["kind"] for edge in result["paths"][0]["path"]]
        self.assertIn("CALL_RETURN", path_kinds)
        self.assertIn("CHANNEL_WRITE_PREDECESSOR", path_kinds)
        self.assertIn("ACTUAL_FORMAL", path_kinds)

    def test_unknown_leaf_and_budget_frontier_are_inconclusive(self) -> None:
        graph = {"object_nodes": [], "channel_edges": [], "call_edges": []}
        empty_sources = dfa.source_index({"source_sites": []}, graph)
        unknown = dfa.trace_parameter(
            {"role": "len", "value_id": "value:unknown", "object_id": ""},
            dfa.ProgramIndex({"functions": []}, graph),
            *empty_sources,
            max_steps=10,
        )
        self.assertEqual(unknown["status"], "GRAPH_INCOMPLETE")
        self.assertIn("unmodeled_origin", unknown["blockers"])

        first = node("reg:f:0", "value:first")
        second = node("reg:f:1", "value:second")
        facts = {
            "functions": [
                {
                    "function_id": "fn:f",
                    "name": "f",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:f:add",
                            "mnemonic": "INT_ADD",
                            "output": first,
                            "inputs": [second],
                        }
                    ],
                }
            ]
        }
        budgeted = dfa.trace_parameter(
            {"role": "len", "value_id": "value:first", "object_id": "reg:f:0"},
            dfa.ProgramIndex(facts, graph),
            *empty_sources,
            max_steps=1,
        )
        self.assertEqual(budgeted["status"], "GRAPH_INCOMPLETE")
        self.assertIn("analysis_budget_exhausted", budgeted["blockers"])
        self.assertEqual(
            budgeted["analysis_frontier"]["nodes"][0]["reason"],
            "analysis_budget_exhausted_before_visit",
        )

    def test_process_name_alone_is_not_a_task_entry(self) -> None:
        facts = {
            "functions": [
                {
                    "function_id": "fn:1",
                    "name": "main",
                    "pcode_ops": [
                        {
                            "mnemonic": "CALL",
                            "call": {"target_function_id": "fn:2"},
                        }
                    ],
                },
                {"function_id": "fn:2", "name": "process_exit", "pcode_ops": []},
                {"function_id": "fn:3", "name": "process_thread_radio", "pcode_ops": []},
            ]
        }
        contexts = channel.infer_execution_contexts(facts)
        self.assertEqual(contexts["fn:2"][0], {"ctx:main"})
        self.assertEqual(contexts["fn:3"][0], {"ctx:task:fn:3"})


if __name__ == "__main__":
    unittest.main()
