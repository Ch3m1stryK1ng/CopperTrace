from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import build_channel_graph_v2 as channel  # noqa: E402
import ccc_effect_resolver as ccc  # noqa: E402
import dataflow_objects  # noqa: E402
import run_sink_backward_dfa as dfa  # noqa: E402


def node(
    value_id: str,
    object_id: str,
    *,
    def_site_id: str = "",
    parameter_slot: int | None = None,
    data_type: str = "void *",
) -> dict:
    return {
        "value_id": value_id,
        "object_id": object_id,
        "space": "register",
        "offset": "0x20",
        "size": 4,
        "high_name": "",
        "high_data_type": data_type,
        "is_parameter": parameter_slot is not None,
        "parameter_slot": parameter_slot,
        "index": parameter_slot,
        "is_constant": False,
        "is_address": False,
        "def_site_id": def_site_id,
    }


def constant(value: int, *, data_type: str = "void *") -> dict:
    return {
        "value_id": f"const:{value:x}:4",
        "object_id": f"const:{value:x}:4",
        "space": "const",
        "offset": hex(value),
        "size": 4,
        "high_data_type": data_type,
        "is_constant": True,
        "is_parameter": False,
        "is_address": False,
        "def_site_id": "",
    }


def call(site: str, target: str, actuals: list[dict]) -> dict:
    return {
        "site_id": site,
        "mnemonic": "CALL",
        "output": None,
        "inputs": [constant(int(target.split(":")[-1], 16))] + actuals,
        "call": {"target_function_id": target},
    }


class DeferredCallbackChannelTests(unittest.TestCase):
    def fixture(self) -> dict:
        payload = node("value:producer-payload", "param:producer:0", parameter_slot=0)
        wrapper_payload = node("value:wrapper-payload", "param:wrapper:1", parameter_slot=1)
        handler_payload = node("value:handler-payload", "param:handler:0", parameter_slot=0)
        handler_field = node("value:handler-field", "unique:handler-field", def_site_id="site:field")
        terminal_queue = node("value:terminal-queue", "param:terminal:0", parameter_slot=0)
        terminal_payload = node("value:terminal-payload", "param:terminal:1", parameter_slot=1)
        queue = node("value:consumer-queue", "param:consumer:0", parameter_slot=0)
        dequeued = node(
            "value:dequeued", "reg:consumer:0", def_site_id="site:dequeue"
        )
        callback_field = node(
            "value:callback-field", "unique:callback-field", def_site_id="site:callback-field"
        )
        callback_target = node(
            "value:callback-target", "reg:consumer:1", def_site_id="site:load-callback"
        )
        dequeue = call("site:dequeue", "fn:6000", [queue])
        dequeue["output"] = dequeued
        return {
            "binary": "",
            "memory_blocks": [{"name": ".text", "start": "0x1000", "end": "0x4fff", "execute": True, "write": False}],
            "symbols": [],
            "functions": [
                {
                    "function_id": "fn:1000",
                    "entry": "0x1000",
                    "name": "f_a",
                    "parameters": [payload],
                    "pcode_ops": [
                        {
                            "site_id": "site:field",
                            "mnemonic": "PTRSUB",
                            "output": handler_field,
                            "inputs": [payload, constant(4)],
                        },
                        {
                            "site_id": "site:store-handler",
                            "mnemonic": "STORE",
                            "inputs": [constant(0), handler_field, constant(0x3001)],
                        },
                        call("site:submit", "fn:2000", [constant(3), payload]),
                    ],
                },
                {
                    "function_id": "fn:2000",
                    "entry": "0x2000",
                    "name": "f_b",
                    "parameters": [
                        node("value:queue-index", "param:wrapper:0", parameter_slot=0, data_type="uint32_t"),
                        wrapper_payload,
                    ],
                    "pcode_ops": [call("site:terminal", "fn:4000", [constant(0x5000), wrapper_payload])],
                },
                {
                    "function_id": "fn:3000",
                    "entry": "0x3000",
                    "name": "f_c",
                    "parameters": [handler_payload],
                    "pcode_ops": [],
                },
                {
                    "function_id": "fn:4000",
                    "entry": "0x4000",
                    "name": "f_d",
                    "parameters": [terminal_queue, terminal_payload],
                    "pcode_ops": [
                        call(
                            "site:mutate-container",
                            "fn:7000",
                            [terminal_queue, constant(0), terminal_payload],
                        )
                    ],
                },
                {
                    "function_id": "fn:5000",
                    "entry": "0x5000",
                    "name": "f_e",
                    "parameters": [queue],
                    "pcode_ops": [
                        dequeue,
                        {
                            "site_id": "site:callback-field",
                            "mnemonic": "PTRSUB",
                            "output": callback_field,
                            "inputs": [dequeued, constant(4)],
                        },
                        {
                            "site_id": "site:load-callback",
                            "mnemonic": "LOAD",
                            "output": callback_target,
                            "inputs": [constant(0), callback_field],
                        },
                        {
                            "site_id": "site:invoke-callback",
                            "mnemonic": "CALLIND",
                            "output": None,
                            "inputs": [callback_target],
                            "call": {"target_function_id": ""},
                        },
                    ],
                },
                {
                    "function_id": "fn:6000",
                    "entry": "0x6000",
                    "name": "f_f",
                    "parameters": [
                        node(
                            "value:dequeue-queue",
                            "param:dequeue:0",
                            parameter_slot=0,
                        )
                    ],
                    "pcode_ops": [
                        {
                            "site_id": "site:queue-load",
                            "mnemonic": "LOAD",
                            "output": node(
                                "value:queue-item",
                                "reg:dequeue:0",
                                def_site_id="site:queue-load",
                            ),
                            "inputs": [
                                constant(0),
                                node(
                                    "value:dequeue-queue",
                                    "param:dequeue:0",
                                    parameter_slot=0,
                                ),
                            ],
                        },
                        {
                            "site_id": "site:return-item",
                            "mnemonic": "RETURN",
                            "output": None,
                            "inputs": [
                                constant(0),
                                node(
                                    "value:queue-item",
                                    "reg:dequeue:0",
                                    def_site_id="site:queue-load",
                                ),
                            ],
                        },
                    ],
                },
                {"function_id": "fn:7000", "entry": "0x7000", "name": "f_g", "parameters": [], "pcode_ops": []},
            ],
        }

    def test_structural_callback_submission_builds_channel_pair(self) -> None:
        facts = self.fixture()
        resolver = channel.DataObjectResolver(facts)
        runtime = dataflow_objects.RuntimeObjectIndex(
            facts,
            static_object=resolver.object_from_node,
            stack_descriptor=resolver.stack_descriptor,
            stack_object_id=channel._stack_local_object_id,
        )
        nodes, edges, blockers = ccc.build_deferred_callback_channels(
            facts, runtime=runtime, literal_words={}
        )
        self.assertEqual(blockers, [])
        self.assertEqual(len(nodes), 1)
        self.assertEqual({edge["edge_kind"] for edge in edges}, {"CHANNEL_WRITE", "CHANNEL_READ"})
        read = next(edge for edge in edges if edge["edge_kind"] == "CHANNEL_READ")
        self.assertEqual(read["dst_node_id"], "fn:3000")
        self.assertEqual(read["value_atom_id"], "value:handler-payload")
        self.assertGreaterEqual(len(read["evidence"]["submission_chain"]), 2)
        self.assertEqual(
            read["evidence"]["enqueue_contract"]["terminal_call_site_id"],
            "site:mutate-container",
        )
        self.assertEqual(
            read["evidence"]["enqueue_contract"]["queue_parameter_slots"],
            [0],
        )
        self.assertEqual(
            read["evidence"]["dequeue_dispatch_consumers"][0][
                "callback_call_site_id"
            ],
            "site:invoke-callback",
        )

    def test_callback_store_without_dequeue_dispatch_is_not_a_channel(self) -> None:
        facts = self.fixture()
        facts["functions"] = [
            row
            for row in facts["functions"]
            if row["function_id"] not in {"fn:5000", "fn:6000"}
        ]
        resolver = channel.DataObjectResolver(facts)
        runtime = dataflow_objects.RuntimeObjectIndex(
            facts,
            static_object=resolver.object_from_node,
            stack_descriptor=resolver.stack_descriptor,
            stack_object_id=channel._stack_local_object_id,
        )

        nodes, edges, blockers = ccc.build_deferred_callback_channels(
            facts, runtime=runtime, literal_words={}
        )

        self.assertEqual(nodes, [])
        self.assertEqual(edges, [])
        self.assertIn(
            "callback_store_has_no_matching_dequeue_dispatch",
            {row["reason"] for row in blockers},
        )

    def test_reverse_bfs_and_rda_cross_the_same_channel_edges(self) -> None:
        facts = self.fixture()
        resolver = channel.DataObjectResolver(facts)
        runtime = dataflow_objects.RuntimeObjectIndex(
            facts,
            static_object=resolver.object_from_node,
            stack_descriptor=resolver.stack_descriptor,
            stack_object_id=channel._stack_local_object_id,
        )
        nodes, edges, _ = ccc.build_deferred_callback_channels(
            facts, runtime=runtime, literal_words={}
        )
        graph = {
            "nodes": [
                *[{"node_id": f["function_id"], "node_kind": "FUNCTION"} for f in facts["functions"]],
                *[{**node, "node_kind": "SHARED_OBJECT"} for node in nodes],
            ],
            "edges": edges,
            "value_object_bindings": [],
        }
        unified = dfa.UnifiedGraph(facts, graph, strict=True, allow_may_channel=True)
        search = unified.reverse_bfs("fn:3000", max_steps=16)
        self.assertTrue(
            any(
                trace["edge_kinds"] == ["CHANNEL_READ", "CHANNEL_WRITE"]
                for trace in search["candidate_traces"]
            )
        )

        sources = {
            "source_sites": [
                {
                    "id": "SO1",
                    "decision": "ACCEPT_DETERMINISTIC",
                    "source_outputs": [
                        {"kind": "scalar_value", "value_id": "value:producer-payload"}
                    ],
                }
            ]
        }
        index = dfa.ProgramIndex(
            facts, graph, strict=True, allow_may_channel=True
        )
        result = dfa.trace_parameter(
            {
                "role": "src",
                "value_id": "value:handler-payload",
                "object_id": "param:handler:0",
            },
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=16,
            graph_search=search,
        )
        self.assertEqual(result["status"], "SOURCE_REACHED_HEURISTIC")
        self.assertEqual(
            [step["kind"] for step in result["paths"][0]["path"]],
            ["CHANNEL_READ", "CHANNEL_WRITE_PREDECESSOR"],
        )


if __name__ == "__main__":
    unittest.main()
