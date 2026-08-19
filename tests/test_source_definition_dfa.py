from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_sink_backward_dfa as dfa  # noqa: E402


def empty_graph() -> dict:
    return {"object_nodes": [], "channel_edges": [], "call_edges": []}


class SourceDefinitionDfaTests(unittest.TestCase):
    def test_load_address_closes_to_prior_source_buffer_definition(self) -> None:
        target = {
            "value_id": "const:target",
            "object_id": "const:target",
            "space": "const",
            "is_constant": True,
        }
        space = {
            "value_id": "const:space",
            "object_id": "const:space",
            "space": "const",
            "is_constant": True,
        }
        buffer = {
            "value_id": "value:rx-buffer",
            "object_id": "global:20000000",
            "space": "ram",
            "offset": "0x20000000",
            "size": 4,
            "is_address": True,
            "is_constant": False,
        }
        loaded = {
            "value_id": "value:loaded-byte",
            "object_id": "reg:consumer:0",
            "space": "register",
            "size": 1,
            "is_constant": False,
        }
        facts = {
            "functions": [
                {
                    "function_id": "fn:consumer",
                    "name": "consumer",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:receive",
                            "mnemonic": "CALL",
                            "inputs": [target, buffer],
                            "call": {"target_function_id": "fn:receive"},
                        },
                        {
                            "site_id": "site:load",
                            "mnemonic": "LOAD",
                            "output": loaded,
                            "inputs": [space, buffer],
                        },
                        {
                            "site_id": "site:sink",
                            "mnemonic": "CALL",
                            "inputs": [target, loaded],
                            "call": {"target_function_id": "fn:sink"},
                        },
                    ],
                }
            ]
        }
        sources = {
            "source_sites": [
                {
                    "id": "SO_RECEIVE_BUFFER",
                    "function_id": "fn:consumer",
                    "site_id": "site:receive",
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ],
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:receive-buffer",
                    "source_id": "SO_RECEIVE_BUFFER",
                    "function_id": "fn:consumer",
                    "site_id": "site:receive",
                    "decision": "ACCEPT_DETERMINISTIC",
                    "outputs": [
                        {
                            "kind": "memory_object",
                            "object_id": "global:20000000",
                            "value_id": "value:rx-buffer",
                            "binding_status": "exact_call_actual",
                        }
                    ],
                    "proof": {
                        "kind": "software_interface_summary_instantiation",
                        "call_site_id": "site:receive",
                        "callee_function_id": "fn:receive",
                    },
                }
            ],
        }
        sink = {
            "id": "SINK_VALUE",
            "function_id": "fn:consumer",
            "site_id": "site:sink",
            "vulnerable_parameters": [{"role": "len", "index": 0}],
        }
        graph = empty_graph()
        index = dfa.ProgramIndex(facts, graph, strict=True)

        chain = dfa.analyze_sink(
            sink,
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=32,
        )

        self.assertEqual(chain["status"], "SOURCE_REACHED_DETERMINISTIC")
        self.assertEqual(
            [
                step["kind"]
                for step in chain["parameter_results"][0]["paths"][0]["path"]
            ],
            ["LOAD_ADDRESS", "SOURCE_MEMORY_DEFINITION"],
        )

    def test_local_receive_call_memory_definition_reaches_later_sink_use(self) -> None:
        target = {
            "value_id": "const:target",
            "object_id": "const:target",
            "space": "const",
            "is_constant": True,
        }
        buffer = {
            "value_id": "value:rx-buffer",
            "object_id": "global:20000000",
            "space": "ram",
            "offset": "0x20000000",
            "size": 4,
            "is_address": True,
            "is_constant": False,
        }
        facts = {
            "functions": [
                {
                    "function_id": "fn:consumer",
                    "name": "consumer",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:receive",
                            "mnemonic": "CALL",
                            "inputs": [target, buffer],
                            "call": {"target_function_id": "fn:receive"},
                        },
                        {
                            "site_id": "site:sink",
                            "mnemonic": "CALL",
                            "inputs": [target, buffer],
                            "call": {"target_function_id": "fn:sink"},
                        },
                    ],
                }
            ]
        }
        sources = {
            "source_sites": [
                {
                    "id": "SO_RECEIVE_BUFFER",
                    "function_id": "fn:consumer",
                    "function": "consumer",
                    "site_id": "site:receive",
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ],
            "source_definitions": [
                {
                    "source_definition_id": "source-definition:receive-buffer",
                    "source_id": "SO_RECEIVE_BUFFER",
                    "function_id": "fn:consumer",
                    "site_id": "site:receive",
                    "decision": "ACCEPT_DETERMINISTIC",
                    "outputs": [
                        {
                            "kind": "memory_object",
                            "object_id": "global:20000000",
                            "value_id": "value:rx-buffer",
                            "binding_status": "exact_call_actual",
                        }
                    ],
                    "proof": {
                        "kind": "software_interface_summary_instantiation",
                        "call_site_id": "site:receive",
                        "callee_function_id": "fn:receive",
                    },
                }
            ],
        }
        sink = {
            "id": "SINK_BUFFER",
            "function_id": "fn:consumer",
            "site_id": "site:sink",
            "vulnerable_parameters": [{"role": "src", "index": 0}],
        }
        graph = empty_graph()
        index = dfa.ProgramIndex(facts, graph, strict=True)

        chain = dfa.analyze_sink(
            sink,
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=32,
        )

        self.assertEqual(chain["status"], "SOURCE_REACHED_DETERMINISTIC")
        self.assertEqual(
            chain["parameter_results"][0]["paths"][0]["path"][-1]["kind"],
            "SOURCE_MEMORY_DEFINITION",
        )

        clobbered_facts = {"functions": [{**facts["functions"][0]}]}
        clobbered_facts["functions"][0]["pcode_ops"] = list(
            facts["functions"][0]["pcode_ops"]
        )
        clobbered_facts["functions"][0]["pcode_ops"].insert(
            1,
            {
                "site_id": "site:clobber",
                "mnemonic": "STORE",
                "inputs": [target, buffer, target],
            },
        )
        clobbered_index = dfa.ProgramIndex(clobbered_facts, graph, strict=True)
        clobbered = dfa.analyze_sink(
            sink,
            clobbered_index,
            *dfa.source_index(sources, graph, index=clobbered_index),
            max_steps=32,
        )
        self.assertEqual(clobbered["status"], "GRAPH_INCOMPLETE")

    def test_exact_scalar_definition_overrides_legacy_bindings(self) -> None:
        artifact = {
            "source_sites": [
                {
                    "id": "SO_SCALAR",
                    "label": "SCALAR_SOURCE",
                    "source_value_id": "value:stale",
                    "source_object_id": "obj:stale",
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ],
            "source_definitions": [
                {
                    "source_id": "SO_SCALAR",
                    "outputs": [
                        {
                            "kind": "scalar_value",
                            "value_id": "value:exact",
                            "object_id": "obj:not-a-scalar-binding",
                        }
                    ],
                }
            ],
        }
        graph = empty_graph()
        graph["object_nodes"] = [
            {
                "object_id": "obj:stale-overlay",
                "source_evidence_ids": ["SO_SCALAR"],
            }
        ]

        by_value, by_object = dfa.source_index(artifact, graph)

        self.assertEqual([row["id"] for row in by_value["value:exact"]], ["SO_SCALAR"])
        self.assertNotIn("value:stale", by_value)
        self.assertNotIn("obj:not-a-scalar-binding", by_object)
        self.assertNotIn("obj:stale", by_object)
        self.assertNotIn("obj:stale-overlay", by_object)

        result = dfa.trace_parameter(
            {"role": "len", "value_id": "value:exact", "object_id": ""},
            dfa.ProgramIndex({"functions": []}, graph),
            by_value,
            by_object,
            max_steps=10,
        )
        self.assertEqual(result["status"], "SOURCE_REACHED_DETERMINISTIC")
        self.assertEqual(result["paths"][0]["path"], [])

    def test_memory_definition_requires_an_explicit_write_path(self) -> None:
        artifact = {
            "source_sites": [
                {
                    "id": "SO_MEMORY",
                    "label": "MEMORY_SOURCE",
                    "source_value_id": "value:buffer-pointer",
                    "source_object_id": "obj:legacy-buffer",
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ],
            "source_definitions": [
                {
                    "source_id": "SO_MEMORY",
                    "outputs": [
                        {
                            "kind": "memory_object",
                            "value_id": "value:buffer-pointer",
                            "object_id": "obj:rx-buffer",
                        }
                    ],
                }
            ],
        }
        graph = empty_graph()
        by_value, by_object = dfa.source_index(artifact, graph)

        self.assertNotIn("value:buffer-pointer", by_value)
        self.assertNotIn("obj:legacy-buffer", by_object)
        self.assertEqual(by_object["obj:rx-buffer"][0]["id"], "SO_MEMORY")

        pointer_only = dfa.trace_parameter(
            {
                "role": "src",
                "value_id": "value:buffer-pointer",
                "object_id": "obj:rx-buffer",
            },
            dfa.ProgramIndex({"functions": []}, graph),
            by_value,
            by_object,
            max_steps=10,
        )
        self.assertEqual(pointer_only["status"], "GRAPH_INCOMPLETE")
        self.assertEqual(pointer_only["paths"], [])

        graph["channel_edges"] = [
            {
                "edge_id": "channel:source-write",
                "edge_kind": "OBJECT_WRITE",
                "site_id": "site:source-write",
                "object_id": "obj:rx-buffer",
                "value_id": "value:buffer-pointer",
                "value_object_id": "obj:rx-buffer",
                "source_id": "SO_MEMORY",
            }
        ]
        reached = dfa.trace_parameter(
            {"role": "src", "value_id": "value:sink", "object_id": "obj:rx-buffer"},
            dfa.ProgramIndex({"functions": []}, graph),
            by_value,
            by_object,
            max_steps=10,
        )
        self.assertEqual(reached["status"], "SOURCE_REACHED_DETERMINISTIC")
        self.assertEqual(
            [edge["kind"] for edge in reached["paths"][0]["path"]],
            ["CHANNEL_WRITE_PREDECESSOR"],
        )

    def test_legacy_source_rows_remain_compatible(self) -> None:
        artifact = {
            "source_sites": [
                {
                    "id": "SO_LEGACY",
                    "label": "LEGACY_SOURCE",
                    "source_value_id": "value:legacy",
                    "source_object_id": "obj:legacy",
                    "decision": "ACCEPT_HEURISTIC",
                }
            ]
        }
        graph = empty_graph()

        by_value, by_object = dfa.source_index(artifact, graph)

        self.assertEqual(by_value["value:legacy"][0]["id"], "SO_LEGACY")
        self.assertEqual(by_object["obj:legacy"][0]["id"], "SO_LEGACY")
        result = dfa.trace_parameter(
            {"role": "value", "value_id": "value:legacy", "object_id": ""},
            dfa.ProgramIndex({"functions": []}, graph),
            by_value,
            by_object,
            max_steps=10,
        )
        self.assertEqual(result["status"], "SOURCE_REACHED_HEURISTIC")

    def test_invalid_and_unbound_definitions_are_ignored(self) -> None:
        artifact = {
            "source_sites": [
                {
                    "id": "SO_FALLBACK",
                    "source_value_id": "value:fallback",
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ],
            "source_definitions": [
                None,
                {
                    "source_id": "SO_UNKNOWN",
                    "outputs": [
                        {
                            "kind": "scalar_value",
                            "value_id": "value:unbound",
                            "object_id": "",
                        }
                    ],
                },
                {"source_id": "SO_FALLBACK", "outputs": "not-a-list"},
                {
                    "source_id": "SO_FALLBACK",
                    "outputs": [
                        {"kind": "scalar_value", "value_id": "", "object_id": ""},
                        {
                            "kind": "memory_object",
                            "value_id": "value:invalid-pointer",
                            "object_id": "",
                        },
                        {
                            "kind": "unknown_kind",
                            "value_id": "value:invalid-kind",
                            "object_id": "obj:invalid-kind",
                        },
                    ],
                },
            ],
        }

        by_value, by_object = dfa.source_index(artifact, empty_graph())

        self.assertEqual(by_value["value:fallback"][0]["id"], "SO_FALLBACK")
        self.assertNotIn("value:unbound", by_value)
        self.assertNotIn("value:invalid-pointer", by_value)
        self.assertNotIn("value:invalid-kind", by_value)
        self.assertNotIn("obj:invalid-kind", by_object)


if __name__ == "__main__":
    unittest.main()
