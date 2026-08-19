from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_sink_backward_dfa as dfa  # noqa: E402
from function_effect_resolver import FunctionEffectResolver  # noqa: E402


def node(
    atom_id: str,
    object_id: str,
    *,
    parameter_slot: int | None = None,
    constant: bool = False,
    space: str = "register",
) -> dict:
    return {
        "atom_id": atom_id,
        "value_id": atom_id,
        "object_id": object_id,
        "space": "const" if constant else space,
        "is_constant": constant,
        "is_parameter": parameter_slot is not None,
        "parameter_slot": parameter_slot,
        "size": 4,
    }


TARGET = node("const:target", "const:target", constant=True)
SPACE = node("const:space", "const:space", constant=True)


def call(site: str, target: str, *, output: dict | None = None, args: list[dict] | None = None) -> dict:
    return {
        "site_id": site,
        "mnemonic": "CALL",
        "output": output,
        "inputs": [TARGET] + list(args or []),
        "call": {"target_function_id": target},
    }


class FunctionEffectResolverTests(unittest.TestCase):
    def test_ambiguous_indirect_target_is_not_summarized(self) -> None:
        result = node("value:result", "reg:caller:0")
        indirect = call("site:dispatch", "", output=result)
        indirect["mnemonic"] = "CALLIND"
        indirect["call"] = {}
        returned_a = node("value:return-a", "reg:a:0")
        returned_b = node("value:return-b", "reg:b:0")
        functions = {
            "fn:caller": {
                "function_id": "fn:caller",
                "pcode_ops": [indirect],
            },
            "fn:a": {
                "function_id": "fn:a",
                "pcode_ops": [
                    {
                        "site_id": "site:return-a",
                        "mnemonic": "RETURN",
                        "inputs": [TARGET, returned_a],
                    }
                ],
            },
            "fn:b": {
                "function_id": "fn:b",
                "pcode_ops": [
                    {
                        "site_id": "site:return-b",
                        "mnemonic": "RETURN",
                        "inputs": [TARGET, returned_b],
                    }
                ],
            },
        }
        calls = {
            "site:dispatch": [
                {"edge_id": "call:a", "dst_node_id": "fn:a"},
                {"edge_id": "call:b", "dst_node_id": "fn:b"},
            ]
        }
        resolver = FunctionEffectResolver(
            functions=functions,
            calls_by_site=calls,
            calls_to={},
            resolved_object_by_atom={},
            identity=dfa._identity,
            public_value=dfa._public_value_id,
            same_object=lambda left, right: left == right,
        )

        predecessors, blocker = resolver.return_predecessors(
            "fn:caller",
            indirect,
            call_depth=0,
            allowed_edge_ids={"call:a", "call:b"},
        )

        self.assertEqual(predecessors, [])
        self.assertEqual(blocker, "ambiguous_call_target")

    def test_body_derived_getter_setter_without_channel_edge_reaches_source(self) -> None:
        external = node("value:external", "reg:root:0")
        sink_value = node("value:sink", "reg:root:1")
        formal = node("value:formal", "param:mutator:0", parameter_slot=0)
        loaded = node("value:loaded", "reg:accessor:0")
        address = node("value:state-address", "obj:state", space="ram")
        facts = {
            "functions": [
                {
                    "function_id": "fn:root",
                    "name": "f_100",
                    "parameters": [],
                    "pcode_ops": [
                        call("site:source", "fn:external", output=external),
                        call("site:set", "fn:mutator", args=[external]),
                        call("site:get", "fn:accessor", output=sink_value),
                        call("site:sink", "fn:sink", args=[sink_value]),
                    ],
                },
                {
                    "function_id": "fn:mutator",
                    "name": "f_200",
                    "parameters": [formal],
                    "pcode_ops": [
                        {
                            "site_id": "site:store",
                            "mnemonic": "STORE",
                            "inputs": [SPACE, address, formal],
                        }
                    ],
                },
                {
                    "function_id": "fn:accessor",
                    "name": "f_300",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:load",
                            "mnemonic": "LOAD",
                            "output": loaded,
                            "inputs": [SPACE, address],
                        },
                        {
                            "site_id": "site:return",
                            "mnemonic": "RETURN",
                            "inputs": [TARGET, loaded],
                        },
                    ],
                },
                {"function_id": "fn:external", "name": "f_400", "parameters": [], "pcode_ops": []},
                {"function_id": "fn:sink", "name": "f_500", "parameters": [], "pcode_ops": []},
            ]
        }
        graph = {"object_nodes": [], "call_edges": [], "channel_edges": []}
        sources = {
            "source_sites": [
                {
                    "id": "SO_EXACT",
                    "source_outputs": [{"kind": "scalar_value", "value_id": "value:external"}],
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ]
        }
        sink = {
            "id": "K1",
            "function_id": "fn:root",
            "site_id": "site:sink",
            "vulnerable_parameters": [{"role": "len", "index": 0}],
        }
        index = dfa.ProgramIndex(facts, graph, strict=True)
        result = dfa.analyze_sink(
            sink,
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=64,
        )

        self.assertEqual(result["status"], "SOURCE_REACHED_DETERMINISTIC")
        kinds = [step["kind"] for step in result["parameter_results"][0]["paths"][0]["path"]]
        self.assertIn("CALL_RETURN", kinds)
        self.assertIn("FUNCTION_SUMMARY", kinds)
        self.assertIn("ACTUAL_FORMAL", kinds)

    def test_nested_wrapper_honors_function_depth(self) -> None:
        external = node("value:external", "reg:root:0")
        final_value = node("value:final", "reg:root:1")
        wrap_one_value = node("value:w1", "reg:w1:0")
        wrap_two_value = node("value:w2", "reg:w2:0")
        facts = {
            "functions": [
                {
                    "function_id": "fn:root",
                    "name": "f_a",
                    "parameters": [],
                    "pcode_ops": [
                        call("site:source", "fn:external", output=external),
                        call("site:wrapper", "fn:w1", output=final_value),
                        call("site:sink", "fn:sink", args=[final_value]),
                    ],
                },
                {
                    "function_id": "fn:w1",
                    "name": "f_b",
                    "parameters": [],
                    "pcode_ops": [
                        call("site:w1:call", "fn:w2", output=wrap_one_value),
                        {"site_id": "site:w1:return", "mnemonic": "RETURN", "inputs": [TARGET, wrap_one_value]},
                    ],
                },
                {
                    "function_id": "fn:w2",
                    "name": "f_c",
                    "parameters": [],
                    "pcode_ops": [
                        call("site:w2:call", "fn:external", output=wrap_two_value),
                        {"site_id": "site:w2:return", "mnemonic": "RETURN", "inputs": [TARGET, wrap_two_value]},
                    ],
                },
                {"function_id": "fn:external", "name": "f_d", "parameters": [], "pcode_ops": []},
                {"function_id": "fn:sink", "name": "f_e", "parameters": [], "pcode_ops": []},
            ]
        }
        graph = {"object_nodes": [], "call_edges": [], "channel_edges": []}
        sources = {
            "source_sites": [
                {
                    "id": "SO_EXTERNAL",
                    "source_outputs": [{"kind": "scalar_value", "value_id": "value:w2"}],
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ]
        }
        sink = {
            "id": "K2",
            "function_id": "fn:root",
            "site_id": "site:sink",
            "vulnerable_parameters": [{"role": "len", "index": 0}],
        }

        enough = dfa.ProgramIndex(facts, graph, strict=True, max_function_depth=3)
        reached = dfa.analyze_sink(
            sink,
            enough,
            *dfa.source_index(sources, graph, index=enough),
            max_steps=64,
        )
        self.assertEqual(reached["status"], "SOURCE_REACHED_DETERMINISTIC")

        shallow = dfa.ProgramIndex(facts, graph, strict=True, max_function_depth=1)
        incomplete = dfa.analyze_sink(
            sink,
            shallow,
            *dfa.source_index(sources, graph, index=shallow),
            max_steps=64,
        )
        self.assertEqual(incomplete["status"], "GRAPH_INCOMPLETE")
        self.assertIn(
            "function_resolution_depth_exhausted",
            incomplete["parameter_results"][0]["blockers"],
        )

    def test_nested_call_uses_exact_callsite_parameter_binding(self) -> None:
        external = node("value:external", "reg:root:0")
        final_value = node("value:final", "reg:root:1")
        outer_formal = node(
            "value:outer-formal", "param:outer:0", parameter_slot=0
        )
        inner_result = node("value:inner-result", "reg:outer:0")
        inner_formal = node(
            "value:inner-formal", "param:inner:0", parameter_slot=0
        )
        unrelated = node("value:unrelated", "reg:other:0")
        unrelated_result = node("value:unrelated-result", "reg:other:1")
        facts = {
            "functions": [
                {
                    "function_id": "fn:root",
                    "name": "f_root",
                    "parameters": [],
                    "pcode_ops": [
                        call("site:source", "fn:external", output=external),
                        call(
                            "site:outer",
                            "fn:outer",
                            output=final_value,
                            args=[external],
                        ),
                        call("site:sink", "fn:sink", args=[final_value]),
                    ],
                },
                {
                    "function_id": "fn:outer",
                    "name": "f_outer",
                    "parameters": [outer_formal],
                    "pcode_ops": [
                        call(
                            "site:inner",
                            "fn:inner",
                            output=inner_result,
                            args=[outer_formal],
                        ),
                        {
                            "site_id": "site:outer:return",
                            "mnemonic": "RETURN",
                            "inputs": [TARGET, inner_result],
                        },
                    ],
                },
                {
                    "function_id": "fn:inner",
                    "name": "f_inner",
                    "parameters": [inner_formal],
                    "pcode_ops": [
                        {
                            "site_id": "site:inner:return",
                            "mnemonic": "RETURN",
                            "inputs": [TARGET, inner_formal],
                        }
                    ],
                },
                {
                    "function_id": "fn:other",
                    "name": "f_other",
                    "parameters": [],
                    "pcode_ops": [
                        call("site:other-source", "fn:internal", output=unrelated),
                        call(
                            "site:other-inner",
                            "fn:inner",
                            output=unrelated_result,
                            args=[unrelated],
                        ),
                    ],
                },
                {
                    "function_id": "fn:external",
                    "name": "f_external",
                    "parameters": [],
                    "pcode_ops": [],
                },
                {
                    "function_id": "fn:internal",
                    "name": "f_internal",
                    "parameters": [],
                    "pcode_ops": [],
                },
                {
                    "function_id": "fn:sink",
                    "name": "f_sink",
                    "parameters": [],
                    "pcode_ops": [],
                },
            ]
        }
        graph = {"object_nodes": [], "call_edges": [], "channel_edges": []}
        sources = {
            "source_sites": [
                {
                    "id": "SO_EXTERNAL",
                    "source_outputs": [
                        {"kind": "scalar_value", "value_id": "value:external"}
                    ],
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ]
        }
        sink = {
            "id": "K_NESTED",
            "function_id": "fn:root",
            "site_id": "site:sink",
            "vulnerable_parameters": [{"role": "src", "index": 0}],
        }
        index = dfa.ProgramIndex(
            facts, graph, strict=True, max_function_depth=3
        )

        result = dfa.analyze_sink(
            sink,
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=64,
        )

        self.assertEqual(result["status"], "SOURCE_REACHED_DETERMINISTIC")
        path = result["parameter_results"][0]["paths"][0]["path"]
        actual_formal_sites = [
            step["site_id"] for step in path if step["kind"] == "ACTUAL_FORMAL"
        ]
        self.assertIn("site:inner", actual_formal_sites)
        self.assertIn("site:outer", actual_formal_sites)
        self.assertNotIn("site:other-inner", actual_formal_sites)
        self.assertNotIn(
            "candidate_trace_excludes_call_binding",
            result["parameter_results"][0]["blockers"],
        )

    def test_exact_source_memory_output_is_an_explicit_source_write(self) -> None:
        pointer = node("value:buffer", "reg:producer:0")
        sink_pointer = node("value:sink-buffer", "reg:consumer:0")
        facts = {
            "functions": [
                {
                    "function_id": "fn:producer",
                    "name": "f_p",
                    "parameters": [],
                    "pcode_ops": [call("site:receive", "fn:rx", args=[pointer])],
                },
                {
                    "function_id": "fn:consumer",
                    "name": "f_c",
                    "parameters": [],
                    "pcode_ops": [call("site:sink", "fn:sink", args=[sink_pointer])],
                },
            ]
        }
        graph = {
            "object_nodes": [],
            "call_edges": [],
            "channel_edges": [],
            "value_object_bindings": [
                {"value_id": "value:buffer", "object_id": "obj:shared"},
                {"value_id": "value:sink-buffer", "object_id": "obj:shared"},
            ],
        }
        sources = {
            "source_sites": [
                {"id": "SO_BUFFER", "site_id": "site:receive", "decision": "ACCEPT_DETERMINISTIC"}
            ],
            "source_definitions": [
                {
                    "source_definition_id": "SD_BUFFER",
                    "source_id": "SO_BUFFER",
                    "function_id": "fn:producer",
                    "site_id": "site:receive",
                    "outputs": [
                        {
                            "kind": "memory_object",
                            "value_id": "value:buffer",
                            "object_id": "pointee:value:buffer",
                            "binding_status": "exact_call_actual",
                        }
                    ],
                    "proof": {
                        "kind": "software_interface_summary_instantiation",
                        "call_site_id": "site:receive",
                    },
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ],
        }
        sink = {
            "id": "K3",
            "function_id": "fn:consumer",
            "site_id": "site:sink",
            "vulnerable_parameters": [{"role": "src", "index": 0}],
        }
        index = dfa.ProgramIndex(facts, graph, strict=True)
        result = dfa.analyze_sink(
            sink,
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=32,
        )
        self.assertEqual(result["status"], "SOURCE_REACHED_DETERMINISTIC")
        self.assertEqual(
            result["parameter_results"][0]["paths"][0]["path"][-1]["kind"],
            "SOURCE_WRITE",
        )


if __name__ == "__main__":
    unittest.main()
