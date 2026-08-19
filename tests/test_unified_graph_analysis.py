from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_sink_backward_dfa as dfa  # noqa: E402


def atom(
    atom_id: str,
    object_id: str,
    *,
    space: str = "register",
    offset: str = "0x0",
    size: int = 4,
    constant: bool = False,
    address: bool = False,
) -> dict:
    return {
        "atom_id": atom_id,
        "object_id": object_id,
        "space": space,
        "offset": offset,
        "size": size,
        "is_constant": constant,
        "is_address": address,
    }


TARGET = atom(
    "atom:target",
    "const:target",
    space="const",
    constant=True,
)
SPACE = atom("atom:space", "const:space", space="const", constant=True)
SHARED_ADDRESS = atom(
    "atom:shared-address",
    "obj:shared",
    space="ram",
    offset="0x20000000",
    address=True,
)


def unified_fixture(*, writer_offset: int = 0, include_store: bool = True) -> tuple[dict, dict, dict, dict]:
    source_value = atom("atom:source", "reg:writer:0")
    loaded_value = atom("atom:loaded", "reg:reader:0")
    writer_ops = [
        {
            "site_id": "site:writer:source",
            "mnemonic": "LOAD",
            "output": source_value,
            "inputs": [SPACE, atom("atom:mmio", "const:mmio", space="const", constant=True)],
        }
    ]
    if include_store:
        writer_ops.append(
            {
                "site_id": "site:writer:store",
                "mnemonic": "STORE",
                "output": None,
                "inputs": [SPACE, SHARED_ADDRESS, source_value],
            }
        )
    facts = {
        "functions": [
            {
                "function_id": "fn:writer-root",
                "name": "writer_root",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:writer-root:call",
                        "mnemonic": "CALL",
                        "output": None,
                        "inputs": [TARGET],
                        "call": {"target_function_id": "fn:writer"},
                    }
                ],
            },
            {
                "function_id": "fn:writer",
                "name": "writer",
                "parameters": [],
                "pcode_ops": writer_ops,
            },
            {
                "function_id": "fn:reader-root",
                "name": "reader_root",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:reader-root:call",
                        "mnemonic": "CALL",
                        "output": None,
                        "inputs": [TARGET],
                        "call": {"target_function_id": "fn:reader"},
                    }
                ],
            },
            {
                "function_id": "fn:reader",
                "name": "reader",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:reader:load",
                        "mnemonic": "LOAD",
                        "output": loaded_value,
                        "inputs": [SPACE, SHARED_ADDRESS],
                    },
                    {
                        "site_id": "site:reader:sink",
                        "mnemonic": "CALL",
                        "output": None,
                        "inputs": [TARGET, loaded_value],
                        "call": {"target_function_id": "fn:sink"},
                    },
                ],
            },
        ]
    }
    graph = {
        "object_nodes": [
            {
                "node_id": "obj:shared",
                "object_id": "obj:shared",
                "address_range": ["0x20000000", "0x2000000f"],
                "identity_kind": "EXACT_ADDRESS",
                "evidence_level": "DETERMINISTIC_IDENTITY",
                "shared_object": True,
            }
        ],
        "call_edges": [
            {
                "edge_id": "call:writer-root",
                "src_node_id": "fn:writer-root",
                "dst_node_id": "fn:writer",
                "site_id": "site:writer-root:call",
                "edge_kind": "CALL",
                "resolution": "DIRECT",
            },
            {
                "edge_id": "call:reader-root",
                "src_node_id": "fn:reader-root",
                "dst_node_id": "fn:reader",
                "site_id": "site:reader-root:call",
                "edge_kind": "CALL",
                "resolution": "DIRECT",
            },
        ],
        "channel_edges": [
            {
                "edge_id": "channel:read",
                "src_node_id": "obj:shared",
                "dst_node_id": "fn:reader",
                "site_id": "site:reader:load",
                "edge_kind": "CHANNEL_READ",
                "object_id": "obj:shared",
                "value_atom_id": "atom:loaded",
                "value_object_id": "reg:reader:0",
                "region": {"object_id": "obj:shared", "offset": 0, "size": 4},
                "evidence_level": "DETERMINISTIC_ACCESS",
            },
            {
                "edge_id": "channel:write",
                "src_node_id": "fn:writer",
                "dst_node_id": "obj:shared",
                "site_id": "site:writer:store",
                "edge_kind": "CHANNEL_WRITE",
                "object_id": "obj:shared",
                "value_atom_id": "atom:source",
                "value_object_id": "reg:writer:0",
                "region": {
                    "object_id": "obj:shared",
                    "offset": writer_offset,
                    "size": 4,
                },
                "evidence_level": "DETERMINISTIC_ACCESS",
            },
        ],
    }
    sources = {
        "source_sites": [
            {
                "id": "SO_BACKEND_ATOM",
                "label": "MMIO_READ",
                "function": "writer",
                "site_id": "site:writer:source",
                "decision": "ACCEPT_DETERMINISTIC",
            }
        ]
    }
    sink = {
        "id": "SINK1",
        "function_id": "fn:reader",
        "function": "reader",
        "site_id": "site:reader:sink",
        "callee": "sink",
        "vulnerable_parameters": [{"role": "len", "index": 0, "constant": False}],
    }
    return facts, graph, sources, sink


class UnifiedGraphAnalysisTests(unittest.TestCase):
    def test_source_index_uses_only_source_side_associations(self) -> None:
        facts, graph, sources, _sink = unified_fixture()
        sources["source_sites"][0]["site_id"] = "site:not-in-program-facts"
        graph["source_associations"] = [
            {
                "association_id": "association:source-side",
                "source_id": "SO_BACKEND_ATOM",
                "state_kind": "VALUE",
                "function_id": "fn:writer",
                "atom_id": "atom:source",
                "relation_kind": "DIRECT_CALL_ACTUAL_FORMAL",
                "site_id": "site:writer:binding",
                "precision": "EXACT",
                "channel_depth": 0,
            },
            {
                "association_id": "association:consumer-side",
                "source_id": "SO_BACKEND_ATOM",
                "state_kind": "VALUE",
                "function_id": "fn:reader",
                "atom_id": "atom:loaded",
                "relation_kind": "CHANNEL_READ_VALUE",
                "site_id": "site:reader:load",
                "precision": "EXACT",
                "channel_depth": 1,
            },
        ]

        index = dfa.ProgramIndex(facts, graph, strict=True)
        by_atom, _by_object = dfa.source_index(sources, graph, index=index)

        self.assertIn("atom:source", by_atom)
        self.assertNotIn("atom:loaded", by_atom)
        self.assertEqual(
            by_atom["atom:source"][0]["_source_association"]["association_id"],
            "association:source-side",
        )

    def test_canonical_graph_excludes_candidate_objects_and_edges(self) -> None:
        facts, graph, _sources, _sink = unified_fixture()
        strict_object = {
            **graph["object_nodes"][0],
            "node_kind": "SHARED_OBJECT",
            "strict_shared_object": True,
        }
        graph["nodes"] = [
            {"node_id": "fn:writer", "node_kind": "FUNCTION"},
            {"node_id": "fn:reader", "node_kind": "FUNCTION"},
            strict_object,
        ]
        graph["edges"] = graph["call_edges"] + graph["channel_edges"]
        graph["object_nodes"].append(
            {
                "node_id": "obj:candidate-only",
                "object_id": "obj:candidate-only",
                "shared_object_candidate": True,
            }
        )
        graph["candidate_channel_edges"] = [
            {
                "edge_id": "candidate:write",
                "src_node_id": "fn:writer",
                "dst_node_id": "obj:candidate-only",
                "site_id": "site:candidate",
                "edge_kind": "OBJECT_WRITE",
                "object_id": "obj:candidate-only",
            }
        ]

        unified = dfa.UnifiedGraph(facts, graph, strict=True)

        self.assertNotIn("obj:candidate-only", unified.nodes)
        self.assertNotIn(
            "candidate:write", {edge["edge_id"] for edge in unified.edges}
        )
        self.assertEqual(
            {edge["edge_kind"] for edge in unified.edges},
            {"CALL", "CHANNEL_READ", "CHANNEL_WRITE"},
        )

    def test_one_mixed_bfs_then_backend_atom_rda_reaches_source(self) -> None:
        facts, graph, sources, sink = unified_fixture()
        index = dfa.ProgramIndex(facts, graph, strict=True)
        by_atom, by_object = dfa.source_index(sources, graph, index=index)
        calls = 0
        reverse_bfs = index.graph.reverse_bfs

        def counted_reverse_bfs(
            start_node_id: str,
            *,
            max_steps: int,
            max_trace_witnesses: int = 64,
        ) -> dict:
            nonlocal calls
            calls += 1
            return reverse_bfs(
                start_node_id,
                max_steps=max_steps,
                max_trace_witnesses=max_trace_witnesses,
            )

        index.graph.reverse_bfs = counted_reverse_bfs  # type: ignore[method-assign]
        chain = dfa.analyze_sink(
            sink,
            index,
            by_atom,
            by_object,
            max_steps=64,
        )

        self.assertEqual(calls, 1)
        self.assertEqual(chain["status"], "SOURCE_REACHED_DETERMINISTIC")
        self.assertTrue(any(trace["mixed"] for trace in chain["candidate_traces"]))
        self.assertNotIn(
            "fn:sink", set(chain["candidate_search"]["allowed_node_ids"])
        )
        self.assertEqual(
            set(index.graph.EDGE_KINDS),
            {"CALL", "CALLIND", "CHANNEL_READ", "CHANNEL_WRITE"},
        )
        result = chain["parameter_results"][0]
        self.assertEqual(result["binding_evidence"]["kind"], "CALLSITE_BACKEND_ARGUMENT")
        self.assertEqual(result["start_value_id"], "")
        self.assertEqual(
            [step["kind"] for step in result["paths"][0]["path"]],
            ["CHANNEL_READ", "CHANNEL_WRITE_PREDECESSOR"],
        )

    def test_nonoverlapping_regions_do_not_transfer(self) -> None:
        facts, graph, sources, sink = unified_fixture(writer_offset=8)
        index = dfa.ProgramIndex(facts, graph, strict=True)
        chain = dfa.analyze_sink(
            sink,
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=64,
        )

        result = chain["parameter_results"][0]
        self.assertEqual(chain["status"], "GRAPH_INCOMPLETE")
        self.assertEqual(result["paths"], [])
        self.assertIn("no_overlapping_channel_write_region", result["blockers"])

    def test_multiple_writers_keep_source_and_internal_branches_separate(self) -> None:
        facts, graph, sources, sink = unified_fixture()
        constant = atom(
            "const:0:4",
            "const:0:4",
            space="const",
            constant=True,
        )
        facts["functions"].append(
            {
                "function_id": "fn:initializer",
                "name": "initializer",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:initializer:store",
                        "mnemonic": "STORE",
                        "output": None,
                        "inputs": [SPACE, SHARED_ADDRESS, constant],
                    }
                ],
            }
        )
        graph["channel_edges"].append(
            {
                "edge_id": "channel:constant-write",
                "src_node_id": "fn:initializer",
                "dst_node_id": "obj:shared",
                "site_id": "site:initializer:store",
                "edge_kind": "CHANNEL_WRITE",
                "object_id": "obj:shared",
                "value_atom_id": "const:0:4",
                "value_object_id": "const:0:4",
                "source_associated": False,
                "region": {
                    "object_id": "obj:shared",
                    "offset": 0,
                    "size": 4,
                },
                "evidence_level": "DETERMINISTIC_ACCESS",
            }
        )
        index = dfa.ProgramIndex(facts, graph, strict=True)
        chain = dfa.analyze_sink(
            sink,
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=64,
        )

        self.assertEqual(chain["status"], "SOURCE_REACHED_DETERMINISTIC")
        result = chain["parameter_results"][0]
        self.assertEqual(
            {path["source_id"] for path in result["paths"]},
            {"SO_BACKEND_ATOM"},
        )

    def test_strict_mode_rejects_legacy_channel_write_with_evidence(self) -> None:
        facts, graph, sources, sink = unified_fixture(include_store=False)
        graph["channel_edges"][1].update(
            {
                "edge_kind": "OBJECT_WRITE",
                "evidence_level": "HEURISTIC_CLUSTER_ACCESS",
                "object_id": "obj:shared",
            }
        )
        index = dfa.ProgramIndex(facts, graph, strict=True)
        chain = dfa.analyze_sink(
            sink,
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=64,
        )

        result = chain["parameter_results"][0]
        self.assertEqual(chain["status"], "GRAPH_INCOMPLETE")
        self.assertNotIn("channel:write", {edge["edge_id"] for edge in index.graph.edges})
        self.assertIn("strict_mode_rejected_channel_edge", result["blockers"])
        self.assertEqual(result["rejected_evidence"][0]["edge_id"], "channel:write")

    def test_resolved_callind_return_uses_the_same_trace_constraint(self) -> None:
        source = atom("atom:indirect-source", "reg:callee:0")
        result = atom("atom:indirect-result", "reg:caller:0")
        facts = {
            "functions": [
                {
                    "function_id": "fn:caller",
                    "name": "caller",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:caller:indirect",
                            "mnemonic": "CALLIND",
                            "output": result,
                            "inputs": [TARGET],
                            "call": {},
                        },
                        {
                            "site_id": "site:caller:sink",
                            "mnemonic": "CALL",
                            "output": None,
                            "inputs": [TARGET, result],
                            "call": {"target_function_id": "fn:sink"},
                        },
                    ],
                },
                {
                    "function_id": "fn:callee",
                    "name": "callee",
                    "parameters": [],
                    "pcode_ops": [
                        {
                            "site_id": "site:callee:source",
                            "mnemonic": "COPY",
                            "output": source,
                            "inputs": [atom("atom:internal", "reg:callee:1")],
                        },
                        {
                            "site_id": "site:callee:return",
                            "mnemonic": "RETURN",
                            "output": None,
                            "inputs": [TARGET, source],
                        },
                    ],
                },
            ]
        }
        graph = {
            "object_nodes": [],
            "channel_edges": [],
            "call_edges": [
                {
                    "edge_id": "callind:resolved",
                    "src_node_id": "fn:caller",
                    "dst_node_id": "fn:callee",
                    "site_id": "site:caller:indirect",
                    "edge_kind": "CALLIND",
                    "resolution": "POINTS_TO_EXACT",
                }
            ],
        }
        sources = {
            "source_sites": [
                {
                    "id": "SO_CALLIND",
                    "site_id": "site:callee:source",
                    "decision": "ACCEPT_DETERMINISTIC",
                }
            ]
        }
        sink = {
            "id": "SINK_CALLIND",
            "function_id": "fn:caller",
            "site_id": "site:caller:sink",
            "vulnerable_parameters": [{"role": "value", "index": 0}],
        }
        index = dfa.ProgramIndex(facts, graph, strict=True)
        chain = dfa.analyze_sink(
            sink,
            index,
            *dfa.source_index(sources, graph, index=index),
            max_steps=32,
        )

        self.assertEqual(chain["status"], "SOURCE_REACHED_DETERMINISTIC")
        path = chain["parameter_results"][0]["paths"][0]["path"]
        self.assertEqual(path[0]["kind"], "CALL_RETURN")
        self.assertEqual(path[0]["graph_edge_kind"], "CALLIND")


if __name__ == "__main__":
    unittest.main()
