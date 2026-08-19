from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import run_sink_backward_dfa as dfa  # noqa: E402


def _node(object_id: str, *, constant: bool = False) -> dict:
    return {
        "object_id": object_id,
        "value_id": f"value:{object_id}",
        "space": "const" if constant else "register",
        "is_constant": constant,
        "size": 4,
    }


def _fixture() -> tuple[dict, dict]:
    actual = _node("reg:caller:0")
    facts = {
        "functions": [
            {
                "function_id": "fn:caller",
                "name": "caller",
                "parameters": [],
                "pcode_ops": [
                    {
                        "site_id": "site:caller:call",
                        "mnemonic": "CALLIND",
                        "inputs": [_node("const:target", constant=True), actual],
                        "output": None,
                        "call": {},
                    }
                ],
            },
            {
                "function_id": "fn:callee",
                "name": "callee",
                "parameters": [{"index": 0, "object_id": "param:callee:0"}],
                "pcode_ops": [],
            },
        ]
    }
    graph = {
        "nodes": [
            {"node_id": "fn:caller", "node_kind": "FUNCTION"},
            {"node_id": "fn:callee", "node_kind": "FUNCTION"},
            {
                "node_id": "region:shared",
                "object_id": "region:shared",
                "node_kind": "SHARED_OBJECT",
            },
        ],
        "edges": [
            {
                "edge_id": "call:finite:callee",
                "edge_kind": "CALLIND",
                "src_node_id": "fn:caller",
                "dst_node_id": "fn:callee",
                "site_id": "site:caller:call",
                "resolution": "FINITE_TABLE_MAY_TARGET",
                "analysis_precision": "MAY",
                "recognition": "heuristic",
                "argument_bindings": [
                    {
                        "slot": 0,
                        "object_id": "reg:caller:0",
                        "value_id": "value:reg:caller:0",
                    }
                ],
            },
            {
                "edge_id": "channel:read",
                "edge_kind": "CHANNEL_READ",
                "src_node_id": "region:shared",
                "dst_node_id": "fn:callee",
                "site_id": "site:callee:read",
                "analysis_precision": "EXACT",
            },
        ],
    }
    return facts, graph


def test_callgraph_only_removes_only_channel_relations() -> None:
    facts, graph = _fixture()
    unified = dfa.UnifiedGraph(facts, graph, graph_mode="unified")
    call_only = dfa.UnifiedGraph(facts, graph, graph_mode="callgraph-only")

    assert {edge["edge_kind"] for edge in unified.edges} == {
        "CALLIND",
        "CHANNEL_READ",
    }
    assert {edge["edge_kind"] for edge in call_only.edges} == {"CALLIND"}


def test_may_call_precision_reaches_actual_formal_relation() -> None:
    facts, graph = _fixture()
    index = dfa.ProgramIndex(facts, graph, graph_mode="callgraph-only")
    parameter = {"parameter_slot": 0, "object_id": "param:callee:0"}

    rows = index.parameter_predecessors("fn:callee", parameter)

    assert len(rows) == 1
    assert rows[0]["edge"]["analysis_precision"] == "MAY"
    assert rows[0]["edge"]["graph_edge_id"] == "call:finite:callee"


def test_first_missing_relation_preserves_specific_blockers() -> None:
    row = dfa.first_missing_relation(
        {"unmodeled_origin", "candidate_trace_excludes_call_return"}
    )

    assert row == {
        "relation": "CALL_ACTUAL_FORMAL_OR_RETURN",
        "blockers": ["candidate_trace_excludes_call_return"],
    }
