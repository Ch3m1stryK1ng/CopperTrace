from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from function_effect_resolver import FunctionEffectResolver  # noqa: E402


def node(
    value_id: str,
    object_id: str,
    *,
    slot: int | None = None,
    def_site_id: str = "",
    size: int = 4,
) -> dict:
    return {
        "value_id": value_id,
        "object_id": object_id,
        "space": "register",
        "offset": "0x0",
        "size": size,
        "high_data_type": "void *" if slot == 0 else "uint32_t",
        "is_parameter": slot is not None,
        "parameter_slot": slot,
        "is_constant": False,
        "is_address": False,
        "def_site_id": def_site_id,
    }


def constant(value: int, *, size: int = 4) -> dict:
    return {
        "value_id": f"const:{value:x}:{size}",
        "object_id": f"const:{value:x}:{size}",
        "space": "const",
        "offset": hex(value),
        "size": size,
        "is_parameter": False,
        "parameter_slot": None,
        "is_constant": True,
        "is_address": False,
        "def_site_id": "",
    }


SPACE = constant(0)
TARGET = constant(0x2000)


def op(site: str, mnemonic: str, inputs: list[dict], output: dict | None = None) -> dict:
    return {
        "site_id": site,
        "mnemonic": mnemonic,
        "inputs": inputs,
        "output": output,
    }


def call(
    site: str,
    target: str,
    actuals: list[dict],
    *,
    mnemonic: str = "CALL",
    output: dict | None = None,
) -> dict:
    return {
        "site_id": site,
        "mnemonic": mnemonic,
        "inputs": [TARGET, *actuals],
        "output": output,
        "call": {"target_function_id": target} if target else {},
    }


def identity(raw: dict | None) -> str:
    item = dict(raw or {})
    return str(item.get("value_id", "") or item.get("object_id", ""))


def resolver(
    functions: dict[str, dict],
    *,
    calls_by_site: dict[str, list[dict]] | None = None,
    resolved_objects: dict[str, str] | None = None,
) -> FunctionEffectResolver:
    calls_by_site = calls_by_site or {}
    calls_to: dict[str, list[dict]] = {}
    for rows in calls_by_site.values():
        for edge in rows:
            calls_to.setdefault(str(edge.get("dst_node_id", "")), []).append(edge)
    return FunctionEffectResolver(
        functions=functions,
        calls_by_site=calls_by_site,
        calls_to=calls_to,
        resolved_object_by_atom=resolved_objects or {},
        identity=identity,
        public_value=identity,
        same_object=lambda left, right: left == right,
    )


def fixed_output_fixture() -> tuple[dict[str, dict], dict, dict, dict]:
    formal_out = node("value:out", "param:callee:0", slot=0)
    formal_value = node("value:input", "param:callee:1", slot=1)
    field_address = node(
        "value:field-address",
        "unique:callee:10",
        def_site_id="site:field-address",
    )
    computed = node(
        "value:computed",
        "reg:callee:20",
        def_site_id="site:compute",
    )
    computed_address = node(
        "value:computed-address",
        "unique:callee:30",
        def_site_id="site:computed-address",
    )
    callee = {
        "function_id": "fn:callee",
        "parameters": [formal_out, formal_value],
        "pcode_ops": [
            op("site:store-zero", "STORE", [SPACE, formal_out, formal_value]),
            op(
                "site:field-address",
                "PTRSUB",
                [formal_out, constant(12)],
                field_address,
            ),
            op("site:store-field", "STORE", [SPACE, field_address, formal_value]),
            op("site:compute", "INT_ADD", [formal_value, constant(1)], computed),
            op(
                "site:computed-address",
                "PTRSUB",
                [formal_out, constant(16)],
                computed_address,
            ),
            op("site:store-local", "STORE", [SPACE, computed_address, computed]),
        ],
    }
    actual_out = node("value:caller-out", "reg:caller:0")
    actual_value = node("value:caller-input", "reg:caller:1")
    call_op = call("site:call", "fn:callee", [actual_out, actual_value])
    caller = {
        "function_id": "fn:caller",
        "parameters": [],
        "pcode_ops": [call_op],
    }
    edge = {
        "edge_id": "call:site:call",
        "edge_kind": "CALL",
        "src_node_id": "fn:caller",
        "dst_node_id": "fn:callee",
        "site_id": "site:call",
        "resolution": "DIRECT",
        "analysis_precision": "EXACT",
        "recognition": "deterministic",
        "argument_bindings": [
            {
                "slot": 0,
                "atom_id": "value:caller-out",
                "value_id": "value:caller-out",
                "object_id": "obj:caller-local",
            },
            {
                "slot": 1,
                "atom_id": "value:caller-input",
                "value_id": "value:caller-input",
                "object_id": "reg:caller:1",
            },
        ],
    }
    return {"fn:caller": caller, "fn:callee": callee}, call_op, edge, computed


def test_extracts_zero_field_and_local_ssa_fixed_output_effects() -> None:
    functions, _, _, _ = fixed_output_fixture()
    effects, blockers = resolver(functions).extract_fixed_output_effects("fn:callee")

    assert blockers == []
    assert [row["output"]["offset"] for row in effects] == [0, 12, 16]
    assert {row["effect_kind"] for row in effects} == {"FIXED_OUTPUT_STORE"}
    by_site = {row["store_site_id"]: row for row in effects}
    assert by_site["site:store-zero"]["stored_value"]["lineage_kind"] == "FORMAL_VALUE"
    assert by_site["site:store-local"]["stored_value"]["lineage_kind"] == "LOCAL_SSA_VALUE"
    assert by_site["site:store-local"]["stored_value"]["formal_parameter_slots"] == [1]


def test_resolved_call_instantiates_caller_region_and_rda_predecessor() -> None:
    functions, call_op, edge, _ = fixed_output_fixture()
    effect_resolver = resolver(
        functions,
        calls_by_site={"site:call": [edge]},
    )

    effects, blockers = effect_resolver.bind_output_effects_to_calls(
        "fn:caller",
        call_op,
        allowed_edge_ids={"call:site:call"},
    )

    assert blockers == []
    assert len(effects) == 3
    field = next(row for row in effects if row["destination"]["offset"] == 12)
    assert field["destination"] == {
        "object_id": "obj:caller-local",
        "base_object_id": "obj:caller-local",
        "offset": 12,
        "extent": 4,
        "region_id": "region:obj:caller-local:12:4",
        "actual_atom_id": "value:caller-out",
        "actual_value_id": "value:caller-out",
        "formal_parameter_slot": 0,
    }
    assert field["stored_value"]["atom_id"] == "value:caller-input"
    assert field["edge"]["kind"] == "CALL_OUTPUT_EFFECT"

    predecessors, predecessor_blockers = effect_resolver.call_output_predecessors(
        "obj:caller-local",
        offset=12,
        allowed_edge_ids={"call:site:call"},
        allowed_node_ids={"fn:caller"},
    )
    assert predecessor_blockers == []
    assert len(predecessors) == 1
    assert predecessors[0]["atom_id"] == "value:caller-input"
    assert predecessors[0]["edge"]["destination_region_id"] == (
        "region:obj:caller-local:12:4"
    )


def test_dynamic_output_offset_reports_blocker() -> None:
    formal_out = node("value:out", "param:callee:0", slot=0)
    formal_value = node("value:value", "param:callee:1", slot=1)
    index = node("value:index", "param:callee:2", slot=2)
    address = node(
        "value:dynamic-address",
        "unique:callee:1",
        def_site_id="site:dynamic-address",
    )
    functions = {
        "fn:callee": {
            "function_id": "fn:callee",
            "parameters": [formal_out, formal_value, index],
            "pcode_ops": [
                op(
                    "site:dynamic-address",
                    "PTRADD",
                    [formal_out, index, constant(1)],
                    address,
                ),
                op("site:dynamic-store", "STORE", [SPACE, address, formal_value]),
            ],
        }
    }

    effects, blockers = resolver(functions).extract_fixed_output_effects("fn:callee")

    assert effects == []
    assert [row["reason"] for row in blockers] == [
        "call_output_dynamic_offset_unsupported"
    ]


def test_caller_actual_access_path_is_added_to_callee_field_offset() -> None:
    functions, call_op, edge, _ = fixed_output_fixture()
    edge["argument_access_paths"] = [["byte_offset:16"], []]
    effect_resolver = resolver(
        functions,
        calls_by_site={"site:call": [edge]},
    )

    effects, blockers = effect_resolver.bind_output_effects_to_calls(
        "fn:caller",
        call_op,
        allowed_edge_ids={"call:site:call"},
    )

    assert blockers == []
    assert [row["destination"]["offset"] for row in effects] == [16, 28, 32]
    field = next(row for row in effects if row["destination"]["offset"] == 28)
    assert field["destination"]["actual_access_path"] == ["byte_offset:16"]


def test_offset_after_last_dereference_is_relative_to_pointee_object() -> None:
    functions, call_op, edge, _ = fixed_output_fixture()
    edge["argument_bindings"][0]["object_id"] = "obj:pointee"
    edge["argument_access_paths"] = [
        ["byte_offset:16", "deref", "byte_offset:8"],
        [],
    ]
    effect_resolver = resolver(
        functions,
        calls_by_site={"site:call": [edge]},
    )

    effects, blockers = effect_resolver.bind_output_effects_to_calls(
        "fn:caller",
        call_op,
        allowed_edge_ids={"call:site:call"},
    )

    assert blockers == []
    assert [row["destination"]["offset"] for row in effects] == [8, 20, 24]
    assert {row["destination"]["object_id"] for row in effects} == {"obj:pointee"}


def test_unresolved_stored_value_reports_blocker() -> None:
    formal_out = node("value:out", "param:callee:0", slot=0)
    orphan = node("value:orphan", "reg:callee:9")
    functions = {
        "fn:callee": {
            "function_id": "fn:callee",
            "parameters": [formal_out],
            "pcode_ops": [op("site:store", "STORE", [SPACE, formal_out, orphan])],
        }
    }

    effects, blockers = resolver(functions).extract_fixed_output_effects("fn:callee")

    assert effects == []
    assert [row["reason"] for row in blockers] == [
        "call_output_stored_value_unresolved"
    ]


def test_unresolved_actual_object_reports_blocker() -> None:
    functions, call_op, edge, _ = fixed_output_fixture()
    edge["argument_bindings"][0]["object_id"] = "reg:caller:0"
    effect_resolver = resolver(functions, calls_by_site={"site:call": [edge]})

    effects, blockers = effect_resolver.bind_output_effects_to_calls(
        "fn:caller", call_op, allowed_edge_ids={"call:site:call"}
    )

    assert effects == []
    assert {row["reason"] for row in blockers} == {
        "call_output_actual_object_unresolved"
    }


def test_ambiguous_resolved_target_reports_blocker() -> None:
    functions, call_op, edge, _ = fixed_output_fixture()
    call_op["mnemonic"] = "CALLIND"
    call_op["call"] = {}
    other = {**functions["fn:callee"], "function_id": "fn:other"}
    functions["fn:other"] = other
    edge_a = {**edge, "edge_id": "call:a"}
    edge_b = {**edge, "edge_id": "call:b", "dst_node_id": "fn:other"}
    effect_resolver = resolver(
        functions,
        calls_by_site={"site:call": [edge_a, edge_b]},
    )

    effects, blockers = effect_resolver.bind_output_effects_to_calls(
        "fn:caller", call_op, allowed_edge_ids={"call:a", "call:b"}
    )

    assert effects == []
    assert [row["reason"] for row in blockers] == [
        "call_output_target_ambiguous"
    ]


def test_call_return_inherits_finite_table_may_precision_and_recognition() -> None:
    result = node(
        "value:result",
        "reg:caller:0",
        def_site_id="site:dispatch",
    )
    returned = node("value:returned", "param:callee:0", slot=0)
    dispatch = call(
        "site:dispatch",
        "",
        [],
        mnemonic="CALLIND",
        output=result,
    )
    functions = {
        "fn:caller": {
            "function_id": "fn:caller",
            "parameters": [],
            "pcode_ops": [dispatch],
        },
        "fn:callee": {
            "function_id": "fn:callee",
            "parameters": [returned],
            "pcode_ops": [op("site:return", "RETURN", [TARGET, returned])],
        },
    }
    edge = {
        "edge_id": "call:finite",
        "edge_kind": "CALLIND",
        "src_node_id": "fn:caller",
        "dst_node_id": "fn:callee",
        "site_id": "site:dispatch",
        "resolution": "FINITE_TABLE_MAY_TARGET",
        "analysis_precision": "MAY",
        "recognition": "heuristic",
    }
    effect_resolver = resolver(
        functions,
        calls_by_site={"site:dispatch": [edge]},
    )

    predecessors, blocker = effect_resolver.return_predecessors(
        "fn:caller",
        dispatch,
        call_depth=0,
        allowed_edge_ids={"call:finite"},
    )

    assert blocker == ""
    assert len(predecessors) == 1
    return_edge = predecessors[0]["edge"]
    assert return_edge["analysis_precision"] == "MAY"
    assert return_edge["recognition"] == "heuristic"
    assert return_edge["resolution"] == "FINITE_TABLE_MAY_TARGET"
