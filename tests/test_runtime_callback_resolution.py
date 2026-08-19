from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import memory_access_facts  # noqa: E402
import runtime_callback_resolver  # noqa: E402


def node(
    value_id: str,
    *,
    slot: int | None = None,
    def_site_id: str = "",
    space: str = "register",
    offset: str = "0x0",
    is_address: bool = False,
) -> dict:
    return {
        "value_id": value_id,
        "object_id": value_id,
        "space": space,
        "offset": offset,
        "size": 4,
        "is_parameter": slot is not None,
        "parameter_slot": slot,
        "is_constant": space == "const",
        "is_address": is_address,
        "def_site_id": def_site_id,
    }


def op(site: str, mnemonic: str, inputs: list[dict], output: dict | None = None) -> dict:
    return {
        "site_id": site,
        "mnemonic": mnemonic,
        "inputs": inputs,
        "output": output,
    }


class Runtime:
    def resolve(self, actual: dict, _function_id: str) -> dict:
        return {
            "object_id": str(actual.get("object_id", "")),
            "root_object_id": str(actual.get("object_id", "")),
            "access_path": [],
        }


class OutputAliasRuntime(Runtime):
    def resolve(self, actual: dict, _function_id: str) -> dict:
        if str(actual.get("value_id", "")) == "value:field-address":
            return {
                "object_id": "obj:local-callback-pointer",
                "root_object_id": "obj:local-callback-pointer",
                "access_path": ["byte_offset:12"],
            }
        return super().resolve(actual, _function_id)


def access_index() -> memory_access_facts.MemoryAccessFactIndex:
    common = {
        "object_id": "obj:callback-field",
        "aggregate_object_id": "obj:callback-field",
        "base_object_id": "obj:callback-table",
        "region_offset": 12,
        "region_extent": 4,
        "selector_terms": (),
        "field_path": ("field_offset:12",),
        "address_provenance": "HIGH_PCODE_FIXED_REGION",
        "storage_kind": "STATIC_WRITABLE_DATA",
        "deterministic_context_ids": (),
        "context_ids": ("ctx:main",),
        "access_edge_id": "",
    }
    return memory_access_facts.MemoryAccessFactIndex(
        write_facts=[
            memory_access_facts.WriteFact(
                access_kind="WRITE",
                site_id="site:store",
                function_id="fn:register",
                stored_atom_id="value:cast",
                loaded_atom_id="",
                **common,
            )
        ],
        read_facts=[
            memory_access_facts.ReadFact(
                access_kind="READ",
                site_id="site:load",
                function_id="fn:dispatch",
                stored_atom_id="",
                loaded_atom_id="value:target",
                **common,
            )
        ],
    )


def fixture(second_target: bool = False) -> tuple[dict, list[dict]]:
    callback_formal = node("value:callback-formal", slot=0)
    cast_value = node("value:cast", def_site_id="site:cast")
    target_value = node("value:target", def_site_id="site:load")
    address = node("value:field-address")
    data = node("value:data", slot=0)
    handler_address = node(
        "value:handler-address",
        space="global",
        offset="0x1000",
        is_address=True,
    )
    call_register = op(
        "site:register-call",
        "CALL",
        [node("value:register-target"), handler_address],
    )
    call_register["call"] = {"target_function_id": "fn:register"}
    main_ops = [call_register]
    call_edges = [
        {
            "edge_id": "call:site:register-call",
            "site_id": "site:register-call",
            "edge_kind": "CALL",
            "src_node_id": "fn:main",
            "dst_node_id": "fn:register",
        }
    ]
    functions = [
        {
            "function_id": "fn:handler",
            "entry": "0x1000",
            "parameters": [data],
            "pcode_ops": [],
        },
        {
            "function_id": "fn:register",
            "entry": "0x2000",
            "parameters": [callback_formal],
            "pcode_ops": [
                op("site:cast", "CAST", [callback_formal], cast_value),
                op("site:store", "STORE", [node("space", space="const"), address, cast_value]),
            ],
        },
        {
            "function_id": "fn:dispatch",
            "entry": "0x3000",
            "parameters": [data],
            "pcode_ops": [
                op("site:load", "LOAD", [node("space", space="const"), address], target_value),
                op("site:dispatch", "CALLIND", [target_value, data]),
            ],
        },
        {
            "function_id": "fn:main",
            "entry": "0x4000",
            "parameters": [],
            "pcode_ops": main_ops,
        },
    ]
    if second_target:
        functions.append(
            {
                "function_id": "fn:other-handler",
                "entry": "0x1100",
                "parameters": [data],
                "pcode_ops": [],
            }
        )
        other_address = node(
            "value:other-handler-address",
            space="global",
            offset="0x1100",
            is_address=True,
        )
        other_call = op(
            "site:other-register-call",
            "CALL",
            [node("value:register-target-2"), other_address],
        )
        other_call["call"] = {"target_function_id": "fn:register"}
        main_ops.append(other_call)
        call_edges.append(
            {
                "edge_id": "call:site:other-register-call",
                "site_id": "site:other-register-call",
                "edge_kind": "CALL",
                "src_node_id": "fn:main",
                "dst_node_id": "fn:register",
            }
        )
    return {"functions": functions}, call_edges


def test_unique_runtime_callback_store_load_recovers_exact_call_relation() -> None:
    facts, call_edges = fixture()
    result = runtime_callback_resolver.resolve_runtime_callback_relations(
        facts,
        call_edges,
        runtime=Runtime(),
        access_index=access_index(),
    )

    assert result["counts"]["resolved_callsites"] == 1
    assert len(result["call_edges"]) == 1
    edge = result["call_edges"][0]
    assert edge["src_node_id"] == "fn:dispatch"
    assert edge["dst_node_id"] == "fn:handler"
    assert edge["analysis_precision"] == "EXACT"
    assert edge["recognition"] == "deterministic"
    assert edge["argument_bindings"][0]["atom_id"] == "value:data"


def test_initialized_literal_slot_resolves_arm_thumb_callback_target() -> None:
    facts, call_edges = fixture()
    register_call = next(
        op
        for function in facts["functions"]
        if function["function_id"] == "fn:main"
        for op in function["pcode_ops"]
        if op["site_id"] == "site:register-call"
    )
    callback_actual = register_call["inputs"][1]
    callback_actual.update(
        {
            "object_id": "global:00001800:4",
            "value_id": "value:literal-slot",
            "space": "ram",
            "offset": "0x1800",
            "address": "00001800",
            "is_address": True,
        }
    )

    result = runtime_callback_resolver.resolve_runtime_callback_relations(
        facts,
        call_edges,
        runtime=Runtime(),
        access_index=access_index(),
        literal_words={0x1800: 0x1001},
    )

    assert result["counts"]["resolved_callsites"] == 1
    assert result["call_edges"][0]["dst_node_id"] == "fn:handler"


def test_output_object_alias_connects_local_callback_load_to_registration_base() -> None:
    facts, call_edges = fixture()
    index = access_index()
    index = memory_access_facts.MemoryAccessFactIndex(
        write_facts=index.write_facts,
        read_facts=[],
    )
    result = runtime_callback_resolver.resolve_runtime_callback_relations(
        facts,
        call_edges,
        runtime=OutputAliasRuntime(),
        access_index=index,
        output_effects=[
            {
                "caller_function_id": "fn:dispatch",
                "call_site_id": "site:before-load",
                "destination": {
                    "object_id": "obj:local-callback-pointer",
                    "offset": 0,
                },
                "stored_value": {"object_id": "obj:callback-table"},
            }
        ],
    )

    assert result["counts"]["resolved_callsites"] == 1
    assert result["call_edges"][0]["dst_node_id"] == "fn:handler"
    assert result["call_edges"][0]["recognition"] == "heuristic"


def test_complete_finite_runtime_callback_set_is_retained_as_may_edges() -> None:
    facts, call_edges = fixture(second_target=True)
    result = runtime_callback_resolver.resolve_runtime_callback_relations(
        facts,
        call_edges,
        runtime=Runtime(),
        access_index=access_index(),
    )

    assert {edge["dst_node_id"] for edge in result["call_edges"]} == {
        "fn:handler",
        "fn:other-handler",
    }
    assert {edge["analysis_precision"] for edge in result["call_edges"]} == {"MAY"}
    assert {edge["recognition"] for edge in result["call_edges"]} == {"heuristic"}


def test_disjoint_callback_regions_do_not_create_call_relation() -> None:
    facts, call_edges = fixture()
    index = access_index()
    read = index.read_facts[0]
    index = memory_access_facts.MemoryAccessFactIndex(
        write_facts=index.write_facts,
        read_facts=[
            memory_access_facts.ReadFact(
                **{
                    **read.__dict__,
                    "region_offset": 24,
                }
            )
        ],
    )

    result = runtime_callback_resolver.resolve_runtime_callback_relations(
        facts,
        call_edges,
        runtime=Runtime(),
        access_index=index,
    )

    assert result["call_edges"] == []
