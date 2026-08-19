import importlib.util
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "finite_callind_device_dispatch_resolver",
    ROOT / "scripts" / "device_dispatch_resolver.py",
)
resolver = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = resolver
SPEC.loader.exec_module(resolver)


def node(value_id, *, offset=0, constant=False, address=False, object_id=""):
    return {
        "value_id": value_id,
        "object_id": object_id or value_id.replace("value:", "object:"),
        "offset": hex(offset),
        "size": 4,
        "is_constant": constant,
        "is_address": address,
    }


SPACE = node("const:space", offset=0x1A1, constant=True)


def op(site, mnemonic, output, *inputs):
    return {
        "site_id": site,
        "instruction_address": "0x" + site.split(":")[-2],
        "mnemonic": mnemonic,
        "output": output,
        "inputs": list(inputs),
    }


def function(entry, name, ops=(), *, parameter_count=0):
    return {
        "function_id": f"fn:{entry:08x}",
        "entry": hex(entry),
        "name": name,
        "parameters": [
            {
                "index": index,
                "object_id": f"param:{entry:08x}:{index}",
                "storage": f"r{index}:4",
            }
            for index in range(parameter_count)
        ],
        "pcode_ops": list(ops),
    }


def word(value):
    return int(value).to_bytes(4, "little")


def finite_callind_fixture(
    target_count,
    *,
    writable_table=False,
    duplicate_target=False,
    use_int_multiply_shape=False,
):
    table_base = 0x7000
    target_addresses = [0x9000 + index * 0x20 for index in range(target_count)]
    table_values = (
        [target_addresses[0]] * target_count
        if duplicate_target and target_addresses
        else target_addresses
    )
    table = b"".join(word(address | 1) for address in table_values)
    text_size = max(2, (target_count - 1) * 0x20 + 2) if target_count else 2
    text = bytearray(text_size)
    for address in target_addresses:
        offset = address - 0x9000
        text[offset : offset + 2] = b"\x70\x47"

    selector = node("value:dispatch:selector", object_id="param:00001200:0")
    table_node = node(
        "const:function-table",
        offset=table_base,
        constant=True,
        address=True,
    )
    if use_int_multiply_shape:
        scaled = node("value:dispatch:scaled-selector")
        scale_op = op(
            "site:00001200:00001204:1",
            "INT_MULT",
            scaled,
            selector,
            node("const:pointer-size", offset=4, constant=True),
        )
        entry_address = node("value:dispatch:entry-address")
        address_op = op(
            "site:00001200:00001208:2",
            "INT_ADD",
            entry_address,
            table_node,
            scaled,
        )
        operations = [scale_op, address_op]
    else:
        entry_address = node("value:dispatch:entry-address")
        address_op = op(
            "site:00001200:00001208:2",
            "PTRADD",
            entry_address,
            table_node,
            selector,
            node("const:pointer-size", offset=4, constant=True),
        )
        operations = [address_op]

    target_value = node("value:dispatch:target")
    target_load = op(
        "site:00001200:0000120c:3",
        "LOAD",
        target_value,
        SPACE,
        entry_address,
    )
    actual_packet = node(
        "value:dispatch:packet",
        object_id="object:stack:00001200:-32",
    )
    actual_length = node(
        "value:dispatch:length",
        object_id="object:register:00001200:r2",
    )
    dispatch = op(
        "site:00001200:00001210:4",
        "CALLIND",
        node("value:dispatch:return"),
        target_value,
        actual_packet,
        actual_length,
    )
    dispatch["call"] = {"kind": "CALLIND"}
    operations.extend([target_load, dispatch])

    functions = [function(0x1200, "dispatch", operations, parameter_count=1)]
    functions.extend(
        function(address, f"target_{index}", parameter_count=2)
        for index, address in enumerate(target_addresses)
    )
    symbols = [
        resolver.MemorySymbol(
            table_base,
            len(table),
            "STT_OBJECT",
            name="fixture_table",
            source="elf:fixture:.symtab",
            section=".rodata",
            writable=writable_table,
        )
    ]
    symbols.extend(
        resolver.MemorySymbol(
            address,
            2,
            "STT_FUNC",
            name=f"target_{index}",
            source="elf:fixture:.symtab",
            section=".text",
            executable=True,
        )
        for index, address in enumerate(target_addresses)
    )
    memory = resolver.InitializedMemory.from_regions(
        [
            resolver.MemoryRegion(
                table_base,
                table,
                source="elf:fixture:.rodata",
                writable=writable_table,
            ),
            resolver.MemoryRegion(
                0x9000,
                bytes(text),
                source="elf:fixture:.text",
                executable=True,
            ),
        ],
        symbols=symbols,
    )
    return {"functions": functions}, memory, dispatch, [actual_packet, actual_length]


@pytest.mark.parametrize("use_int_multiply_shape", [False, True])
def test_unique_executable_target_is_exact(use_int_multiply_shape):
    facts, memory, _, actuals = finite_callind_fixture(
        1,
        use_int_multiply_shape=use_int_multiply_shape,
    )

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["counts"] == {
        "callind": 1,
        "resolved": 1,
        "ambiguous": 0,
        "unresolved": 0,
    }
    row = result["resolved"][0]
    assert row["resolution"] == "EXACT_INDIRECT_TARGET"
    assert row["recognition"] == "deterministic"
    assert row["analysis_precision"] == "EXACT"
    assert row["target"]["function_id"] == "fn:00009000"
    assert row["original_actual_arguments"] == actuals


def test_three_targets_emit_all_may_relations_and_preserve_actuals():
    facts, memory, dispatch, actuals = finite_callind_fixture(3)

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["counts"] == {
        "callind": 1,
        "resolved": 3,
        "ambiguous": 0,
        "unresolved": 0,
    }
    rows = result["resolved"]
    assert {row["target"]["function_id"] for row in rows} == {
        "fn:00009000",
        "fn:00009020",
        "fn:00009040",
    }
    assert {row["resolution"] for row in rows} == {"FINITE_TABLE_MAY_TARGET"}
    assert {row["recognition"] for row in rows} == {"heuristic"}
    assert {row["analysis_precision"] for row in rows} == {"MAY"}
    assert {row["candidate_count"] for row in rows} == {3}
    assert {row["callsite"]["site_id"] for row in rows} == {dispatch["site_id"]}
    for row in rows:
        assert row["original_actual_arguments"] == actuals
        assert [binding["actual_value_id"] for binding in row["argument_bindings"]] == [
            actuals[0]["value_id"],
            actuals[1]["value_id"],
        ]
        assert [
            binding["target_formal_object_id"]
            for binding in row["argument_bindings"]
        ] == [
            f"param:{int(row['target']['address'], 0):08x}:0",
            f"param:{int(row['target']['address'], 0):08x}:1",
        ]


def test_repeated_slots_with_one_executable_function_are_exact():
    facts, memory, _, _ = finite_callind_fixture(3, duplicate_target=True)

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert len(result["resolved"]) == 1
    row = result["resolved"][0]
    assert row["resolution"] == "EXACT_INDIRECT_TARGET"
    assert len(row["slots"]) == 3


def test_literal_pool_base_and_rwx_load_segment_keep_readonly_object_proof():
    facts, memory, _, _ = finite_callind_fixture(1)
    dispatch_function = facts["functions"][0]
    ptradd = next(
        row for row in dispatch_function["pcode_ops"] if row["mnemonic"] == "PTRADD"
    )
    literal_base = ptradd["inputs"][0]
    literal_base.update(
        {
            "offset": "0x6000",
            "is_constant": False,
            "is_address": True,
        }
    )
    table_region = next(row for row in memory.regions if row.start == 0x7000)
    text_region = next(row for row in memory.regions if row.start == 0x9000)
    memory = resolver.InitializedMemory.from_regions(
        [
            resolver.MemoryRegion(
                0x6000,
                word(0x7000),
                source="elf:fixture:literal-pool",
                executable=True,
            ),
            resolver.MemoryRegion(
                table_region.start,
                table_region.data,
                source=table_region.source,
                # MCU ELF files commonly expose one RWX load segment even
                # though the table's section-level object is read-only.
                writable=True,
            ),
            text_region,
        ],
        symbols=memory.symbols,
    )

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert len(result["resolved"]) == 1
    assert result["resolved"][0]["target"]["function_id"] == "fn:00009000"
    assert result["resolved"][0]["analysis_precision"] == "EXACT"


def test_writable_table_is_rejected_with_explicit_blocker():
    facts, memory, _, _ = finite_callind_fixture(3, writable_table=True)

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["resolved"] == []
    assert result["counts"]["unresolved"] == 1
    assert result["unresolved"][0]["reason"] == (
        "finite_table_immutable_object_not_unique"
    )


def test_over_budget_preserves_complete_candidate_set_and_emits_no_guess():
    facts, memory, _, _ = finite_callind_fixture(33)

    result = resolver.resolve_device_dispatches(
        facts,
        initialized_memory=memory,
        max_finite_callind_targets=32,
    )

    assert result["resolved"] == []
    assert result["ambiguous"] == []
    assert len(result["unresolved"]) == 1
    blocker = result["unresolved"][0]
    assert blocker["reason"] == "function_table_candidate_budget_exceeded"
    assert blocker["budget"] == {
        "kind": "finite_function_table_targets",
        "limit": 32,
        "candidate_count": 33,
        "truncated": False,
    }
    assert len(blocker["candidates"]) == 33
    assert len({row["target"]["function_id"] for row in blocker["candidates"]}) == 33


def minimal_channel_graph(call_edge):
    function_nodes = [
        {"node_id": "fn:00001200", "node_kind": "FUNCTION"},
        {"node_id": "fn:00009000", "node_kind": "FUNCTION"},
    ]
    return {
        "schema_version": "ct-mini-channel-graph-v4",
        "strict_traversal_surface": "channel_edges",
        "source_associations": [],
        "shared_objects": [],
        "function_nodes": function_nodes,
        "object_nodes": [],
        "nodes": function_nodes,
        "call_edges": [call_edge],
        "channel_edges": [],
        "edges": [call_edge],
        "candidate_channel_edges": [],
        "channel_blockers": [],
        "value_object_bindings": [],
        "counts": {
            "function_nodes": 2,
            "shared_objects": 0,
            "call_edges": 1,
            "channel_edges": 0,
        },
    }


def test_channel_graph_schema_accepts_only_marked_finite_may_call_edges():
    schema = json.loads(
        (ROOT / "schemas" / "channel_graph.v4.schema.json").read_text()
    )
    validator = Draft202012Validator(schema)
    edge = {
        "edge_id": "callind:site:00001200:00001210:fn:00009000",
        "src_node_id": "fn:00001200",
        "dst_node_id": "fn:00009000",
        "edge_kind": "CALLIND",
        "site_id": "site:00001200:00001210:4",
        "resolution": "FINITE_TABLE_MAY_TARGET",
        "recognition": "heuristic",
        "analysis_precision": "MAY",
        "argument_bindings": [{"argument_index": 0}],
        "bound_output_effects": [],
    }
    validator.validate(minimal_channel_graph(edge))

    for field, invalid_value in (
        ("recognition", "deterministic"),
        ("analysis_precision", "EXACT"),
    ):
        invalid = dict(edge)
        invalid[field] = invalid_value
        with pytest.raises(ValidationError):
            validator.validate(minimal_channel_graph(invalid))
