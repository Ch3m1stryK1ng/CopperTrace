from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import body_sink_heuristics as heuristics  # noqa: E402
from check_binding import ProgramCheckIndex  # noqa: E402


def node(
    name: str,
    *,
    slot: int | None = None,
    pointer: bool = False,
    constant: int | None = None,
    size: int = 4,
) -> dict:
    if constant is not None:
        return {
            "object_id": f"const:{constant:x}:{size}",
            "value_id": f"const:{constant:x}:{size}",
            "space": "const",
            "offset": hex(constant),
            "size": size,
            "high_name": "",
            "high_data_type": "",
            "is_parameter": False,
            "parameter_slot": None,
            "is_constant": True,
            "is_address": pointer,
        }
    return {
        "object_id": f"param:1000:{slot}" if slot is not None else f"unique:{name}:{size}",
        "value_id": f"value:{name}",
        "space": "register" if slot is not None else "unique",
        "offset": "0x0",
        "size": size,
        "high_name": name,
        "high_data_type": "uint8_t *" if pointer else "uint32_t",
        "is_parameter": slot is not None,
        "parameter_slot": slot,
        "is_constant": False,
        "is_address": False,
    }


def op(
    site: str,
    mnemonic: str,
    inputs: list[dict],
    output: dict | None,
    *,
    order: int,
    block_id: str = "b0",
) -> dict:
    return {
        "site_id": site,
        "block_id": block_id,
        "instruction_address": hex(0x1000 + order * 2),
        "op_order": order,
        "mnemonic": mnemonic,
        "inputs": inputs,
        "output": output,
    }


def call_op(
    site: str,
    callee: str,
    actuals: list[dict],
    *,
    order: int,
) -> dict:
    row = op(
        site,
        "CALL",
        [node("target", constant=0x2000, pointer=True), *actuals],
        None,
        order=order,
    )
    row["call"] = {
        "kind": "CALL",
        "target_address": "0x2000",
        "target_function": callee,
        "target_function_id": "fn:00002000",
        "argument_value_ids": [str(item.get("value_id", "")) for item in actuals],
    }
    return row


def function(
    ops: list[dict], *, arity: int = 4, blocks: list[dict] | None = None
) -> dict:
    return {
        "function_id": "fn:00001000",
        "name": "parse_message",
        "entry": "0x1000",
        "parameters": [
            {
                "index": index,
                "name": f"arg{index}",
                "data_type": "uint8_t *" if index == 0 else "uint32_t",
            }
            for index in range(arity)
        ],
        "basic_blocks": blocks or [
            {
                "block_id": "b0",
                "index": 0,
                "start": "0x1000",
                "stop": "0x10ff",
                "predecessor_block_ids": [],
                "successor_block_ids": [],
                "true_successor_block_id": "",
                "false_successor_block_id": "",
            }
        ],
        "pcode_ops": ops,
    }


def facts(fn: dict, *, memory_blocks: list[dict] | None = None) -> dict:
    return {
        "schema_version": "ct-mini-ghidra-high-pcode-cfg-v1",
        "binary": "/tmp/parser.elf",
        "binary_sha256": "b" * 64,
        "functions": [fn],
        "memory_blocks": memory_blocks or [],
    }


def association(
    atom: dict,
    *,
    role: str = "",
    state_kind: str = "VALUE",
    definition: str = "source-definition:one",
    extent_for_role: str = "",
) -> dict:
    return {
        "association_id": f"association:{atom['value_id']}:{role}",
        "source_definition_id": definition,
        "source_id": "SO0001",
        "source_decision": "ACCEPT_DETERMINISTIC",
        "state_kind": state_kind,
        "function_id": "fn:00001000",
        "atom_id": atom["value_id"],
        "object_id": atom.get("object_id", ""),
        "source_output_role": role,
        "extent_for_role": extent_for_role,
        "precision": "EXACT",
    }


def analyze(fn: dict, associations: list[dict], *, memory_blocks=None) -> dict:
    return heuristics.analyze_program_facts(
        facts(fn, memory_blocks=memory_blocks),
        source_associations=associations,
        enabled_methods={"parser_oob_read"},
        method_specs={
            "parser_oob_read": {
                "range_read_primitives": [
                    {"name": "memcmp", "read_pointer_args": [0, 1], "length_arg": 2}
                ]
            }
        },
    )


def test_accepts_source_derived_direct_load_offset() -> None:
    packet = node("packet", slot=0, pointer=True)
    offset = node("offset", slot=1)
    address = node("address", pointer=True)
    loaded = node("loaded", size=1)
    fn = function(
        [
            op("site:add", "INT_ADD", [packet, offset], address, order=1),
            op(
                "site:load", "LOAD", [node("ram", constant=0x1A1), address],
                loaded, order=2,
            ),
        ]
    )
    result = analyze(fn, [association(offset)])
    sinks = result["heuristic_sink_calls"]
    assert len(sinks) == 1
    assert sinks[0]["label"] == "PARSER_OOB_READ_SINK"
    assert sinks[0]["recognition"] == "heuristic"
    assert sinks[0]["vulnerable_parameter_roles"] == ["offset"]
    assert sinks[0]["proof"]["admission"]["admission_path"] == (
        "SOURCE_DERIVED_ADDRESS_OR_WIDTH"
    )


def test_accepts_range_read_with_source_derived_width_and_prunes_rodata_side() -> None:
    packet = node("packet", slot=0, pointer=True)
    offset = node("offset", slot=1)
    width = node("width", slot=2)
    address = node("address", pointer=True)
    rodata = node("literal", constant=0x8000, pointer=True)
    fn = function(
        [
            op("site:add", "PTRADD", [packet, offset, node("one", constant=1)], address, order=1),
            call_op("site:memcmp", "memcmp", [address, rodata, width], order=2),
        ]
    )
    result = analyze(
        fn,
        [association(width)],
        memory_blocks=[
            {
                "name": ".rodata",
                "start": "0x8000",
                "end": "0x8fff",
                "read": True,
                "write": False,
                "initialized": True,
            }
        ],
    )
    sinks = result["heuristic_sink_calls"]
    assert len(sinks) == 1
    assert sinks[0]["site_id"] == "site:memcmp"
    assert sinks[0]["vulnerable_parameter_roles"] == ["width"]
    assert sinks[0]["proof"]["read_effect"]["read_operand_index"] == 0


def test_accepts_fixed_read_with_same_source_extent_contract() -> None:
    packet = node("packet", slot=0, pointer=True)
    available = node("available", slot=1)
    address = node("address", pointer=True)
    loaded = node("loaded", size=2)
    fn = function(
        [
            op("site:add", "PTRSUB", [packet, node("thirteen", constant=13)], address, order=1),
            op(
                "site:load", "LOAD", [node("ram", constant=0x1A1), address],
                loaded, order=2,
            ),
        ]
    )
    result = analyze(
        fn,
        [
            association(packet, role="output_buffer", state_kind="MEMORY_CONTENT"),
            association(
                available,
                role="available_length",
                extent_for_role="output_buffer",
            ),
        ],
    )
    sinks = result["heuristic_sink_calls"]
    assert len(sinks) == 1
    assert sinks[0]["vulnerable_parameter_roles"] == ["available_length"]
    assert sinks[0]["proof"]["read_effect"]["fixed_offset"] == 13
    assert sinks[0]["proof"]["admission"]["admission_path"] == (
        "SAME_SOURCE_BUFFER_AND_AVAILABLE_LENGTH_CONTRACT"
    )


def test_rejects_fixed_read_without_extent_contract() -> None:
    packet = node("packet", slot=0, pointer=True)
    address = node("address", pointer=True)
    loaded = node("loaded", size=1)
    fn = function(
        [
            op("site:add", "PTRSUB", [packet, node("four", constant=4)], address, order=1),
            op(
                "site:load", "LOAD", [node("ram", constant=0x1A1), address],
                loaded, order=2,
            ),
        ]
    )
    result = analyze(
        fn,
        [association(packet, role="output_buffer", state_kind="MEMORY_CONTENT")],
    )
    assert result["heuristic_sink_calls"] == []
    assert any(
        row["reason_code"] == "no_source_derived_address_or_buffer_extent_contract"
        for row in result["candidates"]
    )


def test_rejects_fixed_field_read_from_source_associated_object_pointer() -> None:
    handle = node("handle", slot=0, pointer=True)
    address = node("field_address", pointer=True)
    loaded = node("field_value", size=1)
    fn = function(
        [
            op(
                "site:field",
                "PTRADD",
                [handle, node("field", constant=15), node("one", constant=1)],
                address,
                order=1,
            ),
            op(
                "site:load",
                "LOAD",
                [node("ram", constant=0x1A1), address],
                loaded,
                order=2,
            ),
        ]
    )
    result = analyze(fn, [association(handle, state_kind="VALUE")])
    assert result["heuristic_sink_calls"] == []


def test_rejects_unrelated_load() -> None:
    local = node("local", pointer=True)
    loaded = node("loaded", size=1)
    fn = function(
        [
            op(
                "site:load", "LOAD", [node("ram", constant=0x1A1), local],
                loaded, order=1,
            )
        ]
    )
    result = analyze(fn, [])
    assert result["heuristic_sink_calls"] == []
    assert result["candidates"] == []


def loop_controlled_read_fixture() -> tuple[dict, dict]:
    packet = node("packet", slot=0, pointer=True)
    count = node("count", slot=1)
    pointer_phi = node("pointer_phi", pointer=True)
    count_phi = node("count_phi")
    pointer_update = node("pointer_update", pointer=True)
    count_update = node("count_update")
    address = node("record_field", pointer=True)
    condition = node("loop_condition", size=1)
    loaded = node("record_length", size=1)
    operations = [
        op(
            "site:pointer_phi",
            "MULTIEQUAL",
            [packet, pointer_update],
            pointer_phi,
            order=1,
            block_id="header",
        ),
        op(
            "site:count_phi",
            "MULTIEQUAL",
            [count, count_update],
            count_phi,
            order=2,
            block_id="header",
        ),
        op(
            "site:cmp",
            "INT_NOTEQUAL",
            [count_phi, node("zero", constant=0)],
            condition,
            order=3,
            block_id="header",
        ),
        op(
            "site:branch",
            "CBRANCH",
            [node("exit", constant=0x1080), condition],
            None,
            order=4,
            block_id="header",
        ),
        op(
            "site:address",
            "PTRADD",
            [pointer_phi, node("field", constant=23), node("one", constant=1)],
            address,
            order=5,
            block_id="body",
        ),
        op(
            "site:load",
            "LOAD",
            [node("ram", constant=0x1A1), address],
            loaded,
            order=6,
            block_id="body",
        ),
        op(
            "site:pointer_update",
            "PTRADD",
            [pointer_phi, node("stride", constant=24), node("one2", constant=1)],
            pointer_update,
            order=7,
            block_id="body",
        ),
        op(
            "site:count_update",
            "INT_SUB",
            [count_phi, node("decrement", constant=1)],
            count_update,
            order=8,
            block_id="body",
        ),
    ]
    fn = function(
        operations,
        blocks=[
            {
                "block_id": "entry",
                "index": 0,
                "start": "0x1000",
                "stop": "0x100f",
                "predecessor_block_ids": [],
                "successor_block_ids": ["header"],
            },
            {
                "block_id": "header",
                "index": 1,
                "start": "0x1010",
                "stop": "0x103f",
                "predecessor_block_ids": ["entry", "body"],
                "successor_block_ids": ["body", "exit"],
                "true_successor_block_id": "body",
                "false_successor_block_id": "exit",
            },
            {
                "block_id": "body",
                "index": 2,
                "start": "0x1040",
                "stop": "0x107f",
                "predecessor_block_ids": ["header"],
                "successor_block_ids": ["header"],
            },
            {
                "block_id": "exit",
                "index": 3,
                "start": "0x1080",
                "stop": "0x108f",
                "predecessor_block_ids": ["header"],
                "successor_block_ids": [],
            },
        ],
    )
    return fn, count


def test_accepts_source_controlled_loop_carried_parser_read() -> None:
    fn, count = loop_controlled_read_fixture()
    result = analyze(fn, [association(count)])
    sinks = result["heuristic_sink_calls"]
    assert len(sinks) == 1
    assert sinks[0]["site_id"] == "site:load"
    assert sinks[0]["vulnerable_parameter_roles"] == ["index"]
    assert sinks[0]["proof"]["admission"]["admission_path"] == (
        "SOURCE_DERIVED_LOOP_CONTROL"
    )


def test_rejects_internal_loop_carried_parser_read() -> None:
    fn, _count = loop_controlled_read_fixture()
    result = analyze(fn, [])
    assert result["heuristic_sink_calls"] == []


def guarded_read_fixture(*, mutation: bool = False) -> tuple[dict, list[dict]]:
    packet = node("packet", slot=0, pointer=True)
    offset = node("offset", slot=1)
    available = node("available", slot=2)
    address = node("address", pointer=True)
    condition = node("condition", size=1)
    loaded = node("loaded", size=1)
    operations = [
        op("site:add", "PTRADD", [packet, offset, node("one", constant=1)], address, order=1),
        op("site:cmp", "INT_LESS", [offset, available], condition, order=2),
        op(
            "site:branch",
            "CBRANCH",
            [node("target", constant=0x1020), condition],
            None,
            order=3,
        ),
    ]
    if mutation:
        operations.append(
            call_op("site:mutation", "unknown_mutator", [packet], order=4)
        )
        operations[-1]["block_id"] = "b1"
    operations.append(
        op(
            "site:load",
            "LOAD",
            [node("ram", constant=0x1A1), address],
            loaded,
            order=5,
            block_id="b1",
        )
    )
    fn = function(
        operations,
        blocks=[
            {
                "block_id": "b0",
                "index": 0,
                "start": "0x1000",
                "stop": "0x101f",
                "predecessor_block_ids": [],
                "successor_block_ids": ["b1", "b2"],
                "true_successor_block_id": "b1",
                "false_successor_block_id": "b2",
            },
            {
                "block_id": "b1",
                "index": 1,
                "start": "0x1020",
                "stop": "0x103f",
                "predecessor_block_ids": ["b0"],
                "successor_block_ids": [],
                "true_successor_block_id": "",
                "false_successor_block_id": "",
            },
            {
                "block_id": "b2",
                "index": 2,
                "start": "0x1040",
                "stop": "0x104f",
                "predecessor_block_ids": ["b0"],
                "successor_block_ids": [],
                "true_successor_block_id": "",
                "false_successor_block_id": "",
            },
        ],
    )
    associations = [
        association(offset),
        association(packet, role="output_buffer", state_kind="MEMORY_CONTENT"),
        association(
            available,
            role="available_length",
            extent_for_role="output_buffer",
        ),
    ]
    return fn, associations


def test_dominating_same_ssa_range_check_is_review_evidence_only() -> None:
    fn, associations = guarded_read_fixture()
    program = facts(fn)
    result = heuristics.analyze_program_facts(
        program,
        source_associations=associations,
        enabled_methods={"parser_oob_read"},
        method_specs={"parser_oob_read": {"range_read_primitives": []}},
    )
    sink = result["heuristic_sink_calls"][0]
    check = ProgramCheckIndex(program).bind_sink(sink)
    assert check["status"] == "CAPACITY_SAFE"
    assert check["hard_drop"] is False
    assert check["offline_filter_eligible"] is False
    assert check["capacity_proof"]["required_operand_kind"] == "last_index"


def test_mutation_between_check_and_read_is_unknown() -> None:
    fn, associations = guarded_read_fixture(mutation=True)
    program = facts(fn)
    result = heuristics.analyze_program_facts(
        program,
        source_associations=associations,
        enabled_methods={"parser_oob_read"},
        method_specs={"parser_oob_read": {"range_read_primitives": []}},
    )
    sink = result["heuristic_sink_calls"][0]
    check = ProgramCheckIndex(program).bind_sink(sink)
    assert check["status"] == "UNKNOWN"
    assert check["hard_drop"] is False
    assert check["parameter_checks"][0]["mutation_sites_between_check_and_read"] == [
        "site:mutation"
    ]


def test_parser_read_without_related_check_is_missing() -> None:
    packet = node("packet", slot=0, pointer=True)
    offset = node("offset", slot=1)
    address = node("address", pointer=True)
    loaded = node("loaded", size=1)
    fn = function(
        [
            op("site:add", "INT_ADD", [packet, offset], address, order=1),
            op(
                "site:load", "LOAD", [node("ram", constant=0x1A1), address],
                loaded, order=2,
            ),
        ]
    )
    program = facts(fn)
    result = analyze(fn, [association(offset)])
    check = ProgramCheckIndex(program).bind_sink(result["heuristic_sink_calls"][0])
    assert check["status"] == "MISSING"
    assert check["hard_drop"] is False
