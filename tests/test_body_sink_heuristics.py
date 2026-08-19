from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import body_sink_heuristics as heuristics  # noqa: E402


def node(
    name: str,
    *,
    slot: int | None = None,
    constant: int | None = None,
    size: int = 4,
    data_type: str = "",
) -> dict:
    if constant is not None:
        return {
            "object_id": f"const:{constant:x}:{size}",
            "value_id": f"const:{constant:x}:{size}",
            "space": "const",
            "offset": hex(constant),
            "size": size,
            "high_name": "",
            "high_data_type": data_type,
            "is_parameter": False,
            "parameter_slot": None,
            "is_constant": True,
        }
    return {
        "object_id": f"param:1000:{slot}" if slot is not None else f"unique:{name}:{size}",
        "value_id": f"value:{name}",
        "space": "register" if slot is not None else "unique",
        "offset": "0x0",
        "size": size,
        "high_name": name,
        "high_data_type": data_type,
        "is_parameter": slot is not None,
        "parameter_slot": slot,
        "is_constant": False,
    }


def op(
    site: str,
    mnemonic: str,
    inputs: list[dict],
    output: dict | None,
    *,
    block: str,
    address: int,
    order: int,
) -> dict:
    return {
        "site_id": site,
        "block_id": block,
        "instruction_address": hex(address),
        "op_order": order,
        "mnemonic": mnemonic,
        "inputs": inputs,
        "output": output,
    }


def block(
    block_id: str,
    index: int,
    successors: list[str],
    *,
    true_successor: str = "",
    false_successor: str = "",
) -> dict:
    row = {
        "block_id": block_id,
        "index": index,
        "start": hex(0x1000 + index * 0x10),
        "end": hex(0x1000 + index * 0x10 + 0xF),
        "successors": successors,
    }
    if true_successor:
        row["true_successor"] = true_successor
    if false_successor:
        row["false_successor"] = false_successor
    return row


def function(
    ops: list[dict],
    blocks: list[dict],
    *,
    name: str = "f_1000",
    arity: int = 4,
) -> dict:
    return {
        "function_id": "fn:00001000",
        "name": name,
        "entry": "0x1000",
        "parameters": [
            {"index": index, "name": f"arg{index}", "data_type": "void *"}
            for index in range(arity)
        ],
        "basic_blocks": blocks,
        "pcode_ops": ops,
    }


def call_op(
    site: str,
    target_id: str,
    target_name: str,
    actuals: list[dict],
) -> dict:
    return {
        "site_id": site,
        "instruction_address": "0x2000",
        "op_order": 1,
        "mnemonic": "CALL",
        "inputs": [node("target", constant=0x1000), *actuals],
        "output": None,
        "call": {
            "kind": "CALL",
            "target_address": "0x1000",
            "target_function": target_name,
            "target_function_id": target_id,
            "argument_object_ids": [
                str(actual.get("object_id", "")) for actual in actuals
            ],
            "argument_value_ids": [
                str(actual.get("value_id", "")) for actual in actuals
            ],
        },
    }


def facts(fn: dict, *, memory_blocks: list[dict] | None = None) -> dict:
    return {
        "schema_version": "ct-mini-ghidra-high-pcode-cfg-v1",
        "binary": "/tmp/synthetic.elf",
        "binary_sha256": "a" * 64,
        "functions": [fn],
        "memory_blocks": memory_blocks or [],
    }


def loop_blocks(
    *,
    header: str = "b1",
    body: str = "b2",
) -> list[dict]:
    return [
        block("b0", 0, [header]),
        block(header, 1, [body, "b3"], true_successor=body, false_successor="b3"),
        block(body, 2, [header]),
        block("b3", 3, []),
    ]


def exported_v4_loop_blocks() -> list[dict]:
    """Use the exact CFG key names emitted by ghidra_export_source_facts.py."""

    return [
        {
            "block_id": "b0",
            "index": 0,
            "start": "0x1000",
            "stop": "0x100f",
            "predecessor_block_ids": [],
            "successor_block_ids": ["b1"],
            "true_successor_block_id": "",
            "false_successor_block_id": "",
        },
        {
            "block_id": "b1",
            "index": 1,
            "start": "0x1010",
            "stop": "0x101f",
            "predecessor_block_ids": ["b0", "b2"],
            "successor_block_ids": ["b2", "b3"],
            "true_successor_block_id": "b2",
            "false_successor_block_id": "b3",
        },
        {
            "block_id": "b2",
            "index": 2,
            "start": "0x1020",
            "stop": "0x102f",
            "predecessor_block_ids": ["b1"],
            "successor_block_ids": ["b1"],
            "true_successor_block_id": "",
            "false_successor_block_id": "",
        },
        {
            "block_id": "b3",
            "index": 3,
            "start": "0x1030",
            "stop": "0x103f",
            "predecessor_block_ids": ["b1"],
            "successor_block_ids": [],
            "true_successor_block_id": "",
            "false_successor_block_id": "",
        },
    ]


def counted_array_ops(
    *,
    transformed: bool = False,
    fill: bool = False,
    fill_constant: bool = False,
    bound_constant: bool = False,
    source_scale: int = 1,
    include_exit_compare: bool = True,
    load_address: dict | None = None,
) -> list[dict]:
    dst = node("dst", slot=0, data_type="uint8_t *")
    src = node("src", slot=1, data_type="uint8_t *")
    count = node("count", slot=2) if not bound_constant else node("four", constant=4)
    fill_value = (
        node("fill_byte", constant=0, size=1)
        if fill_constant
        else node("fill", slot=3)
    )
    zero = node("zero", constant=0)
    one = node("one", constant=1)
    source_scale_node = node("source_scale", constant=source_scale)
    ram = node("ram", constant=0x1A1)
    index_phi = node("index_phi")
    index_next = node("index_next")
    condition = node("condition", size=1)
    dst_address = node("dst_address", data_type="uint8_t *")
    src_address = node("src_address", data_type="uint8_t *")
    loaded = node("loaded", size=1)
    transformed_value = node("transformed", size=1)
    rows = [
        op(
            "site:phi",
            "MULTIEQUAL",
            [zero, index_next],
            index_phi,
            block="b1",
            address=0x1010,
            order=1,
        )
    ]
    if include_exit_compare:
        rows.extend(
            [
                op(
                    "site:cmp",
                    "INT_LESS",
                    [index_phi, count],
                    condition,
                    block="b1",
                    address=0x1012,
                    order=2,
                ),
                op(
                    "site:branch",
                    "CBRANCH",
                    [node("target", constant=0x1030), condition],
                    None,
                    block="b1",
                    address=0x1014,
                    order=3,
                ),
            ]
        )
    rows.append(
        op(
            "site:dst-address",
            "PTRADD",
            [dst, index_phi, one],
            dst_address,
            block="b2",
            address=0x1020,
            order=4,
        )
    )
    stored = fill_value
    if not fill:
        if load_address is None:
            rows.append(
                op(
                    "site:src-address",
                    "PTRADD",
                    [src, index_phi, source_scale_node],
                    src_address,
                    block="b2",
                    address=0x1022,
                    order=5,
                )
            )
            actual_load_address = src_address
        else:
            actual_load_address = load_address
        rows.append(
            op(
                "site:load",
                "LOAD",
                [ram, actual_load_address],
                loaded,
                block="b2",
                address=0x1024,
                order=6,
            )
        )
        stored = loaded
        if transformed:
            rows.append(
                op(
                    "site:transform",
                    "INT_XOR",
                    [loaded, node("mask", constant=0xFF)],
                    transformed_value,
                    block="b2",
                    address=0x1026,
                    order=7,
                )
            )
            stored = transformed_value
    rows.extend(
        [
            op(
                "site:store",
                "STORE",
                [ram, dst_address, stored],
                None,
                block="b2",
                address=0x1028,
                order=8,
            ),
            op(
                "site:increment",
                "INT_ADD",
                [index_phi, one],
                index_next,
                block="b2",
                address=0x102A,
                order=9,
            ),
        ]
    )
    return rows


def counted_pointer_ops() -> list[dict]:
    dst = node("dst", slot=0, data_type="uint8_t *")
    src = node("src", slot=1, data_type="uint8_t *")
    count = node("count", slot=2)
    zero = node("zero", constant=0)
    one = node("one", constant=1)
    ram = node("ram", constant=0x1A1)
    index_phi = node("index_phi")
    index_next = node("index_next")
    dst_phi = node("dst_phi", data_type="uint8_t *")
    dst_next = node("dst_next", data_type="uint8_t *")
    src_phi = node("src_phi", data_type="uint8_t *")
    src_next = node("src_next", data_type="uint8_t *")
    loaded = node("loaded", size=1)
    condition = node("condition", size=1)
    return [
        op("site:i-phi", "MULTIEQUAL", [zero, index_next], index_phi, block="b1", address=0x1010, order=1),
        op("site:dst-phi", "MULTIEQUAL", [dst, dst_next], dst_phi, block="b1", address=0x1010, order=2),
        op("site:src-phi", "MULTIEQUAL", [src, src_next], src_phi, block="b1", address=0x1010, order=3),
        op("site:cmp", "INT_LESS", [index_phi, count], condition, block="b1", address=0x1012, order=4),
        op("site:branch", "CBRANCH", [node("target", constant=0x1030), condition], None, block="b1", address=0x1014, order=5),
        op("site:load", "LOAD", [ram, src_phi], loaded, block="b2", address=0x1020, order=6),
        op("site:store", "STORE", [ram, dst_phi, loaded], None, block="b2", address=0x1022, order=7),
        op("site:i-next", "INT_ADD", [index_phi, one], index_next, block="b2", address=0x1024, order=8),
        op("site:dst-next", "PTRADD", [dst_phi, one, one], dst_next, block="b2", address=0x1026, order=9),
        op("site:src-next", "PTRADD", [src_phi, one, one], src_next, block="b2", address=0x1028, order=10),
    ]


def opposite_pointer_copy_ops() -> list[dict]:
    dst = node("dst", slot=0, data_type="uint8_t *")
    src = node("src", slot=1, data_type="uint8_t *")
    end = node("end", slot=2, data_type="uint8_t *")
    one = node("one", constant=1)
    minus_one = node("minus_one", constant=0xFFFFFFFF)
    ram = node("ram", constant=0x1A1)
    dst_phi = node("dst_phi", data_type="uint8_t *")
    dst_next = node("dst_next", data_type="uint8_t *")
    src_phi = node("src_phi", data_type="uint8_t *")
    src_next = node("src_next", data_type="uint8_t *")
    loaded = node("loaded", size=1)
    condition = node("condition", size=1)
    return [
        op("site:dst-phi", "MULTIEQUAL", [dst, dst_next], dst_phi, block="b1", address=0x1010, order=1),
        op("site:src-phi", "MULTIEQUAL", [src, src_next], src_phi, block="b1", address=0x1010, order=2),
        op("site:load", "LOAD", [ram, src_phi], loaded, block="b1", address=0x1012, order=3),
        op("site:store", "STORE", [ram, dst_phi, loaded], None, block="b1", address=0x1014, order=4),
        op("site:dst-next", "PTRADD", [dst_phi, one, one], dst_next, block="b1", address=0x1016, order=5),
        op("site:src-next", "PTRADD", [src_phi, minus_one, one], src_next, block="b1", address=0x1018, order=6),
        op("site:cmp", "INT_NOTEQUAL", [dst_next, end], condition, block="b1", address=0x101A, order=7),
        op("site:branch", "CBRANCH", [node("target", constant=0x1010), condition], None, block="b1", address=0x101C, order=8),
    ]


def counted_countdown_ops() -> list[dict]:
    dst = node("dst", slot=0, data_type="uint8_t *")
    src = node("src", slot=1, data_type="uint8_t *")
    count = node("count", slot=2)
    zero = node("zero", constant=0)
    one = node("one", constant=1)
    ram = node("ram", constant=0x1A1)
    remaining_phi = node("remaining_phi")
    remaining_next = node("remaining_next")
    dst_phi = node("dst_phi", data_type="uint8_t *")
    dst_next = node("dst_next", data_type="uint8_t *")
    src_phi = node("src_phi", data_type="uint8_t *")
    src_next = node("src_next", data_type="uint8_t *")
    loaded = node("loaded", size=1)
    condition = node("condition", size=1)
    return [
        op("site:remaining-phi", "MULTIEQUAL", [count, remaining_next], remaining_phi, block="b1", address=0x1010, order=1),
        op("site:dst-phi", "MULTIEQUAL", [dst, dst_next], dst_phi, block="b1", address=0x1010, order=2),
        op("site:src-phi", "MULTIEQUAL", [src, src_next], src_phi, block="b1", address=0x1010, order=3),
        op("site:cmp", "INT_NOTEQUAL", [remaining_phi, zero], condition, block="b1", address=0x1012, order=4),
        op("site:branch", "CBRANCH", [node("target", constant=0x1030), condition], None, block="b1", address=0x1014, order=5),
        op("site:load", "LOAD", [ram, src_phi], loaded, block="b2", address=0x1020, order=6),
        op("site:store", "STORE", [ram, dst_phi, loaded], None, block="b2", address=0x1022, order=7),
        op("site:remaining-next", "INT_SUB", [remaining_phi, one], remaining_next, block="b2", address=0x1024, order=8),
        op("site:dst-next", "PTRADD", [dst_phi, one, one], dst_next, block="b2", address=0x1026, order=9),
        op("site:src-next", "PTRADD", [src_phi, one, one], src_next, block="b2", address=0x1028, order=10),
    ]


def fixed_same_base_fill_ops() -> list[dict]:
    destination = node("destination", slot=0, data_type="uint8_t *")
    minus_one = node("minus_one", constant=0xFFFFFFFF)
    terminal_offset = node("terminal_offset", constant=0xFF)
    one = node("one", constant=1)
    zero = node("zero", constant=0, size=1)
    ram = node("ram", constant=0x1A1)
    start = node("start", data_type="uint8_t *")
    terminal = node("terminal", data_type="uint8_t *")
    cursor_phi = node("cursor_phi", data_type="uint8_t *")
    cursor_next = node("cursor_next", data_type="uint8_t *")
    condition = node("condition", size=1)
    return [
        op("site:start", "PTRADD", [destination, minus_one, one], start, block="b0", address=0x1000, order=1),
        op("site:terminal", "PTRADD", [destination, terminal_offset, one], terminal, block="b0", address=0x1002, order=2),
        op("site:phi", "MULTIEQUAL", [start, cursor_next], cursor_phi, block="b1", address=0x1010, order=3),
        op("site:cmp", "INT_NOTEQUAL", [cursor_phi, terminal], condition, block="b1", address=0x1012, order=4),
        op("site:branch", "CBRANCH", [node("target", constant=0x1030), condition], None, block="b1", address=0x1014, order=5),
        op("site:store", "STORE", [ram, cursor_phi, zero], None, block="b2", address=0x1020, order=6),
        op("site:next", "PTRADD", [cursor_phi, one, one], cursor_next, block="b2", address=0x1022, order=7),
    ]


def sentinel_ops(
    *,
    transformed: bool = False,
    branch_uses_other_load: bool = False,
    advance_destination: bool = True,
    sentinel: int = 0,
) -> list[dict]:
    dst = node("dst", slot=0, data_type="char *")
    src = node("src", slot=1, data_type="char *")
    other = node("other", slot=2, data_type="char *")
    one = node("one", constant=1)
    zero = node("sentinel", constant=sentinel, size=1)
    ram = node("ram", constant=0x1A1)
    dst_phi = node("dst_phi", data_type="char *")
    dst_next = node("dst_next", data_type="char *")
    src_phi = node("src_phi", data_type="char *")
    src_next = node("src_next", data_type="char *")
    value = node("value", size=1)
    other_value = node("other_value", size=1)
    changed = node("changed", size=1)
    condition = node("condition", size=1)
    rows = [
        op("site:dst-phi", "MULTIEQUAL", [dst, dst_next], dst_phi, block="b1", address=0x1010, order=1),
        op("site:src-phi", "MULTIEQUAL", [src, src_next], src_phi, block="b1", address=0x1010, order=2),
        op("site:load", "LOAD", [ram, src_phi], value, block="b1", address=0x1012, order=3),
    ]
    stored = value
    if transformed:
        rows.append(
            op(
                "site:transform",
                "INT_XOR",
                [value, node("mask", constant=0x20, size=1)],
                changed,
                block="b1",
                address=0x1014,
                order=4,
            )
        )
        stored = changed
    if branch_uses_other_load:
        rows.append(
            op(
                "site:other-load",
                "LOAD",
                [ram, other],
                other_value,
                block="b1",
                address=0x1015,
                order=5,
            )
        )
    rows.extend(
        [
            op("site:store", "STORE", [ram, dst_phi if advance_destination else dst, stored], None, block="b1", address=0x1016, order=6),
            op("site:src-next", "PTRADD", [src_phi, one, one], src_next, block="b1", address=0x1018, order=7),
            op("site:dst-next", "PTRADD", [dst_phi, one, one], dst_next, block="b1", address=0x101A, order=8),
            op(
                "site:cmp",
                "INT_NOTEQUAL",
                [other_value if branch_uses_other_load else value, zero],
                condition,
                block="b1",
                address=0x101C,
                order=9,
            ),
            op(
                "site:branch",
                "CBRANCH",
                [node("target", constant=0x1010), condition],
                None,
                block="b1",
                address=0x101E,
                order=10,
            ),
        ]
    )
    return rows


def sentinel_blocks() -> list[dict]:
    return [
        block("b0", 0, ["b1"]),
        block("b1", 1, ["b1", "b2"], true_successor="b1", false_successor="b2"),
        block("b2", 2, []),
    ]


def paired_ops(
    *,
    scalar_delta_slot: int = 1,
    cursor_delta_slot: int = 1,
    scalar_direction: str = "sub",
    cursor_direction: str = "add",
    scalar_block: str = "b0",
    cursor_block: str = "b0",
    cursor_pointer_typed: bool = True,
) -> list[dict]:
    buf = node("buf", slot=0, data_type="struct buffer *")
    scalar_delta = node("scalar_delta", slot=scalar_delta_slot)
    cursor_delta = node("cursor_delta", slot=cursor_delta_slot)
    ram = node("ram", constant=0x1A1)
    one = node("one", constant=1)
    length_offset = node("length_offset", constant=4)
    cursor_offset = node("cursor_offset", constant=8)
    length_address = node("length_address", data_type="uint16_t *")
    cursor_address = node(
        "cursor_address",
        data_type="uint8_t **" if cursor_pointer_typed else "uint32_t *",
    )
    old_length = node("old_length", size=2, data_type="uint16_t")
    old_cursor = node(
        "old_cursor",
        data_type="uint8_t *" if cursor_pointer_typed else "uint32_t",
    )
    new_length = node("new_length", size=2, data_type="uint16_t")
    new_cursor = node(
        "new_cursor",
        data_type="uint8_t *" if cursor_pointer_typed else "uint32_t",
    )
    scalar_op = "INT_SUB" if scalar_direction == "sub" else "INT_ADD"
    cursor_op = (
        "PTRADD"
        if cursor_pointer_typed and cursor_direction == "add"
        else "INT_ADD"
        if cursor_direction == "add"
        else "INT_SUB"
    )
    cursor_inputs = (
        [old_cursor, cursor_delta, one]
        if cursor_op == "PTRADD"
        else [old_cursor, cursor_delta]
    )
    return [
        op("site:length-address", "PTRSUB", [buf, length_offset], length_address, block=scalar_block, address=0x1000, order=1),
        op("site:length-load", "LOAD", [ram, length_address], old_length, block=scalar_block, address=0x1002, order=2),
        op("site:length-update", scalar_op, [old_length, scalar_delta], new_length, block=scalar_block, address=0x1004, order=3),
        op("site:length-store", "STORE", [ram, length_address, new_length], None, block=scalar_block, address=0x1006, order=4),
        op("site:cursor-address", "PTRSUB", [buf, cursor_offset], cursor_address, block=cursor_block, address=0x1008, order=5),
        op("site:cursor-load", "LOAD", [ram, cursor_address], old_cursor, block=cursor_block, address=0x100A, order=6),
        op("site:cursor-update", cursor_op, cursor_inputs, new_cursor, block=cursor_block, address=0x100C, order=7),
        op("site:cursor-store", "STORE", [ram, cursor_address, new_cursor], None, block=cursor_block, address=0x100E, order=8),
    ]


def global_node(name: str, address: int, *, size: int = 4, data_type: str = "") -> dict:
    return {
        "object_id": f"global:{address:08x}:{size}",
        "value_id": f"value:1000:global:{address:08x}:{size}:input:{name}",
        "space": "ram",
        "offset": hex(address),
        "size": size,
        "high_name": name,
        "high_data_type": data_type,
        "is_parameter": False,
        "parameter_slot": None,
        "is_constant": False,
        "is_address": True,
    }


def stateful_loop_ops(
    *,
    pointer_cursor: bool = False,
    transformed: bool = False,
    include_state_update: bool = True,
    source_is_formal: bool = True,
) -> list[dict]:
    src = (
        node("src", slot=0, data_type="uint8_t *")
        if source_is_formal
        else global_node("source_buffer", 0x20000100, data_type="uint8_t *")
    )
    dst = node("dst", slot=1, data_type="uint8_t *")
    state_address = global_node(
        "cursor_state" if pointer_cursor else "index_state",
        0x20000020,
        data_type="uint8_t **" if pointer_cursor else "uint32_t *",
    )
    ram = node("ram", constant=0x1A1)
    one = node("one", constant=1)
    state = node(
        "state",
        data_type="uint8_t *" if pointer_cursor else "uint32_t",
    )
    next_state = node(
        "next_state",
        data_type="uint8_t *" if pointer_cursor else "uint32_t",
    )
    source_address = node("source_address", data_type="uint8_t *")
    destination = state if pointer_cursor else node(
        "destination", data_type="uint8_t *"
    )
    loaded = node("loaded", size=1, data_type="uint8_t")
    stored = node("stored", size=1, data_type="uint8_t")
    rows = [
        op("site:state-load", "LOAD", [ram, state_address], state, block="b1", address=0x1010, order=1),
        op("site:src-address", "PTRADD", [src, state if not pointer_cursor else one, one], source_address, block="b1", address=0x1012, order=2),
        op("site:src-load", "LOAD", [ram, source_address], loaded, block="b1", address=0x1014, order=3),
    ]
    if not pointer_cursor:
        rows.append(
            op("site:dst-address", "PTRADD", [dst, state, one], destination, block="b1", address=0x1016, order=4)
        )
    if transformed:
        rows.append(
            op("site:transform", "INT_XOR", [loaded, one], stored, block="b1", address=0x1018, order=5)
        )
    else:
        stored = loaded
    rows.append(
        op("site:data-store", "STORE", [ram, destination, stored], None, block="b1", address=0x101A, order=6)
    )
    if include_state_update:
        rows.extend(
            [
                op(
                    "site:state-next",
                    "PTRADD" if pointer_cursor else "INT_ADD",
                    [state, one, one] if pointer_cursor else [state, one],
                    next_state,
                    block="b1",
                    address=0x101C,
                    order=7,
                ),
                op("site:state-store", "STORE", [ram, state_address, next_state], None, block="b1", address=0x101E, order=8),
            ]
        )
    return rows


def reservation_ops(*, return_old_tail: bool = True) -> list[dict]:
    buf = node("buf", slot=0, data_type="struct buffer *")
    amount = node("amount", slot=1, data_type="size_t")
    ram = node("ram", constant=0x1A1)
    one = node("one", constant=1)
    length_address = node("length_address", data_type="uint16_t *")
    data_address = node("data_address", data_type="uint8_t **")
    old_length = node("old_length", size=2, data_type="uint16_t")
    data_pointer = node("data_pointer", data_type="uint8_t *")
    new_length = node("new_length", size=2, data_type="uint16_t")
    tail = node("tail", data_type="uint8_t *")
    returned = tail if return_old_tail else data_pointer
    return [
        op("site:length-address", "PTRSUB", [buf, node("four", constant=4)], length_address, block="b0", address=0x1000, order=1),
        op("site:length-load", "LOAD", [ram, length_address], old_length, block="b0", address=0x1002, order=2),
        op("site:data-address", "PTRSUB", [buf, node("zero", constant=0)], data_address, block="b0", address=0x1004, order=3),
        op("site:data-load", "LOAD", [ram, data_address], data_pointer, block="b0", address=0x1006, order=4),
        op("site:length-add", "INT_ADD", [old_length, amount], new_length, block="b0", address=0x1008, order=5),
        op("site:length-store", "STORE", [ram, length_address, new_length], None, block="b0", address=0x100A, order=6),
        op("site:tail", "PTRADD", [data_pointer, old_length, one], tail, block="b0", address=0x100C, order=7),
        op("site:return", "RETURN", [node("space", constant=0), returned], None, block="b0", address=0x100E, order=8),
    ]


def swap_ops(
    *,
    same_buffer: bool = True,
    cross_write: bool = True,
    dynamic_extent: bool = False,
) -> list[dict]:
    buf = node("buf", slot=0, data_type="uint8_t *")
    extent = node("extent", slot=1, data_type="size_t")
    other = node("other", slot=2, data_type="uint8_t *")
    one = node("one", constant=1)
    minus_one = node("minus_one", constant=0xFFFFFFFF)
    eight = node("eight", constant=8)
    three = node("three", constant=3)
    ram = node("ram", constant=0x1A1)
    left_start = node("left_start", data_type="uint8_t *")
    right_start = node("right_start", data_type="uint8_t *")
    terminal = node("terminal", data_type="uint8_t *")
    left_phi = node("left_phi", data_type="uint8_t *")
    right_phi = node("right_phi", data_type="uint8_t *")
    left_next = node("left_next", data_type="uint8_t *")
    right_next = node("right_next", data_type="uint8_t *")
    left_value = node("left_value", size=1, data_type="uint8_t")
    right_value = node("right_value", size=1, data_type="uint8_t")
    condition = node("condition", size=1, data_type="bool")
    right_base = buf if same_buffer else other
    right_offset = extent if dynamic_extent else eight
    terminal_offset = extent if dynamic_extent else three
    left_store_value = right_value if cross_write else left_value
    right_store_value = left_value if cross_write else right_value
    return [
        op("site:left-start", "PTRADD", [buf, minus_one, one], left_start, block="b0", address=0x1000, order=1),
        op("site:right-start", "PTRADD", [right_base, right_offset, one], right_start, block="b0", address=0x1002, order=2),
        op("site:terminal", "PTRADD", [buf, terminal_offset, one], terminal, block="b0", address=0x1004, order=3),
        op("site:left-phi", "MULTIEQUAL", [left_start, left_next], left_phi, block="b1", address=0x1010, order=4),
        op("site:right-phi", "MULTIEQUAL", [right_start, right_next], right_phi, block="b1", address=0x1010, order=5),
        op("site:left-next", "PTRADD", [left_phi, one, one], left_next, block="b1", address=0x1012, order=6),
        op("site:left-load", "LOAD", [ram, left_next], left_value, block="b1", address=0x1014, order=7),
        op("site:right-next", "PTRADD", [right_phi, minus_one, one], right_next, block="b1", address=0x1016, order=8),
        op("site:right-load", "LOAD", [ram, right_next], right_value, block="b1", address=0x1018, order=9),
        op("site:left-store", "STORE", [ram, left_next, left_store_value], None, block="b1", address=0x101A, order=10),
        op("site:right-store", "STORE", [ram, right_next, right_store_value], None, block="b1", address=0x101C, order=11),
        op("site:cmp", "INT_NOTEQUAL", [left_next, terminal], condition, block="b1", address=0x101E, order=12),
        op("site:branch", "CBRANCH", [node("target", constant=0x1010), condition], None, block="b1", address=0x1020, order=13),
    ]


def analyze(fn: dict, **kwargs: dict) -> dict:
    return heuristics.analyze_program_facts(facts(fn), **kwargs)


def reasons(result: dict, pattern: str) -> set[str]:
    return {
        row["reason_code"]
        for row in result["candidates"]
        if row["pattern"] == pattern
    }


class CountedRangeTests(unittest.TestCase):
    def test_body_implementation_is_materialized_at_real_callsite(self) -> None:
        implementation = function(
            counted_array_ops(),
            exported_v4_loop_blocks(),
            name="custom_copy",
            arity=3,
        )
        implementation["function_id"] = "fn:00001000"
        dst = node("caller_dst", slot=0)
        src = node("caller_src", slot=1)
        length = node("caller_len", slot=2)
        caller = {
            "function_id": "fn:00002000",
            "name": "caller",
            "entry": "0x2000",
            "parameters": [],
            "basic_blocks": [],
            "pcode_ops": [
                call_op(
                    "site:00002000:00002010:1",
                    "fn:00001000",
                    "custom_copy",
                    [dst, src, length],
                )
            ],
        }
        program = {
            **facts(implementation),
            "functions": [implementation, caller],
        }
        analyzed = heuristics.analyze_program_facts(program)
        materialized = heuristics.materialize_body_sink_calls(
            program,
            analyzed["heuristic_sink_implementations"],
        )

        rows = materialized["heuristic_sink_calls"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["function"], "caller")
        self.assertEqual(rows[0]["callee"], "custom_copy")
        self.assertEqual(
            rows[0]["site_id"], "site:00002000:00002010:1"
        )
        self.assertEqual(
            [row["role"] for row in rows[0]["vulnerable_parameters"]],
            ["src", "len"],
        )

    def test_exported_v4_cfg_keys_preserve_loop_detection(self) -> None:
        result = analyze(
            function(counted_array_ops(), exported_v4_loop_blocks())
        )

        methods = {
            row["recognition_method"] for row in result["heuristic_sink_calls"]
        }
        self.assertIn("counted_range_copy", methods)

    def test_array_index_copy_is_heuristic_copy_sink(self) -> None:
        result = analyze(function(counted_array_ops(), loop_blocks()))

        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "counted_range_copy"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sink_type"], "COPY_SINK")
        self.assertEqual(rows[0]["recognition"], "heuristic")
        self.assertEqual(
            [row["role"] for row in rows[0]["vulnerable_parameters"]],
            ["src", "len"],
        )
        self.assertEqual(rows[0]["site_id"], "site:store")

    def test_pointer_increment_copy_is_supported(self) -> None:
        result = analyze(function(counted_pointer_ops(), loop_blocks()))
        methods = {
            row["recognition_method"] for row in result["heuristic_sink_calls"]
        }
        self.assertIn("counted_range_copy", methods)

    def test_opposite_pointer_directions_use_signed_ptradd_stride(self) -> None:
        result = analyze(
            function(opposite_pointer_copy_ops(), sentinel_blocks())
        )
        methods = {
            row["recognition_method"] for row in result["heuristic_sink_calls"]
        }
        self.assertIn("counted_range_copy", methods)

    def test_countdown_uses_initial_remaining_value_as_length(self) -> None:
        result = analyze(function(counted_countdown_ops(), loop_blocks()))
        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "counted_range_copy"
        ]
        self.assertEqual(len(rows), 1)
        parameters = {
            row["role"]: row for row in rows[0]["vulnerable_parameters"]
        }
        self.assertEqual(parameters["len"]["parameter_slot"], 2)
        self.assertEqual(parameters["len"]["expr"], "count")

    def test_loop_invariant_fill_is_memset_sink(self) -> None:
        result = analyze(
            function(counted_array_ops(fill=True), loop_blocks())
        )
        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "counted_range_fill"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sink_type"], "MEMSET_SINK")
        self.assertEqual(
            [row["role"] for row in rows[0]["vulnerable_parameters"]],
            ["len"],
        )

    def test_constant_fill_is_memset_sink(self) -> None:
        result = analyze(
            function(
                counted_array_ops(fill=True, fill_constant=True),
                loop_blocks(),
            )
        )
        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "counted_range_fill"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["roles"]["value"], "const:0:1")

    def test_same_base_fixed_pointer_range_is_pruned(self) -> None:
        result = analyze(
            function(fixed_same_base_fill_ops(), loop_blocks(), arity=1)
        )
        self.assertFalse(
            any(
                row["recognition_method"] == "counted_range_fill"
                for row in result["heuristic_sink_calls"]
            )
        )
        self.assertIn(
            "no_trackable_vulnerable_parameter",
            reasons(result, "counted_range"),
        )

    def test_constant_bound_retains_mutable_source_content(self) -> None:
        result = analyze(
            function(
                counted_array_ops(bound_constant=True),
                loop_blocks(),
            )
        )
        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "counted_range_copy"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            [row["role"] for row in rows[0]["vulnerable_parameters"]],
            ["src"],
        )

    def test_transformed_load_is_rejected(self) -> None:
        result = analyze(
            function(counted_array_ops(transformed=True), loop_blocks())
        )
        self.assertFalse(
            any(
                row["recognition_method"] == "counted_range_copy"
                for row in result["heuristic_sink_calls"]
            )
        )
        self.assertIn(
            "counted_range_stored_value_not_copy_or_invariant_fill",
            reasons(result, "counted_range"),
        )

    def test_stride_mismatch_is_rejected(self) -> None:
        result = analyze(
            function(
                counted_array_ops(source_scale=2),
                loop_blocks(),
            )
        )
        self.assertIn(
            "counted_range_source_destination_stride_mismatch",
            reasons(result, "counted_range"),
        )

    def test_missing_exit_bound_is_rejected(self) -> None:
        blocks = [
            block("b0", 0, ["b1"]),
            block("b1", 1, ["b2"]),
            block("b2", 2, ["b1"]),
        ]
        result = analyze(
            function(
                counted_array_ops(include_exit_compare=False),
                blocks,
            )
        )
        self.assertIn(
            "counted_range_no_recurrence_bound_exit",
            reasons(result, "counted_range"),
        )

    def test_external_mmio_load_is_excluded_as_source_side(self) -> None:
        mmio_address = node("mmio", constant=0x40013008)
        result = heuristics.analyze_program_facts(
            facts(
                function(
                    counted_array_ops(load_address=mmio_address),
                    loop_blocks(),
                )
            ),
            register_evidence={
                "register_profiles": [
                    {
                        "register_address": "0x40013008",
                        "register_role": "receive_data",
                        "external_input_capable": True,
                        "load_site_id": "site:load",
                    }
                ]
            },
        )
        self.assertFalse(result["heuristic_sink_calls"])
        self.assertIn(
            "excluded_external_input_mmio_to_buffer_source",
            reasons(result, "counted_range"),
        )


class SentinelCopyTests(unittest.TestCase):
    def test_unchanged_loaded_value_controls_sentinel_exit(self) -> None:
        result = analyze(function(sentinel_ops(), sentinel_blocks()))
        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "sentinel_copy"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sink_type"], "COPY_SINK")
        self.assertEqual(rows[0]["recognition"], "heuristic")
        self.assertEqual(
            [row["role"] for row in rows[0]["vulnerable_parameters"]],
            ["src"],
        )
        self.assertEqual(rows[0]["proof"]["sentinel"], 0)
        self.assertEqual(rows[0]["proof"]["loop"]["blocks"], ["b1"])

    def test_nonzero_sentinel_is_supported_without_tracking_constant(self) -> None:
        result = analyze(
            function(sentinel_ops(sentinel=0xFF), sentinel_blocks())
        )
        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "sentinel_copy"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["proof"]["sentinel"], 0xFF)
        self.assertEqual(
            [row["role"] for row in rows[0]["vulnerable_parameters"]],
            ["src"],
        )

    def test_transformed_stored_value_is_rejected(self) -> None:
        result = analyze(
            function(sentinel_ops(transformed=True), sentinel_blocks())
        )
        self.assertFalse(
            any(
                row["recognition_method"] == "sentinel_copy"
                for row in result["heuristic_sink_calls"]
            )
        )
        self.assertIn(
            "sentinel_store_value_not_unchanged_load",
            reasons(result, "sentinel_copy"),
        )

    def test_branch_testing_different_load_is_rejected(self) -> None:
        result = analyze(
            function(
                sentinel_ops(branch_uses_other_load=True),
                sentinel_blocks(),
            )
        )
        self.assertIn(
            "sentinel_branch_does_not_test_stored_load_value",
            reasons(result, "sentinel_copy"),
        )

    def test_nonadvancing_destination_is_rejected(self) -> None:
        result = analyze(
            function(
                sentinel_ops(advance_destination=False),
                sentinel_blocks(),
            )
        )
        self.assertIn(
            "sentinel_source_or_destination_not_fixed_stride",
            reasons(result, "sentinel_copy"),
        )

    def test_range_comparison_is_not_treated_as_exact_sentinel(self) -> None:
        rows = sentinel_ops()
        comparison = next(row for row in rows if row["site_id"] == "site:cmp")
        comparison["mnemonic"] = "INT_LESS"
        result = analyze(function(rows, sentinel_blocks()))
        self.assertIn(
            "sentinel_branch_does_not_test_stored_load_value",
            reasons(result, "sentinel_copy"),
        )


class PairedBufferStateTests(unittest.TestCase):
    def test_opposite_updates_on_same_object_and_amount(self) -> None:
        blocks = [block("b0", 0, ["b1"]), block("b1", 1, [])]
        result = analyze(function(paired_ops(), blocks))
        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "paired_buffer_state"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sink_type"], "BUFFER_STATE_SINK")
        self.assertEqual(rows[0]["recognition"], "heuristic")
        self.assertEqual(
            [row["role"] for row in rows[0]["vulnerable_parameters"]],
            ["buffer", "amount"],
        )
        self.assertIn("buffer", rows[0]["object_roles"])

    def test_pointer_type_is_supporting_evidence_not_a_hard_gate(self) -> None:
        blocks = [block("b0", 0, ["b1"]), block("b1", 1, [])]
        result = analyze(
            function(
                paired_ops(cursor_pointer_typed=False),
                blocks,
            )
        )
        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "paired_buffer_state"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            rows[0]["proof"]["effect_kind_evidence"],
            ["scalar"],
        )

    def test_different_amount_lineage_is_rejected(self) -> None:
        blocks = [block("b0", 0, ["b1"]), block("b1", 1, [])]
        result = analyze(
            function(
                paired_ops(cursor_delta_slot=2),
                blocks,
            )
        )
        self.assertIn(
            "paired_state_different_amount_lineage",
            reasons(result, "paired_buffer_state"),
        )

    def test_same_direction_updates_are_rejected(self) -> None:
        blocks = [block("b0", 0, ["b1"]), block("b1", 1, [])]
        result = analyze(
            function(
                paired_ops(scalar_direction="add", cursor_direction="add"),
                blocks,
            )
        )
        self.assertIn(
            "paired_state_updates_not_opposite",
            reasons(result, "paired_buffer_state"),
        )

    def test_mutually_exclusive_branch_updates_are_rejected(self) -> None:
        blocks = [
            block("b0", 0, ["left", "right"], true_successor="left", false_successor="right"),
            block("left", 1, ["exit"]),
            block("right", 2, ["exit"]),
            block("exit", 3, []),
        ]
        result = analyze(
            function(
                paired_ops(scalar_block="left", cursor_block="right"),
                blocks,
            )
        )
        self.assertIn(
            "paired_state_updates_not_cfg_compatible",
            reasons(result, "paired_buffer_state"),
        )

    def test_constant_amount_at_callsite_keeps_mutable_buffer(self) -> None:
        implementation = function(
            paired_ops(),
            [block("b0", 0, ["b1"]), block("b1", 1, [])],
            name="consume",
            arity=2,
        )
        implementation["function_id"] = "fn:00001000"
        caller = {
            "function_id": "fn:00002000",
            "name": "caller",
            "entry": "0x2000",
            "parameters": [],
            "basic_blocks": [],
            "pcode_ops": [
                call_op(
                    "site:00002000:00002010:1",
                    "fn:00001000",
                    "consume",
                    [
                        node("buffer", constant=0x20000000, data_type="struct buffer *"),
                        node("one", constant=1),
                    ],
                )
            ],
        }
        program = {
            **facts(
                implementation,
                memory_blocks=[
                    {
                        "name": ".bss",
                        "start": "0x20000000",
                        "end": "0x200000ff",
                        "read": True,
                        "write": True,
                        "initialized": False,
                    }
                ],
            ),
            "functions": [implementation, caller],
        }
        analyzed = heuristics.analyze_program_facts(
            program, enabled_methods={"paired_buffer_state"}
        )
        materialized = heuristics.materialize_body_sink_calls(
            program, analyzed["heuristic_sink_implementations"]
        )

        self.assertEqual(len(materialized["heuristic_sink_calls"]), 1)
        row = materialized["heuristic_sink_calls"][0]
        self.assertEqual(
            [parameter["role"] for parameter in row["vulnerable_parameters"]],
            ["buffer"],
        )
        self.assertEqual(
            [parameter["role"] for parameter in row["pruned_vulnerable_parameters"]],
            ["amount"],
        )


class StatefulLoopWriteTests(unittest.TestCase):
    def test_indexed_stateful_loop_write_is_recognized(self) -> None:
        implementation = function(
            stateful_loop_ops(), sentinel_blocks(), arity=2
        )
        result = analyze(
            implementation,
            enabled_methods={"stateful_loop_write"},
        )
        rows = result["heuristic_sink_calls"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sink_type"], "LOOP_WRITE_SINK")
        self.assertEqual(rows[0]["recognition"], "heuristic")
        self.assertEqual(rows[0]["site_id"], "site:data-store")
        self.assertIn(
            "src",
            [parameter["role"] for parameter in rows[0]["vulnerable_parameters"]],
        )
        materialized = heuristics.materialize_body_sink_calls(
            facts(implementation), result["heuristic_sink_implementations"]
        )
        self.assertEqual(materialized["body_effect_fallbacks"], 1)
        self.assertEqual(
            materialized["heuristic_sink_calls"][0]["site_id"],
            "site:data-store",
        )

    def test_pointer_cursor_stateful_loop_write_is_recognized(self) -> None:
        result = analyze(
            function(
                stateful_loop_ops(pointer_cursor=True),
                sentinel_blocks(),
                arity=2,
            ),
            enabled_methods={"stateful_loop_write"},
        )
        self.assertEqual(len(result["heuristic_sink_calls"]), 1)
        recurrence = result["heuristic_sink_calls"][0]["proof"][
            "destination_state_recurrence"
        ]
        self.assertEqual(recurrence["step"], 1)

    def test_stateful_store_outside_loop_is_rejected(self) -> None:
        result = analyze(
            function(
                stateful_loop_ops(),
                [block("b0", 0, ["b1"]), block("b1", 1, [])],
                arity=2,
            ),
            enabled_methods={"stateful_loop_write"},
        )
        self.assertFalse(result["heuristic_sink_calls"])

    def test_transformed_source_value_is_rejected(self) -> None:
        result = analyze(
            function(
                stateful_loop_ops(transformed=True),
                sentinel_blocks(),
                arity=2,
            ),
            enabled_methods={"stateful_loop_write"},
        )
        self.assertFalse(result["heuristic_sink_calls"])

    def test_missing_memory_state_progression_is_rejected(self) -> None:
        result = analyze(
            function(
                stateful_loop_ops(include_state_update=False),
                sentinel_blocks(),
                arity=2,
            ),
            enabled_methods={"stateful_loop_write"},
        )
        self.assertFalse(result["heuristic_sink_calls"])

    def test_mmio_to_ram_producer_loop_is_rejected(self) -> None:
        fn = function(
            stateful_loop_ops(), sentinel_blocks(), arity=2
        )
        source_load = next(
            row for row in fn["pcode_ops"] if row["site_id"] == "site:src-load"
        )
        result = heuristics.analyze_program_facts(
            facts(fn),
            enabled_methods={"stateful_loop_write"},
            register_evidence={
                "register_profiles": [
                    {
                        "register_address": "0x40013008",
                        "register_role": "receive_data",
                        "external_input_capable": True,
                        "confirmed_source": True,
                        "load_site_id": source_load["site_id"],
                    }
                ]
            },
        )
        self.assertFalse(result["heuristic_sink_calls"])
        self.assertIn(
            "excluded_external_input_mmio_to_buffer_source",
            reasons(result, "stateful_loop_write"),
        )

    def test_source_without_unique_formal_binding_is_rejected(self) -> None:
        result = analyze(
            function(
                stateful_loop_ops(source_is_formal=False),
                sentinel_blocks(),
                arity=2,
            ),
            enabled_methods={"stateful_loop_write"},
        )
        self.assertFalse(result["heuristic_sink_calls"])
        self.assertIn(
            "stateful_loop_source_not_uniquely_formal_bound",
            reasons(result, "stateful_loop_write"),
        )


class BufferStateReservationTests(unittest.TestCase):
    def test_length_growth_returning_old_tail_is_recognized(self) -> None:
        result = analyze(
            function(
                reservation_ops(),
                [block("b0", 0, [])],
                name="reserve",
                arity=2,
            ),
            enabled_methods={"buffer_state_reserve"},
        )
        rows = result["heuristic_sink_calls"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sink_type"], "BUFFER_STATE_SINK")
        self.assertEqual(
            [parameter["role"] for parameter in rows[0]["vulnerable_parameters"]],
            ["buffer", "amount"],
        )

    def test_counter_increment_without_tail_return_is_rejected(self) -> None:
        result = analyze(
            function(
                reservation_ops(return_old_tail=False),
                [block("b0", 0, [])],
                name="counter",
                arity=2,
            ),
            enabled_methods={"buffer_state_reserve"},
        )
        self.assertFalse(result["heuristic_sink_calls"])

    def test_heuristic_summary_propagates_through_thin_wrapper(self) -> None:
        implementation = function(
            reservation_ops(),
            [block("b0", 0, [])],
            name="reserve",
            arity=2,
        )
        implementation["function_id"] = "fn:00001000"
        wrapper_buf = node("wrapper_buf", slot=0, data_type="struct buffer *")
        wrapper_amount = node("wrapper_amount", slot=1, data_type="size_t")
        wrapper = {
            "function_id": "fn:00002000",
            "name": "wrapper",
            "entry": "0x2000",
            "parameters": [
                {"index": 0, "name": "buf", "data_type": "struct buffer *"},
                {"index": 1, "name": "amount", "data_type": "size_t"},
            ],
            "basic_blocks": [],
            "pcode_ops": [
                call_op(
                    "site:00002000:00002010:1",
                    "fn:00001000",
                    "reserve",
                    [wrapper_buf, wrapper_amount],
                )
            ],
        }
        outer = {
            "function_id": "fn:00003000",
            "name": "outer",
            "entry": "0x3000",
            "parameters": [],
            "basic_blocks": [],
            "pcode_ops": [
                {
                    **call_op(
                        "site:00003000:00003010:1",
                        "fn:00002000",
                        "wrapper",
                        [node("outer_buf", slot=0), node("outer_amount", slot=1)],
                    ),
                    "inputs": [
                        node("target", constant=0x2000),
                        node("outer_buf", slot=0),
                        node("outer_amount", slot=1),
                    ],
                    "call": {
                        "kind": "CALL",
                        "target_address": "0x2000",
                        "target_function": "wrapper",
                        "target_function_id": "fn:00002000",
                    },
                }
            ],
        }
        program = {
            **facts(implementation),
            "functions": [implementation, wrapper, outer],
        }
        analyzed = heuristics.analyze_program_facts(
            program, enabled_methods={"buffer_state_reserve"}
        )
        materialized = heuristics.materialize_body_sink_calls(
            program, analyzed["heuristic_sink_implementations"]
        )
        rows = materialized["heuristic_sink_calls"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["function"], "outer")
        self.assertEqual(rows[0]["callee"], "wrapper")
        self.assertEqual(rows[0]["summary_depth"], 2)
        self.assertTrue(
            any(
                boundary.get("site_id") == "site:length-store"
                for boundary in rows[0]["boundary_callsites"]
            )
        )


class InPlaceSwapTests(unittest.TestCase):
    def test_cross_write_loop_on_same_buffer_is_recognized(self) -> None:
        result = analyze(
            function(
                swap_ops(),
                sentinel_blocks(),
                name="custom_transform",
                arity=3,
            )
        )
        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "in_place_swap"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sink_type"], "LOOP_WRITE_SINK")
        self.assertEqual(rows[0]["recognition"], "heuristic")
        self.assertEqual(
            [row["role"] for row in rows[0]["vulnerable_parameters"]],
            ["buffer"],
        )

    def test_extent_is_bound_only_when_it_controls_the_loop_range(self) -> None:
        fn = function(
            swap_ops(dynamic_extent=True),
            sentinel_blocks(),
            name="custom_transform",
            arity=3,
        )
        fn["parameters"][0]["data_type"] = "uint8_t *"
        fn["parameters"][1]["data_type"] = "size_t"
        fn["parameters"][2]["data_type"] = "uint8_t *"
        result = analyze(fn)
        rows = [
            row
            for row in result["heuristic_sink_calls"]
            if row["recognition_method"] == "in_place_swap"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            [row["role"] for row in rows[0]["vulnerable_parameters"]],
            ["buffer", "len"],
        )

    def test_values_must_be_cross_written_unchanged(self) -> None:
        result = analyze(
            function(
                swap_ops(cross_write=False),
                sentinel_blocks(),
                name="custom_transform",
                arity=3,
            )
        )
        self.assertFalse(
            [
                row
                for row in result["heuristic_sink_calls"]
                if row["recognition_method"] == "in_place_swap"
            ]
        )
        self.assertIn(
            "in_place_swap_no_cross_write_pair",
            reasons(result, "in_place_swap"),
        )

    def test_two_different_buffers_are_not_an_in_place_swap(self) -> None:
        fn = function(
            swap_ops(same_buffer=False),
            sentinel_blocks(),
            name="custom_transform",
            arity=3,
        )
        fn["parameters"][0]["data_type"] = "uint8_t *"
        fn["parameters"][1]["data_type"] = "size_t"
        fn["parameters"][2]["data_type"] = "uint8_t *"
        result = analyze(fn)
        self.assertFalse(
            [
                row
                for row in result["heuristic_sink_calls"]
                if row["recognition_method"] == "in_place_swap"
            ]
        )

    def test_same_operations_without_a_loop_are_not_recognized(self) -> None:
        blocks = [
            block("b0", 0, ["b1"]),
            block("b1", 1, ["b2"]),
            block("b2", 2, []),
        ]
        result = analyze(
            function(
                swap_ops(),
                blocks,
                name="custom_transform",
                arity=3,
            )
        )
        self.assertFalse(
            [
                row
                for row in result["heuristic_sink_calls"]
                if row["recognition_method"] == "in_place_swap"
            ]
        )


class ArtifactCompatibilityTests(unittest.TestCase):
    def test_status_register_evidence_is_not_external_data_evidence(self) -> None:
        index = heuristics.SourceEvidenceIndex(
            {
                "register_profiles": [
                    {
                        "register_address": "0x40013008",
                        "register_role": "status_control",
                        "external_input_capable": True,
                        "label": "MMIO_READ",
                        "load_site_id": "site:load",
                    }
                ]
            }
        )
        self.assertFalse(
            index.is_external_load(
                {
                    "site_id": "site:load",
                    "mnemonic": "LOAD",
                    "output": node("loaded"),
                    "inputs": [
                        node("space", constant=0x1A1),
                        node("mmio", constant=0x40013008),
                    ],
                }
            )
        )

    def test_old_flat_pcode_returns_explicit_blocker(self) -> None:
        flat = function(counted_array_ops(), loop_blocks())
        flat.pop("basic_blocks")
        for row in flat["pcode_ops"]:
            row.pop("block_id", None)

        result = analyze(flat)

        self.assertFalse(result["heuristic_sink_calls"])
        self.assertEqual(result["stats"]["functions_blocked"], 1)
        self.assertEqual(result["blockers"][0]["code"], "missing_cfg_basic_blocks")

    def test_unknown_block_reference_returns_explicit_blocker(self) -> None:
        fn = function(counted_array_ops(), loop_blocks())
        fn["pcode_ops"][0]["block_id"] = "missing"

        result = analyze(fn)

        self.assertFalse(result["heuristic_sink_calls"])
        self.assertEqual(result["blockers"][0]["code"], "pcode_op_missing_block_id")

    def test_outputs_use_only_existing_sink_semantic_types(self) -> None:
        functions = [
            function(counted_array_ops(), loop_blocks()),
            function(sentinel_ops(), sentinel_blocks()),
            function(
                paired_ops(),
                [block("b0", 0, ["b1"]), block("b1", 1, [])],
            ),
        ]
        result = heuristics.analyze_program_facts(
            {
                "binary": "/tmp/synthetic.elf",
                "binary_sha256": "b" * 64,
                "functions": functions,
                "memory_blocks": [],
            }
        )
        self.assertTrue(result["heuristic_sink_calls"])
        self.assertLessEqual(
            {row["sink_type"] for row in result["heuristic_sink_calls"]},
            {"COPY_SINK", "MEMSET_SINK", "BUFFER_STATE_SINK"},
        )
        self.assertEqual(
            {row["recognition"] for row in result["heuristic_sink_calls"]},
            {"heuristic"},
        )


class VariableAddressStoreTests(unittest.TestCase):
    @staticmethod
    def variable_store_facts(*, static_base: int | None = None) -> dict:
        dst = (
            node("dst", slot=0, data_type="uint8_t *")
            if static_base is None
            else node("base", constant=static_base)
        )
        index = node("index", slot=1, data_type="size_t")
        address = node("address", data_type="uint8_t *")
        value = node("value", slot=2, data_type="uint8_t")
        rows = [
            op(
                "site:addr",
                "PTRADD",
                [dst, index, node("scale", constant=1)],
                address,
                block="b0",
                address=0x1000,
                order=1,
            ),
            op(
                "site:store",
                "STORE",
                [node("ram", constant=0x1A1), address, value],
                None,
                block="b0",
                address=0x1002,
                order=2,
            ),
        ]
        fn = function(rows, [block("b0", 0, [])], arity=3)
        fn["parameters"][0]["data_type"] = "uint8_t *"
        fn["parameters"][1]["data_type"] = "size_t"
        fn["parameters"][2]["data_type"] = "uint8_t"
        memory_blocks = []
        if static_base is not None:
            memory_blocks.append(
                {
                    "name": ".data",
                    "start": hex(static_base),
                    "end": hex(static_base + 0xFF),
                    "read": True,
                    "write": True,
                    "initialized": True,
                }
            )
        return facts(fn, memory_blocks=memory_blocks)

    def test_formal_pointer_plus_scalar_index_is_audit_store_candidate(self) -> None:
        artifact = heuristics.analyze_program_facts(
            self.variable_store_facts(),
            enabled_methods={"variable_address_store"},
        )
        rows = artifact["heuristic_sink_implementations"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "STORE_SINK")
        self.assertTrue(rows[0]["audit_only"])
        self.assertEqual(
            rows[0]["vulnerable_parameter_roles"], ["dst", "index"]
        )

    def test_fixed_field_store_is_outside_variable_address_rule(self) -> None:
        dst = node("dst", slot=0, data_type="struct item *")
        address = node("field", data_type="uint32_t *")
        rows = [
            op(
                "site:field",
                "PTRSUB",
                [dst, node("field_offset", constant=4)],
                address,
                block="b0",
                address=0x1000,
                order=1,
            ),
            op(
                "site:store",
                "STORE",
                [node("ram", constant=0x1A1), address, node("value", slot=1)],
                None,
                block="b0",
                address=0x1002,
                order=2,
            ),
        ]
        fn = function(rows, [block("b0", 0, [])], arity=2)
        fn["parameters"][0]["data_type"] = "struct item *"
        fn["parameters"][1]["data_type"] = "uint32_t"
        artifact = heuristics.analyze_program_facts(
            facts(fn), enabled_methods={"variable_address_store"}
        )
        self.assertEqual(artifact["heuristic_sink_implementations"], [])

    def test_unknown_mmio_base_is_rejected(self) -> None:
        program = self.variable_store_facts(static_base=0x40000000)
        program["memory_blocks"] = []
        artifact = heuristics.analyze_program_facts(
            program, enabled_methods={"variable_address_store"}
        )
        self.assertEqual(artifact["heuristic_sink_implementations"], [])
        self.assertIn(
            "variable_store_base_not_proved_writable",
            {row["reason_code"] for row in artifact["candidates"]},
        )


if __name__ == "__main__":
    unittest.main()
