from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import deterministic_sink_engine as engine  # noqa: E402
from sink_artifact_schema import load_sink_registry  # noqa: E402


def node(name: str, *, slot: int | None = None, constant: int | None = None) -> dict:
    if constant is not None:
        return {
            "object_id": f"const:{constant:x}:4",
            "value_id": f"const:{constant:x}:4",
            "space": "const",
            "offset": hex(constant),
            "size": 4,
            "high_name": "",
            "is_parameter": False,
            "parameter_slot": None,
            "is_constant": True,
        }
    return {
        "object_id": f"param:f:{slot}" if slot is not None else f"reg:{name}:4",
        "value_id": f"value:{name}",
        "space": "register",
        "offset": "0x0",
        "size": 4,
        "high_name": name,
        "is_parameter": slot is not None,
        "parameter_slot": slot,
        "is_constant": False,
    }


def call(
    site: str,
    target_id: str,
    target_name: str,
    actuals: list[dict],
    address: int,
) -> dict:
    return {
        "site_id": site,
        "instruction_address": hex(address),
        "op_order": 1,
        "mnemonic": "CALL",
        "output": None,
        "inputs": [node("target", constant=address), *actuals],
        "call": {
            "kind": "CALL",
            "target_address": hex(address),
            "target_function": target_name,
            "target_function_id": target_id,
            "argument_object_ids": [str(item.get("object_id", "")) for item in actuals],
            "argument_value_ids": [str(item.get("value_id", "")) for item in actuals],
        },
    }


def temporary(name: str, *, data_type: str = "", size: int = 4) -> dict:
    return {
        "object_id": f"unique:{name}:{size}",
        "value_id": f"value:{name}",
        "space": "unique",
        "offset": "0x100",
        "size": size,
        "high_name": "",
        "high_data_type": data_type,
        "is_parameter": False,
        "parameter_slot": None,
        "is_constant": False,
    }


def pcode(
    site: str,
    mnemonic: str,
    inputs: list[dict],
    output: dict | None,
    address: int,
    order: int,
) -> dict:
    return {
        "site_id": site,
        "instruction_address": hex(address),
        "op_order": order,
        "mnemonic": mnemonic,
        "inputs": inputs,
        "output": output,
    }


def derived_formal_destination_call(
    *,
    site: str = "site:2000:2010:7",
    target_id: str = "fn:1000",
    target_name: str = "memcpy",
    base_slot: int = 0,
    src_slot: int = 1,
    len_slot: int = 2,
) -> list[dict]:
    base = node("buffer", slot=base_slot)
    src = node("src", slot=src_slot)
    length = node("length", slot=len_slot)
    space = node("ram", constant=0x1A1)
    zero = node("zero", constant=0)
    one = node("one", constant=1)
    four = node("four", constant=4)
    data_address = temporary("data_address")
    data_pointer = temporary("data_pointer")
    length_address = temporary("length_address")
    old_length = temporary("old_length")
    derived_destination = temporary("derived_destination")
    return [
        pcode("site:2000:2000:1", "PTRSUB", [base, zero], data_address, 0x2000, 1),
        pcode("site:2000:2002:2", "LOAD", [space, data_address], data_pointer, 0x2002, 2),
        pcode("site:2000:2004:3", "PTRSUB", [base, four], length_address, 0x2004, 3),
        pcode("site:2000:2006:4", "LOAD", [space, length_address], old_length, 0x2006, 4),
        pcode(
            "site:2000:2008:5", "PTRADD",
            [data_pointer, old_length, one], derived_destination, 0x2008, 5,
        ),
        call(
            site, target_id, target_name,
            [derived_destination, src, length], 0x1000,
        ),
    ]


def paired_state_ops(
    *, base_slot: int = 0, scalar_delta_slot: int = 1,
    cursor_delta_slot: int = 1, cursor_base_slot: int | None = None,
    include_branch: bool = False, include_types: bool = True,
) -> list[dict]:
    base = node("state", slot=base_slot)
    cursor_base = node(
        "cursor_state", slot=base_slot if cursor_base_slot is None else cursor_base_slot
    )
    scalar_delta = node("amount", slot=scalar_delta_slot)
    cursor_delta = node("cursor_amount", slot=cursor_delta_slot)
    space = node("ram", constant=0x1A1)
    zero = node("zero", constant=0)
    one = node("one", constant=1)
    four = node("four", constant=4)
    length_address = temporary("length_address", data_type="uint16_t *" if include_types else "")
    old_length = temporary("old_length", data_type="uint16_t" if include_types else "", size=2)
    narrowed_amount = temporary("narrowed_amount", data_type="uint16_t" if include_types else "", size=2)
    new_length = temporary("new_length", data_type="uint16_t" if include_types else "", size=2)
    cursor_address = temporary("cursor_address", data_type="uint8_t **" if include_types else "")
    old_cursor = temporary("old_cursor", data_type="uint8_t *" if include_types else "")
    new_cursor = temporary("new_cursor", data_type="uint8_t *" if include_types else "")
    ops = [
        pcode("site:2000:2000:1", "PTRSUB", [base, four], length_address, 0x2000, 1),
        pcode("site:2000:2000:2", "LOAD", [space, length_address], old_length, 0x2000, 2),
        pcode("site:2000:2002:3", "SUBPIECE", [scalar_delta, zero], narrowed_amount, 0x2002, 3),
        pcode("site:2000:2004:4", "INT_SUB", [old_length, narrowed_amount], new_length, 0x2004, 4),
        pcode("site:2000:2006:5", "STORE", [space, length_address, new_length], None, 0x2006, 5),
    ]
    if include_branch:
        ops.append(pcode("site:2000:2008:6", "CBRANCH", [node("cond", slot=2)], None, 0x2008, 6))
    ops.extend([
        pcode("site:2000:200a:7", "PTRSUB", [cursor_base, zero], cursor_address, 0x200A, 7),
        pcode("site:2000:200a:8", "LOAD", [space, cursor_address], old_cursor, 0x200A, 8),
        pcode("site:2000:200c:9", "PTRADD", [old_cursor, cursor_delta, one], new_cursor, 0x200C, 9),
        pcode("site:2000:200e:10", "STORE", [space, cursor_address, new_cursor], None, 0x200E, 10),
    ])
    return ops


def function(fid: str, name: str, ops: list[dict], arity: int = 3) -> dict:
    return {
        "function_id": fid,
        "name": name,
        "entry": hex(int(fid.split(":")[-1], 16)),
        "parameters": [
            {"index": index, "name": f"arg{index}", "data_type": "void *"}
            for index in range(arity)
        ],
        "pcode_ops": ops,
    }


def registry() -> dict:
    return load_sink_registry(ROOT / "registries/sink_patterns.v2.json")


def facts(functions: list[dict]) -> dict:
    return {
        "schema_version": "ct-mini-ghidra-high-pcode-v2",
        "binary": "/tmp/test.elf",
        "binary_sha256": "a" * 64,
        "functions": functions,
        "symbols": [],
        "memory_blocks": [],
    }


def global_address(name: str, address: int) -> dict:
    return {
        "object_id": f"global:{address:08x}:4",
        "value_id": f"value:{name}",
        "space": "ram",
        "offset": hex(address),
        "size": 4,
        "high_name": name,
        "is_parameter": False,
        "parameter_slot": None,
        "is_constant": False,
        "is_address": True,
    }


class DeterministicSinkEngineTests(unittest.TestCase):
    def test_display_index_uses_argument_evidence_when_c_order_differs(self) -> None:
        target = function("fn:1000", "append", [], 3)
        dynamic = call(
            "site:2000:2010:1",
            "fn:1000",
            "append",
            [node("buf", slot=0), node("payload", slot=1), node("length", slot=2)],
            0x1000,
        )
        fixed = call(
            "site:2000:2020:1",
            "fn:1000",
            "append",
            [node("buf", slot=0), node("header", slot=1), node("four", constant=4)],
            0x1000,
        )
        caller = function("fn:2000", "receive", [dynamic, fixed], 3)
        index = engine.ProgramIndex(facts([target, caller]))
        display = engine.DisplayIndex(
            index,
            [
                {
                    "function": "receive",
                    "callee": "append",
                    "line": 10,
                    "expr": "append(buf, header, 4)",
                    "args": ["buf", "header", "4"],
                },
                {
                    "function": "receive",
                    "callee": "append",
                    "line": 20,
                    "expr": "append(buf, payload, length)",
                    "args": ["buf", "payload", "length"],
                },
            ],
        )

        self.assertEqual(display.get("site:2000:2010:1")["line"], 20)
        self.assertEqual(display.get("site:2000:2020:1")["line"], 10)

    def test_v1_registry_loads_without_promoting_structural_rule(self) -> None:
        legacy = load_sink_registry(
            ROOT / "registries/deterministic_sink_seeds.v1.json"
        )
        self.assertIn("memcpy", legacy["primitive_sinks"])
        self.assertEqual(
            legacy["primitive_sinks"]["memcpy"]["recognition"], "deterministic"
        )
        self.assertEqual(
            legacy["heuristic_sink_rules"][0]["recognition"], "heuristic"
        )

    def test_body_proved_paired_buffer_state_is_not_deterministic(self) -> None:
        helper = function(
            "fn:2000", "zv_q17", paired_state_ops(include_types=False), 2
        )
        invoke = call(
            "site:3000:3010:1", "fn:2000", "zv_q17",
            [node("object", slot=0), node("delta", slot=1)], 0x2000,
        )
        caller = function("fn:3000", "unnamed_stage", [invoke], 2)
        artifact, compatibility = engine.analyze(
            program_facts=facts([helper, caller]), registry=registry(),
            display_calls=[], input_metadata={},
        )
        self.assertFalse(any(
            row["label"] == "BUFFER_STATE_SINK"
            for row in artifact["deterministic_sink_calls"]
        ))
        self.assertEqual(artifact["counts"]["body_derived_buffer_state_callsites"], 0)
        self.assertEqual(compatibility["candidates"], [])

    def test_paired_buffer_state_does_not_propagate_as_deterministic_wrapper(self) -> None:
        helper = function("fn:2000", "helper_17", paired_state_ops(), 2)
        wrapper_call = call(
            "site:3000:3010:1", "fn:2000", "helper_17",
            [node("ctx", slot=1), node("amount", slot=0)], 0x2000,
        )
        wrapper = function("fn:3000", "wrapper_42", [wrapper_call], 2)
        top_call = call(
            "site:4000:4010:1", "fn:3000", "wrapper_42",
            [node("n", slot=0), node("state", slot=1)], 0x3000,
        )
        top = function("fn:4000", "top", [top_call], 2)
        artifact, _compatibility = engine.analyze(
            program_facts=facts([helper, wrapper, top]), registry=registry(),
            display_calls=[], input_metadata={},
        )
        self.assertFalse(any(
            row["label"] == "BUFFER_STATE_SINK"
            for row in artifact["deterministic_sink_calls"]
        ))

    def test_unpaired_counter_update_is_not_a_buffer_state_sink(self) -> None:
        helper = function("fn:2000", "counter_update", paired_state_ops()[:5], 2)
        invoke = call(
            "site:3000:3010:1", "fn:2000", "counter_update",
            [node("stats", slot=0), node("count", slot=1)], 0x2000,
        )
        caller = function("fn:3000", "caller", [invoke], 2)
        artifact, _compatibility = engine.analyze(
            program_facts=facts([helper, caller]), registry=registry(),
            display_calls=[], input_metadata={},
        )
        self.assertFalse(any(
            row["label"] == "BUFFER_STATE_SINK" for row in artifact["sink_startpoints"]
        ))

    def test_constant_amount_buffer_state_is_outside_deterministic_engine(self) -> None:
        helper = function("fn:2000", "state_helper", paired_state_ops(), 2)
        invoke = call(
            "site:3000:3010:1", "fn:2000", "state_helper",
            [node("state", slot=0), node("four", constant=4)], 0x2000,
        )
        caller = function("fn:3000", "caller", [invoke], 1)
        artifact, _compatibility = engine.analyze(
            program_facts=facts([helper, caller]), registry=registry(),
            display_calls=[], input_metadata={},
        )
        self.assertFalse(any(
            row["label"] == "BUFFER_STATE_SINK" for row in artifact["sink_startpoints"]
        ))
        self.assertFalse(any(
            row.get("label") == "BUFFER_STATE_SINK"
            for row in artifact["withdrawn_out_of_scope"]
        ))

    def test_different_delta_formals_are_not_paired(self) -> None:
        helper = function(
            "fn:2000", "mixed_update",
            paired_state_ops(scalar_delta_slot=1, cursor_delta_slot=2), 3,
        )
        invoke = call(
            "site:3000:3010:1", "fn:2000", "mixed_update",
            [node("state", slot=0), node("left", slot=1), node("right", slot=2)],
            0x2000,
        )
        caller = function("fn:3000", "caller", [invoke], 3)
        artifact, _compatibility = engine.analyze(
            program_facts=facts([helper, caller]), registry=registry(),
            display_calls=[], input_metadata={},
        )
        self.assertFalse(any(
            row["label"] == "BUFFER_STATE_SINK" for row in artifact["sink_startpoints"]
        ))

    def test_updates_to_different_base_formals_are_not_paired(self) -> None:
        helper = function(
            "fn:2000", "mixed_objects",
            paired_state_ops(cursor_base_slot=2), 3,
        )
        invoke = call(
            "site:3000:3010:1", "fn:2000", "mixed_objects",
            [node("left", slot=0), node("amount", slot=1), node("right", slot=2)],
            0x2000,
        )
        caller = function("fn:3000", "caller", [invoke], 3)
        artifact, _compatibility = engine.analyze(
            program_facts=facts([helper, caller]), registry=registry(),
            display_calls=[], input_metadata={},
        )
        self.assertFalse(any(
            row["label"] == "BUFFER_STATE_SINK" for row in artifact["sink_startpoints"]
        ))

    def test_control_flow_split_prevents_structural_pairing(self) -> None:
        helper = function("fn:2000", "split_update", paired_state_ops(include_branch=True), 3)
        invoke = call(
            "site:3000:3010:1", "fn:2000", "split_update",
            [node("state", slot=0), node("amount", slot=1), node("cond", slot=2)],
            0x2000,
        )
        caller = function("fn:3000", "caller", [invoke], 3)
        artifact, _compatibility = engine.analyze(
            program_facts=facts([helper, caller]), registry=registry(),
            display_calls=[], input_metadata={},
        )
        self.assertFalse(any(
            row["label"] == "BUFFER_STATE_SINK" for row in artifact["sink_startpoints"]
        ))

    def test_dynamic_length_primitive_is_admitted(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        op = call(
            "site:2000:2010:1", "fn:1000", "memcpy",
            [node("dst", slot=0), node("src", slot=1), node("length", slot=2)],
            0x1000,
        )
        caller = function("fn:2000", "renamed_handler", [op], 3)
        artifact, compatibility = engine.analyze(
            program_facts=facts([memcpy, caller]),
            registry=registry(),
            display_calls=[{
                "function": "renamed_handler", "callee": "memcpy", "line": 3,
                "expr": "memcpy(arg0, arg1, arg2)", "args": ["arg0", "arg1", "arg2"],
            }],
            input_metadata={},
        )
        self.assertEqual(artifact["counts"]["sink_startpoints"], 1)
        self.assertEqual(artifact["counts"]["heuristic_sink_startpoints"], 0)
        self.assertEqual(compatibility["candidates"], [])
        row = artifact["sink_startpoints"][0]
        self.assertEqual(row["site_id"], "site:2000:2010:1")
        self.assertEqual(row["recognition"], "deterministic")
        self.assertEqual(
            [item["role"] for item in row["semantic_parameters"]],
            ["dst", "src", "len"],
        )
        self.assertEqual([item["role"] for item in row["vulnerable_parameters"]], ["src", "len"])
        self.assertTrue(all(item.get("value_id") for item in row["vulnerable_parameters"]))
        self.assertEqual(row["role_argument_indexes"], {"dst": 0, "src": 1, "len": 2})
        self.assertEqual(row["role_bindings"]["dst"]["value_id"], "value:dst")

    def test_constant_length_prunes_only_length_and_retains_source(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        op = call(
            "site:2000:2010:1", "fn:1000", "memcpy",
            [node("dst", slot=0), node("src", slot=1), node("four", constant=4)],
            0x1000,
        )
        caller = function("fn:2000", "decode_header", [op], 2)
        artifact, _compatibility = engine.analyze(
            program_facts=facts([memcpy, caller]), registry=registry(),
            display_calls=[], input_metadata={},
        )
        self.assertEqual(len(artifact["sink_startpoints"]), 1)
        row = artifact["sink_startpoints"][0]
        self.assertEqual(
            [item["role"] for item in row["vulnerable_parameters"]], ["src"]
        )
        self.assertEqual(
            [
                (item["role"], item["prune_reason"])
                for item in row["pruned_vulnerable_parameters"]
            ],
            [("len", "constant_scalar")],
        )

    def test_recursive_wrapper_summary_uses_only_body_and_pcode(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        inner_call = call(
            "site:2000:2010:1", "fn:1000", "memcpy",
            [node("out", slot=1), node("packet", slot=0), node("count", slot=2)],
            0x1000,
        )
        randomly_named_inner = function("fn:2000", "qzv_17", [inner_call], 3)
        outer_call = call(
            "site:3000:3010:1", "fn:2000", "qzv_17",
            [node("payload", slot=0), node("destination", slot=1), node("size", slot=2)],
            0x2000,
        )
        randomly_named_outer = function("fn:3000", "mcu_vendor_42", [outer_call], 3)
        top_call = call(
            "site:4000:4010:1", "fn:3000", "mcu_vendor_42",
            [node("rx", slot=0), node("dst", slot=1), node("rx_len", slot=2)],
            0x3000,
        )
        top = function("fn:4000", "task_entry", [top_call], 3)
        display = [
            {"function": "qzv_17", "callee": "memcpy", "line": 3,
             "expr": "memcpy(arg1, arg0, arg2)", "args": ["arg1", "arg0", "arg2"]},
            {"function": "mcu_vendor_42", "callee": "qzv_17", "line": 8,
             "expr": "qzv_17(arg0, arg1, arg2)", "args": ["arg0", "arg1", "arg2"]},
            {"function": "task_entry", "callee": "mcu_vendor_42", "line": 13,
             "expr": "mcu_vendor_42(arg0, arg1, arg2)", "args": ["arg0", "arg1", "arg2"]},
        ]
        artifact, _compatibility = engine.analyze(
            program_facts=facts([memcpy, randomly_named_inner, randomly_named_outer, top]),
            registry=registry(), display_calls=display, input_metadata={},
        )
        self.assertEqual(len(artifact["sink_startpoints"]), 1)
        row = artifact["sink_startpoints"][0]
        self.assertEqual(row["site_id"], "site:4000:4010:1")
        self.assertEqual(row["effect_site_id"], "site:2000:2010:1")
        self.assertEqual(row["callee"], "mcu_vendor_42")
        self.assertEqual(row["recognition"], "deterministic")
        self.assertEqual(
            set(row["role_bindings"]), {"dst", "src", "len"}
        )
        boundaries = {item["callee"]: item for item in row["boundary_callsites"]}
        self.assertIn("qzv_17", boundaries)
        self.assertIn("mcu_vendor_42", boundaries)
        self.assertEqual(boundaries["mcu_vendor_42"]["roles"]["src"], "arg0")
        self.assertEqual(boundaries["mcu_vendor_42"]["roles"]["len"], "arg2")
        self.assertEqual(
            artifact["primitive_effect_sites"][0]["site_id"],
            "site:2000:2010:1",
        )
        self.assertEqual(
            artifact["primitive_effect_sites"][0]["effect_site_id"],
            "site:2000:2010:1",
        )

    def test_recursive_wrapper_accepts_nonrequired_derived_formal_destination(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        helper = function(
            "fn:2000", "body_17", derived_formal_destination_call(), 3
        )
        wrapper_call = call(
            "site:3000:3010:1", "fn:2000", "body_17",
            [node("state", slot=0), node("payload", slot=1), node("count", slot=2)],
            0x2000,
        )
        wrapper = function("fn:3000", "body_29", [wrapper_call], 3)
        top_call = call(
            "site:4000:4010:1", "fn:3000", "body_29",
            [node("object", slot=0), node("rx", slot=1), node("rx_len", slot=2)],
            0x3000,
        )
        top = function("fn:4000", "consumer", [top_call], 3)

        artifact, _compatibility = engine.analyze(
            program_facts=facts([memcpy, helper, wrapper, top]),
            registry=registry(), display_calls=[], input_metadata={},
        )

        self.assertEqual(len(artifact["sink_startpoints"]), 1)
        row = artifact["sink_startpoints"][0]
        self.assertEqual(row["site_id"], "site:4000:4010:1")
        self.assertEqual(row["effect_site_id"], "site:2000:2010:7")
        self.assertEqual(
            {item["role"] for item in row["vulnerable_parameters"]},
            {"src", "len"},
        )
        self.assertEqual(
            row["role_bindings"]["dst"]["kind"], "derived_formal_object"
        )
        self.assertIsNone(row["role_bindings"]["dst"]["index"])
        self.assertEqual(
            row["role_bindings"]["dst"]["base_parameter_index"], 0
        )
        self.assertEqual(row["role_argument_indexes"]["dst"], None)
        self.assertEqual(row["roles"]["dst"], "<derived from object>")
        self.assertEqual(set(row["admission_roles"]), {"src", "len"})

    def test_recursive_wrapper_rejects_derived_vulnerable_role(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        ops = derived_formal_destination_call()
        derived_source = dict(ops[-1]["inputs"][1])
        ops[-1] = call(
            "site:2000:2010:7", "fn:1000", "memcpy",
            [node("dst", slot=0), derived_source, node("length", slot=2)],
            0x1000,
        )
        helper = function("fn:2000", "body_31", ops, 3)
        outer_call = call(
            "site:3000:3010:1", "fn:2000", "body_31",
            [node("out", slot=0), node("object", slot=1), node("count", slot=2)],
            0x2000,
        )
        outer = function("fn:3000", "body_43", [outer_call], 3)

        artifact, _compatibility = engine.analyze(
            program_facts=facts([memcpy, helper, outer]), registry=registry(),
            display_calls=[], input_metadata={},
        )

        self.assertEqual(
            [row["site_id"] for row in artifact["sink_startpoints"]],
            ["site:2000:2010:7"],
        )
        self.assertEqual(artifact["body_derived_boundary_callsites"], [])
        self.assertTrue(any(
            blocker.get("reason") == "summary_role_not_formal_or_constant:src"
            for blocker in artifact["analysis_blockers"]
        ))

    def test_wrapper_summary_stops_at_business_function_with_other_calls(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        inner_call = call(
            "site:2000:2010:1", "fn:1000", "memcpy",
            [node("dst", slot=0), node("src", slot=1), node("len", slot=2)],
            0x1000,
        )
        wrapper = function("fn:2000", "helper_17", [inner_call], 3)
        wrapper_call = call(
            "site:3000:3010:1", "fn:2000", "helper_17",
            [node("out", slot=0), node("packet", slot=1), node("count", slot=2)],
            0x2000,
        )
        other_call = call(
            "site:3000:3020:1", "fn:5000", "unrelated_42",
            [node("packet", slot=1)], 0x5000,
        )
        business = function(
            "fn:3000", "process_91", [wrapper_call, other_call], 3
        )
        top_call = call(
            "site:4000:4010:1", "fn:3000", "process_91",
            [node("dst", slot=0), node("rx", slot=1), node("rx_len", slot=2)],
            0x3000,
        )
        top = function("fn:4000", "task_63", [top_call], 3)
        unrelated = function("fn:5000", "unrelated_42", [], 1)

        artifact, _compatibility = engine.analyze(
            program_facts=facts([memcpy, wrapper, business, top, unrelated]),
            registry=registry(), display_calls=[], input_metadata={},
        )

        self.assertEqual(len(artifact["sink_startpoints"]), 1)
        self.assertEqual(
            artifact["sink_startpoints"][0]["site_id"],
            "site:3000:3010:1",
        )
        self.assertEqual(
            artifact["sink_startpoints"][0]["effect_site_id"],
            "site:2000:2010:1",
        )
        self.assertTrue(any(
            row.get("reason") == "wrapper_body_has_additional_calls"
            for row in artifact["analysis_blockers"]
        ))
        registry_text = json.dumps(registry())
        self.assertNotIn("qzv_17", registry_text)
        self.assertNotIn("mcu_vendor_42", registry_text)

    def test_wrapper_boundary_prunes_constant_length_but_keeps_source(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        inner_call = call(
            "site:2000:2010:1", "fn:1000", "memcpy",
            [node("out", slot=0), node("input", slot=1), node("count", slot=2)],
            0x1000,
        )
        wrapper = function("fn:2000", "helper_91", [inner_call], 3)
        outer_call = call(
            "site:3000:3010:1", "fn:2000", "helper_91",
            [node("dst", slot=0), node("packet", slot=1), node("four", constant=4)],
            0x2000,
        )
        caller = function("fn:3000", "consumer", [outer_call], 2)
        artifact, _compatibility = engine.analyze(
            program_facts=facts([memcpy, wrapper, caller]),
            registry=registry(), display_calls=[], input_metadata={},
        )
        self.assertEqual(len(artifact["sink_startpoints"]), 1)
        row = artifact["sink_startpoints"][0]
        self.assertEqual(row["site_id"], "site:3000:3010:1")
        self.assertEqual(
            [parameter["role"] for parameter in row["vulnerable_parameters"]],
            ["src"],
        )
        self.assertEqual(
            [
                (parameter["role"], parameter["prune_reason"])
                for parameter in row["pruned_vulnerable_parameters"]
            ],
            [("len", "constant_scalar")],
        )

    def test_wrapper_rejects_undefined_local_destination(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        inner_call = call(
            "site:2000:2010:1", "fn:1000", "memcpy",
            [node("local_dst"), node("input", slot=0), node("count", slot=1)],
            0x1000,
        )
        helper = function("fn:2000", "helper_73", [inner_call], 2)
        outer_call = call(
            "site:3000:3010:1", "fn:2000", "helper_73",
            [node("packet", slot=0), node("length", slot=1)], 0x2000,
        )
        caller = function("fn:3000", "consumer", [outer_call], 2)
        artifact, _compatibility = engine.analyze(
            program_facts=facts([memcpy, helper, caller]),
            registry=registry(), display_calls=[], input_metadata={},
        )
        self.assertEqual(len(artifact["sink_startpoints"]), 1)
        self.assertEqual(
            artifact["sink_startpoints"][0]["site_id"], "site:2000:2010:1"
        )
        self.assertEqual(artifact["body_derived_boundary_callsites"], [])
        self.assertTrue(any(
            blocker.get("reason") == "summary_role_has_no_formal_object_lineage:dst"
            for blocker in artifact["analysis_blockers"]
        ))

    def test_explicit_admission_role_requires_exact_binding_and_is_reported(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        exact_call = call(
            "site:2000:2010:1", "fn:1000", "memcpy",
            [node("dst", slot=0), node("src", slot=1), node("len", slot=2)],
            0x1000,
        )
        exact_helper = function("fn:2000", "body_47", [exact_call], 3)
        exact_boundary = call(
            "site:3000:3010:1", "fn:2000", "body_47",
            [node("out", slot=0), node("packet", slot=1), node("count", slot=2)],
            0x2000,
        )
        exact_caller = function("fn:3000", "consumer_53", [exact_boundary], 3)
        configured = registry()
        configured["primitive_sinks"]["memcpy"]["admission_roles"] = ["dst"]

        accepted, _compatibility = engine.analyze(
            program_facts=facts([memcpy, exact_helper, exact_caller]),
            registry=configured, display_calls=[], input_metadata={},
        )
        self.assertEqual(accepted["sink_startpoints"][0]["admission_roles"], ["dst"])

        derived_helper = function(
            "fn:4000", "body_59", derived_formal_destination_call(), 3
        )
        derived_boundary = call(
            "site:5000:5010:1", "fn:4000", "body_59",
            [node("state", slot=0), node("packet", slot=1), node("count", slot=2)],
            0x4000,
        )
        derived_caller = function("fn:5000", "consumer_61", [derived_boundary], 3)
        rejected, _compatibility = engine.analyze(
            program_facts=facts([memcpy, derived_helper, derived_caller]),
            registry=configured, display_calls=[], input_metadata={},
        )
        self.assertEqual(
            [row["site_id"] for row in rejected["sink_startpoints"]],
            ["site:2000:2010:7"],
        )
        self.assertTrue(any(
            blocker.get("reason") == "summary_role_not_formal_or_constant:dst"
            for blocker in rejected["analysis_blockers"]
        ))

    def test_immutable_source_and_constant_length_withdraw_the_callsite(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        op = call(
            "site:2000:2010:1", "fn:1000", "memcpy",
            [
                node("dst", slot=0),
                global_address("constant_bytes", 0x3000),
                node("four", constant=4),
            ],
            0x1000,
        )
        caller = function("fn:2000", "copy_constant_header", [op], 1)
        program = facts([memcpy, caller])
        program["memory_blocks"] = [{
            "name": ".rodata", "start": "0x3000", "end": "0x30ff",
            "read": True, "write": False, "execute": False,
            "initialized": True,
        }]
        artifact, _compatibility = engine.analyze(
            program_facts=program, registry=registry(), display_calls=[],
            input_metadata={},
        )
        self.assertEqual(artifact["sink_startpoints"], [])
        row = artifact["withdrawn_out_of_scope"][0]
        self.assertEqual(row["withdraw_reason"], "no_trackable_vulnerable_parameter")
        self.assertEqual(
            {item["prune_reason"] for item in row["pruned_vulnerable_parameters"]},
            {"immutable_memory_object", "constant_scalar"},
        )

    def test_constant_writable_source_tracks_memory_content(self) -> None:
        memcpy = function("fn:1000", "memcpy", [], 3)
        op = call(
            "site:2000:2010:1", "fn:1000", "memcpy",
            [
                node("dst", slot=0),
                global_address("rx_buffer", 0x4000),
                node("four", constant=4),
            ],
            0x1000,
        )
        caller = function("fn:2000", "copy_buffer", [op], 1)
        program = facts([memcpy, caller])
        program["memory_blocks"] = [{
            "name": ".data", "start": "0x4000", "end": "0x40ff",
            "read": True, "write": True, "execute": False,
            "initialized": True,
        }]
        artifact, _compatibility = engine.analyze(
            program_facts=program, registry=registry(), display_calls=[],
            input_metadata={},
        )
        self.assertEqual(len(artifact["sink_startpoints"]), 1)
        parameter = artifact["sink_startpoints"][0]["vulnerable_parameters"][0]
        self.assertEqual(parameter["role"], "src")
        self.assertTrue(parameter["track_memory_content"])
        self.assertEqual(parameter["constant_address"], "0x4000")

    def test_loaded_global_pointer_is_not_pruned_as_immutable_slot(self) -> None:
        strcpy = function("fn:1000", "strcpy", [], 2)
        loaded_pointer = global_address("configured_pointer", 0x3000)
        loaded_pointer["high_data_type"] = "char *"
        loaded_pointer["def_site_id"] = "site:2000:2008:1"
        op = call(
            "site:2000:2010:2", "fn:1000", "strcpy",
            [node("dst", slot=0), loaded_pointer], 0x1000,
        )
        caller = function("fn:2000", "copy_configured_value", [op], 1)
        program = facts([strcpy, caller])
        program["memory_blocks"] = [{
            "name": ".rodata", "start": "0x3000", "end": "0x30ff",
            "read": True, "write": False, "execute": False,
            "initialized": True,
        }]

        artifact, _compatibility = engine.analyze(
            program_facts=program, registry=registry(), display_calls=[],
            input_metadata={},
        )

        self.assertEqual(len(artifact["sink_startpoints"]), 1)
        parameter = artifact["sink_startpoints"][0]["vulnerable_parameters"][0]
        self.assertEqual(parameter["role"], "src")
        self.assertNotIn("constant_address", parameter)
        self.assertEqual(artifact["withdrawn_out_of_scope"], [])

    def test_loaded_pointer_slot_tracks_its_writable_pointee(self) -> None:
        strcpy = function("fn:1000", "strcpy", [], 2)
        loaded_pointer = global_address("configured_pointer", 0x3000)
        loaded_pointer["high_data_type"] = "char *"
        loaded_pointer["def_site_id"] = "site:2000:2008:1"
        loaded_pointer["initial_memory_value"] = "0x4000"
        op = call(
            "site:2000:2010:2", "fn:1000", "strcpy",
            [node("dst", slot=0), loaded_pointer], 0x1000,
        )
        caller = function("fn:2000", "copy_configured_value", [op], 1)
        program = facts([strcpy, caller])
        program["memory_blocks"] = [
            {
                "name": ".rodata", "start": "0x3000", "end": "0x30ff",
                "read": True, "write": False, "initialized": True,
            },
            {
                "name": ".bss", "start": "0x4000", "end": "0x40ff",
                "read": True, "write": True, "initialized": False,
            },
        ]

        artifact, _compatibility = engine.analyze(
            program_facts=program, registry=registry(), display_calls=[],
            input_metadata={},
        )

        parameter = artifact["sink_startpoints"][0]["vulnerable_parameters"][0]
        self.assertEqual(parameter["constant_address"], "0x4000")
        self.assertEqual(parameter["memory_block"], ".bss")
        self.assertTrue(parameter["track_memory_content"])

    def test_loaded_pointer_slot_prunes_its_readonly_pointee(self) -> None:
        strcpy = function("fn:1000", "strcpy", [], 2)
        loaded_pointer = global_address("configured_pointer", 0x3000)
        loaded_pointer["high_data_type"] = "char *"
        loaded_pointer["def_site_id"] = "site:2000:2008:1"
        loaded_pointer["initial_memory_value"] = "0x5000"
        op = call(
            "site:2000:2010:2", "fn:1000", "strcpy",
            [node("dst", slot=0), loaded_pointer], 0x1000,
        )
        caller = function("fn:2000", "copy_configured_value", [op], 1)
        program = facts([strcpy, caller])
        program["memory_blocks"] = [
            {
                "name": ".rodata", "start": "0x3000", "end": "0x50ff",
                "read": True, "write": False, "initialized": True,
            },
        ]

        artifact, _compatibility = engine.analyze(
            program_facts=program, registry=registry(), display_calls=[],
            input_metadata={},
        )

        self.assertEqual(artifact["sink_startpoints"], [])
        pruned = artifact["withdrawn_out_of_scope"][0][
            "pruned_vulnerable_parameters"
        ][0]
        self.assertEqual(pruned["constant_address"], "0x5000")
        self.assertEqual(pruned["prune_reason"], "immutable_memory_object")

    def test_name_only_framework_call_is_ignored(self) -> None:
        custom = function("fn:1000", "net_buf_simple_add_mem", [], 3)
        op = call(
            "site:2000:2010:1", "fn:1000", "net_buf_simple_add_mem",
            [node("dst", slot=0), node("src", slot=1), node("len", slot=2)],
            0x1000,
        )
        caller = function("fn:2000", "task", [op], 3)
        artifact, _compatibility = engine.analyze(
            program_facts=facts([custom, caller]), registry=registry(),
            display_calls=[], input_metadata={},
        )
        self.assertEqual(artifact["sink_startpoints"], [])

    def test_readonly_format_object_is_not_a_dfa_startpoint(self) -> None:
        printf = function("fn:1000", "printf", [], 1)
        op = call(
            "site:2000:2010:1", "fn:1000", "printf",
            [global_address("DAT_00003000", 0x3000)], 0x1000,
        )
        caller = function("fn:2000", "log_status", [op], 0)
        program = facts([printf, caller])
        program["memory_blocks"] = [{
            "name": ".rodata", "start": "0x3000", "end": "0x30ff",
            "read": True, "write": False, "execute": False,
            "initialized": True,
        }]
        artifact, _compatibility = engine.analyze(
            program_facts=program, registry=registry(), display_calls=[],
            input_metadata={},
        )
        self.assertEqual(artifact["sink_startpoints"], [])
        self.assertEqual(
            artifact["withdrawn_out_of_scope"][0]["withdraw_reason"],
            "readonly_format_object",
        )

    def test_writable_format_object_remains_a_dfa_startpoint(self) -> None:
        printf = function("fn:1000", "printf", [], 1)
        op = call(
            "site:2000:2010:1", "fn:1000", "printf",
            [global_address("format_buffer", 0x4000)], 0x1000,
        )
        caller = function("fn:2000", "render_message", [op], 0)
        program = facts([printf, caller])
        program["memory_blocks"] = [{
            "name": ".data", "start": "0x4000", "end": "0x40ff",
            "read": True, "write": True, "execute": False,
            "initialized": True,
        }]
        artifact, _compatibility = engine.analyze(
            program_facts=program, registry=registry(), display_calls=[],
            input_metadata={},
        )
        self.assertEqual(len(artifact["sink_startpoints"]), 1)


if __name__ == "__main__":
    unittest.main()
