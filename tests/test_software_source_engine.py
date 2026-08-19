import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "software_source_engine", ROOT / "scripts" / "software_source_engine.py"
)
engine = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = engine
SPEC.loader.exec_module(engine)


def node(
    value_id, object_id, *, name="", constant=False, offset="0x0",
    slot=None, address=False, high_type="",
):
    return {
        "value_id": value_id,
        "object_id": object_id,
        "high_name": name,
        "is_constant": constant,
        "is_address": address,
        "offset": offset,
        "parameter_slot": slot,
        "high_data_type": high_type,
    }


def function(entry, name, params, ops):
    return {
        "function_id": f"fn:{entry:08x}",
        "entry": f"0x{entry:x}",
        "name": name,
        "parameters": [
            {"index": i, "name": p, "object_id": f"param:{entry:08x}:{i}"}
            for i, p in enumerate(params)
        ],
        "pcode_ops": ops,
    }


def call(site, target, args, output=None, *, indirect=False):
    return {
        "site_id": site,
        "mnemonic": "CALLIND" if indirect else "CALL",
        "output": output,
        "inputs": [target] + args,
        "call": {
            "kind": "CALLIND" if indirect else "CALL",
            "target_function": "" if indirect else target.get("high_name", ""),
            "target_function_id": "" if indirect else target.get("target_function_id", ""),
        },
    }


def summary_pack(*summaries, callbacks=()):
    return {
        "schema_version": "test",
        "summaries": list(summaries),
        "callback_registrations": list(callbacks),
    }


RECV = {
    "summary_id": "mango.recv",
    "function_names": ["recv"],
    "match": {"min_args": 4, "max_args": 4, "scope": "standard_abi"},
    "channel": "network",
    "proof_kind": "trusted_mango_handler_contract",
    "outputs": [
        {"role": "output_buffer", "binding_kind": "formal_pointee", "parameter_slot": 1},
        {"role": "received_length", "binding_kind": "return_value"},
    ],
}


READ = {
    "summary_id": "mango.read",
    "function_names": ["read"],
    "match": {"min_args": 3, "max_args": 3, "scope": "standard_abi"},
    "channel": "descriptor_input",
    "proof_kind": "trusted_mango_handler_contract",
    "descriptor": {"parameter_slot": 0, "provenance_required": True},
    "outputs": [
        {"role": "output_buffer", "binding_kind": "formal_pointee", "parameter_slot": 1},
        {"role": "received_length", "binding_kind": "return_value"},
    ],
}


def test_recv_contract_binds_exact_call_actual_and_return():
    recv = function(0x2000, "recv", ["fd", "buf", "n", "flags"], [])
    dst = node("v:dst", "reg:1000:20:4", name="packet")
    result = node("v:ret", "reg:1000:0:4", name="nread")
    op = call(
        "site:00001000:00001010:1",
        node("fnptr:recv", "global:2000:8", name="recv", address=True, offset="0x2000")
        | {"target_function_id": "fn:00002000"},
        [node("fd", "reg:1000:0:4"), dst, node("n", "const:40:4", constant=True, offset="0x40"), node("fl", "const:0:4", constant=True)],
        result,
    )
    caller = function(0x1000, "handle", [], [op])
    out = engine.analyze({"functions": [caller, recv]}, summary_pack(RECV))
    assert len(out["confirmed_sources"]) == 1
    row = out["confirmed_sources"][0]
    assert row["site_id"] == op["site_id"]
    assert row["source_outputs"][0]["object_id"] == "pointee:v:dst"
    assert row["source_outputs"][1]["value_id"] == "v:ret"


def test_two_argument_internal_read_is_not_posix_read_contract():
    read = function(0x2000, "read", ["buf", "n"], [])
    op = call(
        "site:00001000:00001010:1",
        node("fnptr:read", "global:2000:8", name="read", address=True, offset="0x2000")
        | {"target_function_id": "fn:00002000"},
        [node("v:buf", "reg:1000:0:4"), node("n", "const:40:4", constant=True, offset="0x40")],
        node("v:ret", "reg:1000:0:4"),
    )
    out = engine.analyze({"functions": [function(0x1000, "caller", [], [op]), read]}, summary_pack(READ))
    assert out["confirmed_sources"] == []


def test_three_argument_member_read_with_scalar_output_slot_is_not_posix_read():
    read = function(0x2000, "read", ["this", "offset", "callback"], [])
    read["parameters"][0]["data_type"] = "Characteristic *"
    read["parameters"][1]["data_type"] = "uint16_t"
    read["parameters"][2]["data_type"] = "ReadCallback *"
    op = call(
        "site:00001000:00001010:1",
        node("fnptr:read", "global:2000:8", name="read", address=True, offset="0x2000")
        | {"target_function_id": "fn:00002000"},
        [
            node("stdin", "const:0:4", constant=True),
            node("offset", "const:0:2", constant=True, high_type="uint16_t"),
            node("callback", "reg:1000:8:4", high_type="ReadCallback *"),
        ],
        node("v:ret", "reg:1000:0:4"),
    )
    out = engine.analyze(
        {"functions": [function(0x1000, "caller", [], [op]), read]},
        summary_pack(READ),
    )
    assert out["confirmed_sources"] == []


def test_wrapper_discovery_rechecks_callee_abi_before_propagation():
    member_read = function(
        0x3000, "read", ["this", "connection", "attribute", "offset"], []
    )
    member_read["parameters"][0]["data_type"] = "GattClient *"
    member_read["parameters"][1]["data_type"] = "uintptr_t"
    member_read["parameters"][2]["data_type"] = "uint16_t"
    member_read["parameters"][3]["data_type"] = "uint16_t"
    wrapper_offset = node(
        "v:offset", "param:00002000:1", name="offset", slot=1,
        high_type="uint16_t",
    )
    member_call = call(
        "site:00002000:00002010:1",
        node("fnptr:read", "global:3000:8", name="read", address=True, offset="0x3000")
        | {"target_function_id": "fn:00003000"},
        [
            node("this", "param:00002000:0", slot=0, high_type="GattClient *"),
            wrapper_offset,
            node("attr", "reg:2000:8:2", high_type="uint16_t"),
            wrapper_offset,
        ],
        node("v:ret", "reg:2000:0:4"),
    )
    wrapper = function(0x2000, "read", ["this", "offset"], [member_call])
    out = engine.analyze(
        {"functions": [wrapper, member_read]}, summary_pack(READ)
    )
    assert out["confirmed_sources"] == []
    assert not any(
        summary["proof_kind"] == "direct_wrapper_actual_formal_return_binding"
        for summary in out["function_summaries"]
    )


def test_socket_provenance_allows_posix_read():
    socket_fn = function(0x3000, "socket", ["domain", "type", "proto"], [])
    read_fn = function(0x2000, "read", ["fd", "buf", "n"], [])
    fd = node("v:fd", "reg:1000:0:4", name="fd")
    socket_call = call(
        "site:00001000:00001004:1",
        node("fnptr:socket", "global:3000:8", name="socket", address=True, offset="0x3000")
        | {"target_function_id": "fn:00003000"},
        [node("a", "const:2:4", constant=True, offset="2"), node("b", "const:1:4", constant=True, offset="1"), node("c", "const:0:4", constant=True)],
        fd,
    )
    read_call = call(
        "site:00001000:00001010:1",
        node("fnptr:read", "global:2000:8", name="read", address=True, offset="0x2000")
        | {"target_function_id": "fn:00002000"},
        [fd, node("v:buf", "reg:1000:4:4", name="buf"), node("n", "const:40:4", constant=True, offset="0x40")],
        node("v:nread", "reg:1000:0:4"),
    )
    caller = function(0x1000, "handle", [], [socket_call, read_call])
    out = engine.analyze({"functions": [caller, socket_fn, read_fn]}, summary_pack(READ))
    assert len(out["confirmed_sources"]) == 1
    proof = out["confirmed_sources"][0]["proof"]["descriptor_provenance"]
    assert proof["kind"] == "network_socket"


def test_read_without_descriptor_provenance_is_not_confirmed():
    read_fn = function(0x2000, "read", ["fd", "buf", "n"], [])
    read_call = call(
        "site:00001000:00001010:1",
        node("fnptr:read", "global:2000:8", name="read", address=True, offset="0x2000")
        | {"target_function_id": "fn:00002000"},
        [node("v:unknown-fd", "reg:1000:0:4"), node("v:buf", "reg:1000:4:4"), node("n", "const:40:4", constant=True, offset="0x40")],
        node("v:nread", "reg:1000:0:4"),
    )
    out = engine.analyze({"functions": [function(0x1000, "handle", [], [read_call]), read_fn]}, summary_pack(READ))
    assert out["confirmed_sources"] == []


def test_direct_wrapper_propagates_output_formal():
    recv = function(0x3000, "recv", ["fd", "buf", "n", "flags"], [])
    wrapper_buf = node("v:wbuf", "param:00002000:0", name="out", slot=0)
    recv_call = call(
        "site:00002000:00002008:1",
        node("fnptr:recv", "global:3000:8", name="recv", address=True, offset="0x3000")
        | {"target_function_id": "fn:00003000"},
        [node("fd", "reg:2000:0:4"), wrapper_buf, node("n", "const:40:4", constant=True, offset="0x40"), node("fl", "const:0:4", constant=True)],
        node("v:wret", "reg:2000:0:4"),
    )
    wrapper = function(0x2000, "receive_wrapper", ["out"], [recv_call])
    dst = node("v:dst", "reg:1000:4:4", name="packet")
    wrapper_call = call(
        "site:00001000:00001010:1",
        node("fnptr:wrapper", "global:2000:8", name="receive_wrapper", address=True, offset="0x2000")
        | {"target_function_id": "fn:00002000"},
        [dst],
        node("v:ret", "reg:1000:0:4"),
    )
    caller = function(0x1000, "handle", [], [wrapper_call])
    out = engine.analyze({"functions": [caller, wrapper, recv]}, summary_pack(RECV))
    wrapper_rows = [row for row in out["confirmed_sources"] if row["callee"] == "receive_wrapper"]
    assert len(wrapper_rows) == 1
    assert wrapper_rows[0]["source_outputs"][0]["object_id"] == "pointee:v:dst"


def test_read_wrapper_preserves_descriptor_provenance_requirement():
    socket_fn = function(0x4000, "socket", ["domain", "type", "proto"], [])
    read_fn = function(0x3000, "read", ["fd", "buf", "n"], [])
    wrapper_fd = node("v:wfd", "param:00002000:0", name="fd", slot=0)
    wrapper_buf = node(
        "v:wbuf", "param:00002000:1", name="buf", slot=1,
        high_type="void *",
    )
    wrapper_n = node(
        "v:wn", "param:00002000:2", name="n", slot=2,
        high_type="size_t",
    )
    read_call = call(
        "site:00002000:00002008:1",
        node("fnptr:read", "global:3000:8", name="read", address=True, offset="0x3000")
        | {"target_function_id": "fn:00003000"},
        [wrapper_fd, wrapper_buf, wrapper_n],
        node("v:wret", "reg:2000:0:4"),
    )
    wrapper = function(0x2000, "read_wrapper", ["fd", "buf", "n"], [read_call])

    fd = node("v:fd", "reg:1000:0:4", name="fd")
    socket_call = call(
        "site:00001000:00001004:1",
        node("fnptr:socket", "global:4000:8", name="socket", address=True, offset="0x4000")
        | {"target_function_id": "fn:00004000"},
        [
            node("domain", "const:2:4", constant=True, offset="2"),
            node("type", "const:1:4", constant=True, offset="1"),
            node("proto", "const:0:4", constant=True),
        ],
        fd,
    )
    dst = node("v:dst", "reg:1000:4:4", name="packet", high_type="void *")
    wrapper_call = call(
        "site:00001000:00001010:1",
        node(
            "fnptr:wrapper", "global:2000:8", name="read_wrapper",
            address=True, offset="0x2000",
        ) | {"target_function_id": "fn:00002000"},
        [fd, dst, node("n", "const:40:4", constant=True, offset="0x40")],
        node("v:ret", "reg:1000:0:4"),
    )
    caller = function(0x1000, "handle", [], [socket_call, wrapper_call])

    out = engine.analyze(
        {"functions": [caller, wrapper, read_fn, socket_fn]}, summary_pack(READ)
    )
    rows = [
        row for row in out["confirmed_sources"]
        if row["callee"] == "read_wrapper"
    ]
    assert len(rows) == 1
    assert rows[0]["source_outputs"][0]["object_id"] == "pointee:v:dst"
    assert rows[0]["proof"]["descriptor_provenance"]["kind"] == "network_socket"


def test_constant_callind_target_is_resolved():
    recv = function(0x3000, "recv", ["fd", "buf", "n", "flags"], [])
    target = node("const:3001", "const:3001:4", constant=True, offset="0x3001")
    op = call(
        "site:00001000:00001010:1", target,
        [node("fd", "reg:0"), node("v:dst", "reg:4", name="packet"), node("n", "const:20", constant=True, offset="0x20"), node("f", "const:0", constant=True)],
        node("v:ret", "reg:0"), indirect=True,
    )
    out = engine.analyze({"functions": [function(0x1000, "dispatch", [], [op]), recv]}, summary_pack(RECV))
    assert len(out["confirmed_sources"]) == 1
    assert out["unresolved_indirect_calls"] == []


def test_trusted_registration_binds_callback_parameters():
    register = function(0x3000, "register_input_callback", ["cb"], [])
    callback = function(0x4000, "on_packet", ["ctx", "packet", "len"], [])
    registration = call(
        "site:00001000:00001004:1",
        node("fnptr:register", "global:3000:8", name="register_input_callback", address=True, offset="0x3000")
        | {"target_function_id": "fn:00003000"},
        [node("cb", "const:4001:4", constant=True, offset="0x4001")],
    )
    dispatch = call(
        "site:00002000:00002010:1",
        node("cb", "const:4001:4", constant=True, offset="0x4001"),
        [node("ctx", "reg:0"), node("packet", "reg:4", name="packet"), node("len", "reg:8")],
        indirect=True,
    )
    pack = summary_pack(callbacks=[{
        "registration_names": ["register_input_callback"],
        "callback_arg_index": 0,
        "channel": "framework_callback_input",
        "callback_outputs": [
            {"role": "output_buffer", "binding_kind": "formal_pointee", "parameter_slot": 1},
            {"role": "received_length", "binding_kind": "formal_value", "parameter_slot": 2},
        ],
    }])
    out = engine.analyze(
        {"functions": [function(0x1000, "setup", [], [registration]), function(0x2000, "framework", [], [dispatch]), register, callback]},
        pack,
    )
    callback_rows = [row for row in out["confirmed_sources"] if row["callee"] == "on_packet"]
    assert len(callback_rows) == 1
    assert callback_rows[0]["source_outputs"][0]["object_id"] == "pointee:packet"


def test_source_definitions_include_admitted_bound_outputs_with_decision():
    rows = [{
        "id": "SO1", "decision": "ACCEPT_DETERMINISTIC", "site_id": "site:1",
        "function_id": "fn:1", "function": "f", "source_kind": "network",
        "source_outputs": [{"kind": "scalar_value", "value_id": "value:1", "object_id": ""}],
        "proof": {"kind": "test"},
    }, {
        "id": "SO2", "decision": "ACCEPT_HEURISTIC", "site_id": "site:2",
        "source_outputs": [{"kind": "scalar_value", "value_id": "value:2"}],
    }]
    definitions = engine.source_definitions(rows)
    assert len(definitions) == 2
    by_source = {row["source_id"]: row for row in definitions}
    assert by_source["SO1"]["decision"] == "ACCEPT_DETERMINISTIC"
    assert by_source["SO1"]["outputs"][0]["value_id"] == "value:1"
    assert by_source["SO2"]["decision"] == "ACCEPT_HEURISTIC"
    assert by_source["SO2"]["outputs"][0]["value_id"] == "value:2"


def test_resolved_callind_and_stack_descriptor_propagate_body_source_without_names():
    target = function(0x9000, "target_impl", ["dev", "rx_desc"], [])
    indirect = call(
        "site:00008000:00008010:7",
        node("v:target", "reg:8000:c:4"),
        [],
        node("v:result", "reg:8000:0:4"),
        indirect=True,
    )
    indirect.update({"instruction_address": "0x8010", "op_order": 7})
    wrapper = function(0x8000, "typed_dispatch", ["dev", "rx_desc"], [indirect])

    sp = node("v:sp", "reg:00007000:54:4")
    descriptor = node("v:desc", "unique:00007000:desc:4")
    element = node("v:element", "unique:00007000:element:4")
    formal_data = node("v:data", "param:00007000:0", name="data", slot=0)
    ptr_desc = {
        "site_id": "site:00007000:00007004:1", "instruction_address": "0x7004",
        "op_order": 1, "mnemonic": "PTRSUB", "output": descriptor,
        "inputs": [sp, node("c:-10", "const:fffffff0:4", constant=True, offset="0xfffffff0") | {"size": 4}],
    }
    ptr_element = {
        "site_id": "site:00007000:00007006:2", "instruction_address": "0x7006",
        "op_order": 2, "mnemonic": "PTRSUB", "output": element,
        "inputs": [sp, node("c:-18", "const:ffffffe8:4", constant=True, offset="0xffffffe8") | {"size": 4}],
    }
    cause = node("cause", "const:7:4", constant=True, offset="0x7")
    snapshot_desc = {
        "site_id": "site:00007000:00007010:20", "instruction_address": "0x7010",
        "op_order": 20, "mnemonic": "INDIRECT",
        "output": node("v:stack-desc", "stack:00007000:-10:4"),
        "inputs": [element, cause],
    }
    snapshot_element = {
        "site_id": "site:00007000:00007010:21", "instruction_address": "0x7010",
        "op_order": 21, "mnemonic": "INDIRECT",
        "output": node("v:stack-element", "stack:00007000:-18:4"),
        "inputs": [formal_data, cause],
    }
    direct = call(
        "site:00007000:00007010:7",
        node("fn:wrapper", "global:8000:8", name="typed_dispatch", address=True, offset="0x8000")
        | {"target_function_id": "fn:00008000"},
        [node("dev", "reg:7000:0:4"), descriptor],
    )
    direct.update({"instruction_address": "0x7010", "op_order": 7})
    caller = function(
        0x7000, "caller", ["data"],
        [ptr_desc, ptr_element, direct, snapshot_desc, snapshot_element],
    )
    seed = {
        "id": "SO-seed", "decision": "ACCEPT_DETERMINISTIC",
        "function_id": "fn:00009000", "function": "target_impl",
        "site_id": "site:00009000:00009020:1",
        "source_kind": "peripheral_input",
        "source_object_id": "param:00009000:1",
        "source_outputs": [{"role": "output_buffer", "kind": "memory_object", "object_id": "param:00009000:1"}],
        "proof": {
            "source_buffer_formal_access": {"parameter_slot": 1, "access_path": [0, 0]}
        },
    }
    facts = {
        "functions": [caller, wrapper, target],
        "device_dispatch_resolution": {
            "resolved": [{
                "callsite": {"site_id": indirect["site_id"]},
                "target": {"function_id": "fn:00009000"},
                "formal_identity_bindings": [
                    {"caller_parameter_slot": 0, "target_parameter_slot": 0},
                    {"caller_parameter_slot": 1, "target_parameter_slot": 1},
                ],
            }]
        },
    }

    result = engine.analyze(facts, summary_pack(), seed_sources=[seed])

    rows = [row for row in result["confirmed_sources"] if row["function"] == "caller"]
    assert len(rows) == 1
    assert rows[0]["source_buffer"] == "data"
    assert rows[0]["source_outputs"][0]["object_id"] == "param:00007000:0"


def test_typed_state_field_derives_nested_formal_output_without_names():
    space = node("space", "const:1", constant=True, offset="0x1")
    state = node("v:isr-state", "param:00001000:0", slot=0, high_type="driver_state *")
    field = node("v:isr-field", "u:isr-field", high_type="uint8_t **")
    buffer_pointer = node("v:isr-buffer", "reg:isr-buffer", name="dst", high_type="uint8_t *")
    isr_ops = [
        {"site_id": "site:00001000:00001004:1", "mnemonic": "PTRSUB", "output": field,
         "inputs": [state, node("off10", "const:10", constant=True, offset="0x10")]},
        {"site_id": "site:00001000:00001008:2", "mnemonic": "LOAD", "output": buffer_pointer,
         "inputs": [space, field]},
    ]
    isr = function(0x1000, "irq_handler", ["device"], isr_ops)

    driver_state = node(
        "v:driver-state", "param:00002000:0", slot=0, high_type="driver_state *"
    )
    descriptor = node(
        "v:descriptor", "param:00002000:1", slot=1, high_type="descriptor *"
    )
    descriptor_field = node("v:descriptor-field", "u:descriptor-field", high_type="item **")
    item = node("v:item", "reg:item", high_type="item *")
    item_field = node("v:item-field", "u:item-field", high_type="uint8_t **")
    caller_buffer = node("v:caller-buffer", "reg:caller-buffer", high_type="uint8_t *")
    state_field = node("v:state-field", "u:state-field", high_type="uint8_t **")
    driver_ops = [
        {"site_id": "site:00002000:00002004:1", "mnemonic": "PTRSUB", "output": descriptor_field,
         "inputs": [descriptor, node("off0a", "const:0", constant=True, offset="0x0")]},
        {"site_id": "site:00002000:00002008:2", "mnemonic": "LOAD", "output": item,
         "inputs": [space, descriptor_field]},
        {"site_id": "site:00002000:0000200c:3", "mnemonic": "PTRSUB", "output": item_field,
         "inputs": [item, node("off4", "const:4", constant=True, offset="0x4")]},
        {"site_id": "site:00002000:00002010:4", "mnemonic": "LOAD", "output": caller_buffer,
         "inputs": [space, item_field]},
        {"site_id": "site:00002000:00002014:5", "mnemonic": "PTRSUB", "output": state_field,
         "inputs": [driver_state, node("off10b", "const:10", constant=True, offset="0x10")]},
        {"site_id": "site:00002000:00002018:6", "mnemonic": "STORE", "output": None,
         "inputs": [space, state_field, caller_buffer]},
    ]
    driver = function(0x2000, "driver_operation", ["state", "descriptor"], driver_ops)
    facts = {"functions": [isr, driver]}
    index = engine.ProgramIndex(facts)
    seed = {
        "id": "SO1", "decision": "ACCEPT_DETERMINISTIC",
        "function_id": "fn:00001000", "function": "irq_handler",
        "site_id": "site:00001000:00001020:9",
        "source_kind": "peripheral_data_register_to_buffer",
        "proof": {"destination_pointer_value_id": "v:isr-buffer"},
    }
    summaries = engine.stateful_summaries_from_seed_sources(index, [seed])
    assert len(summaries) == 1
    output = summaries[0].outputs[0]
    assert summaries[0].function_id == "fn:00002000"
    assert output.binding_kind == "formal_access_path"
    assert output.parameter_slot == 1
    assert output.access_path == (0, 4)


def test_real_mango_pack_imports_only_generalized_source_contracts():
    pack = engine.read_json(ROOT / "registries" / "software_source_summaries.mango.json")
    summaries = engine.parse_summary_pack(pack)
    names = {name for summary in summaries for name in summary.function_names}
    assert {"read", "fread", "fgets", "recv", "recvfrom", "getenv"} <= names
    assert "nvram_get" not in names
    recv = next(summary for summary in summaries if "recv" in summary.function_names)
    assert [(out.role, out.binding_kind, out.parameter_slot) for out in recv.outputs] == [
        ("output_buffer", "formal_pointee", 1),
        ("available_length", "return_value", None),
    ]
    assert recv.outputs[1].extent_for_role == "output_buffer"


def test_explicit_mango_compat_mode_models_nvram_return_without_core_pollution():
    pack = engine.read_json(ROOT / "registries" / "software_source_summaries.mango.json")
    assert "nvram_get" not in {
        name for summary in engine.parse_summary_pack(pack)
        for name in summary.function_names
    }
    nvram = function(0x3000, "nvram_get", ["key"], [])
    result = node("v:nvram-result", "reg:1000:0:4", name="setting")
    op = call(
        "site:00001000:00001010:1",
        node("fnptr:nvram", "global:3000:4", name="nvram_get", address=True, offset="0x3000")
        | {"target_function_id": "fn:00003000"},
        [node("v:key", "global:4000:4", name="config_key")],
        result,
    )
    out = engine.analyze(
        {"functions": [function(0x1000, "load_config", [], [op]), nvram]},
        pack,
        include_compatibility_specific=True,
    )
    rows = [row for row in out["confirmed_sources"] if row["callee"] == "nvram_get"]
    assert len(rows) == 1
    assert rows[0]["source_kind"] == "persistent_configuration"
    assert rows[0]["source_outputs"][0]["kind"] == "memory_object"
    assert rows[0]["source_outputs"][0]["value_id"] == "v:nvram-result"
