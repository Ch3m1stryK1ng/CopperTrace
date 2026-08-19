import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "device_dispatch_resolver", ROOT / "scripts" / "device_dispatch_resolver.py"
)
resolver = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = resolver
SPEC.loader.exec_module(resolver)


def node(value_id, *, offset=0, constant=False, address=False, name=""):
    return {
        "value_id": value_id,
        "object_id": value_id.replace("value:", "object:"),
        "offset": hex(offset),
        "size": 4,
        "is_constant": constant,
        "is_address": address,
        "high_name": name,
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


def function(entry, name, ops=()):
    return {
        "function_id": f"fn:{entry:08x}",
        "entry": hex(entry),
        "name": name,
        "pcode_ops": list(ops),
    }


def word(value):
    return int(value).to_bytes(4, "little")


def memory_for_named_devices(*, duplicate=False):
    literal = bytearray(0x20)
    literal[0:4] = word(0x2000)  # runtime device-pointer storage
    literal[4:8] = word(0x5000)  # lookup name

    rodata = bytearray(0x2200)
    rodata[0:6] = b"BUS_3\x00"
    rodata[0x1000:0x1004] = word(0x5000)  # config.name
    rodata[0x2000:0x2004] = word(0x9001)  # API slot zero
    rodata[0x2100:0x2104] = word(0x9001)

    data = bytearray(0x200)
    data[0:4] = word(0x6000)      # device.config
    data[4:8] = word(0x7000)      # device.api
    if duplicate:
        data[0x100:0x104] = word(0x6000)
        data[0x104:0x108] = word(0x7100)

    return resolver.InitializedMemory.from_regions(
        [
            resolver.MemoryRegion(0x1000, bytes(literal), source="fixture:text", executable=True),
            resolver.MemoryRegion(0x5000, bytes(rodata), source="fixture:rodata"),
            resolver.MemoryRegion(0x8000, bytes(data), source="fixture:data", writable=True),
        ]
    )


def named_device_program(*, duplicate=False):
    call_result = node("value:init:result")
    lookup = op(
        "site:00001100:00001104:1",
        "CALL",
        call_result,
        node("function:lookup", offset=0xA000, address=True),
        node("literal:name", offset=0x1004, address=True),
    )
    lookup["call"] = {
        "kind": "CALL",
        "target_function_id": "fn:0000a000",
        "target_function": "lookup_by_label",
    }
    store = op(
        "site:00001100:00001108:2",
        "STORE",
        None,
        SPACE,
        node("literal:storage", offset=0x1000, address=True),
        call_result,
    )

    device = node("value:dispatch:device")
    api_address = node("value:dispatch:api_address")
    api = node("value:dispatch:api")
    target = node("value:dispatch:target")
    load_device = op(
        "site:00001200:00001204:1",
        "LOAD",
        device,
        SPACE,
        node("literal:storage:dispatch", offset=0x1000, address=True),
    )
    add_api = op(
        "site:00001200:00001208:2",
        "INT_ADD",
        api_address,
        device,
        node("const:api_offset", offset=4, constant=True),
    )
    load_api = op("site:00001200:0000120c:3", "LOAD", api, SPACE, api_address)
    load_target = op("site:00001200:00001210:4", "LOAD", target, SPACE, api)
    dispatch = op(
        "site:00001200:00001214:5",
        "CALLIND",
        node("value:dispatch:return"),
        target,
        device,
    )
    dispatch["call"] = {"kind": "CALLIND", "target_function_id": "", "target_function": ""}

    symbols = [
        {"name": "device_pointer", "address": "0x2000", "type": "Label"},
        {"name": "config_object", "address": "0x6000", "type": "Label"},
        {"name": "device_object", "address": "0x8000", "type": "Label"},
        {"name": "api_table", "address": "0x7000", "type": "Label"},
    ]
    if duplicate:
        symbols.extend(
            [
                {"name": "second_device", "address": "0x8100", "type": "Label"},
                {"name": "second_api", "address": "0x7100", "type": "Label"},
            ]
        )
    return {
        "schema_version": "fixture",
        "symbols": symbols,
        "functions": [
            function(0x1100, "initialize", [lookup, store]),
            function(0x1200, "dispatch", [load_device, add_api, load_api, load_target, dispatch]),
            function(0x9000, "resolved_operation"),
            function(0xA000, "lookup_by_label"),
        ],
    }


def test_resolves_named_device_api_slot_without_function_name_rules():
    result = resolver.resolve_device_dispatches(
        named_device_program(), initialized_memory=memory_for_named_devices()
    )
    assert result["counts"] == {"callind": 1, "resolved": 1, "ambiguous": 0, "unresolved": 0}
    row = result["resolved"][0]
    assert row["callsite"]["site_id"] == "site:00001200:00001214:5"
    assert row["target"]["function_id"] == "fn:00009000"
    assert row["target"]["raw_address"] == "0x9001"
    assert row["device"]["address"] == "0x8000"
    assert row["device"]["config_address"] == "0x6000"
    assert row["device"]["name"] == "BUS_3"
    assert row["table"]["address"] == "0x7000"
    assert row["slot"]["offset"] == 0
    assert row["slot"]["index"] == 0
    assert {item["kind"] for item in row["evidence"]} >= {
        "high_pcode_device_dispatch_load_chain",
        "named_device_binding_store",
        "initialized_api_table_slot",
    }


def test_expensive_fallback_budget_preserves_an_explicit_unresolved_callsite():
    result = resolver.resolve_device_dispatches(
        named_device_program(),
        initialized_memory=memory_for_named_devices(),
        max_expensive_fallbacks=0,
    )

    assert result["counts"] == {
        "callind": 1,
        "resolved": 0,
        "ambiguous": 0,
        "unresolved": 1,
    }
    assert result["unresolved"][0]["reason"] == "expensive_resolution_budget_exhausted"
    assert result["unresolved"][0]["callsite"]["site_id"] == (
        "site:00001200:00001214:5"
    )
    assert result["analysis_budget"] == {
        "max_expensive_fallbacks": 0,
        "expensive_fallbacks_attempted": 0,
    }


def test_multiple_matching_devices_are_preserved_as_ambiguous():
    result = resolver.resolve_device_dispatches(
        named_device_program(duplicate=True),
        initialized_memory=memory_for_named_devices(duplicate=True),
    )
    assert result["counts"] == {"callind": 1, "resolved": 0, "ambiguous": 1, "unresolved": 0}
    row = result["ambiguous"][0]
    assert row["reason"] == "multiple_initialized_device_candidates"
    assert {candidate["device"]["address"] for candidate in row["candidates"]} == {
        "0x8000",
        "0x8100",
    }


def test_exact_data_symbol_prevents_adjacent_object_cross_product():
    facts = named_device_program()
    facts["symbols"].extend(
        [
            {"name": "overlapping_config", "address": "0x5ff0", "type": "Label"},
            {"name": "unrelated_device", "address": "0x8100", "type": "Label"},
            {"name": "unrelated_api", "address": "0x7100", "type": "Label"},
        ]
    )
    memory = memory_for_named_devices()
    data_region = next(region for region in memory.regions if region.start == 0x8000)
    data = bytearray(data_region.data)
    data[0x100:0x104] = word(0x5ff0)
    data[0x104:0x108] = word(0x7100)
    memory.regions = [
        resolver.MemoryRegion(
            region.start,
            bytes(data) if region.start == 0x8000 else region.data,
            source=region.source,
            writable=region.writable,
            executable=region.executable,
        )
        for region in memory.regions
    ]

    result = resolver.resolve_device_dispatches(
        facts, initialized_memory=memory
    )

    assert result["counts"] == {
        "callind": 1,
        "resolved": 1,
        "ambiguous": 0,
        "unresolved": 0,
    }
    assert result["resolved"][0]["device"]["address"] == "0x8000"


def test_missing_initialized_binding_stays_unresolved():
    memory = memory_for_named_devices()
    memory.regions = [region for region in memory.regions if region.start != 0x8000]
    result = resolver.resolve_device_dispatches(named_device_program(), initialized_memory=memory)
    assert result["counts"] == {"callind": 1, "resolved": 0, "ambiguous": 0, "unresolved": 1}
    assert result["unresolved"][0]["reason"] == "device_candidates_not_unique_or_missing"


def test_resolves_unique_initialized_object_domain_return_table_without_names():
    def formal(function_entry, slot):
        return {
            **node(f"value:{function_entry:x}:param:{slot}"),
            "object_id": f"param:{function_entry:08x}:{slot}",
            "parameter_slot": slot,
            "is_parameter": True,
            "is_input": True,
            "high_data_type": "void *",
        }

    root = bytearray(4)
    root[:] = word(0x8100)
    middle = bytearray(8)
    middle[4:8] = word(0x8200)
    table = bytearray(4)
    table[:] = word(0x9001)
    memory = resolver.InitializedMemory.from_regions(
        [
            resolver.MemoryRegion(0x8000, bytes(root), source="fixture:root", writable=True),
            resolver.MemoryRegion(0x8100, bytes(middle), source="fixture:middle", writable=True),
            resolver.MemoryRegion(0x8200, bytes(table), source="fixture:table"),
            resolver.MemoryRegion(0x9000, b"\x70\x47", source="fixture:text", executable=True),
        ],
        symbols=[
            resolver.MemorySymbol(0x8000, 4, "STT_OBJECT", "", "elf:fixture", ".objects", True),
            resolver.MemorySymbol(0x8100, 8, "STT_OBJECT", "", "elf:fixture", ".objects", True),
            resolver.MemorySymbol(0x8200, 4, "STT_OBJECT", "", "elf:fixture", ".tables"),
            resolver.MemorySymbol(0x9001, 2, "STT_FUNC", "", "elf:fixture", ".text", False, True),
        ],
        machine="EM_ARM",
    )

    accessor_param = formal(0x7000, 0)
    first_address = node("value:accessor:first-address")
    first_pointer = node("value:accessor:first-pointer")
    second_address = node("value:accessor:second-address")
    returned_table = node("value:accessor:table")
    accessor_ops = [
        op("site:00007000:00007000:1", "PTRSUB", first_address, accessor_param, node("const:zero:a", constant=True)),
        op("site:00007000:00007002:2", "LOAD", first_pointer, SPACE, first_address),
        op("site:00007000:00007004:3", "PTRSUB", second_address, first_pointer, node("const:four", offset=4, constant=True)),
        op("site:00007000:00007006:4", "LOAD", returned_table, SPACE, second_address),
        op("site:00007000:00007008:5", "RETURN", None, node("const:return", constant=True), returned_table),
    ]
    caller_param0 = formal(0x7100, 0)
    caller_param1 = formal(0x7100, 1)
    call_result = node("value:caller:table")
    accessor_call = op(
        "site:00007100:00007102:1",
        "CALL",
        call_result,
        node("function:accessor", offset=0x7000, address=True),
        caller_param0,
    )
    accessor_call["call"] = {
        "kind": "CALL",
        "target_function_id": "fn:00007000",
        "target_function": "accessor",
    }
    slot_address = node("value:caller:slot-address")
    target_pointer = node("value:caller:target")
    dispatch = op(
        "site:00007100:00007108:4",
        "CALLIND",
        node("value:caller:return"),
        target_pointer,
        caller_param0,
        caller_param1,
    )
    dispatch["call"] = {"kind": "CALLIND", "target_function_id": ""}
    caller_ops = [
        accessor_call,
        op("site:00007100:00007104:2", "PTRSUB", slot_address, call_result, node("const:zero:b", constant=True)),
        op("site:00007100:00007106:3", "LOAD", target_pointer, SPACE, slot_address),
        dispatch,
    ]
    facts = {
        "functions": [
            {**function(0x7000, "accessor", accessor_ops), "parameters": [{"index": 0, "object_id": "param:00007000:0"}]},
            {**function(0x7100, "caller", caller_ops), "parameters": [{"index": 0, "object_id": "param:00007100:0"}, {"index": 1, "object_id": "param:00007100:1"}]},
            {**function(0x9000, "target"), "parameters": [{"index": 0, "object_id": "param:00009000:0"}, {"index": 1, "object_id": "param:00009000:1"}]},
        ]
    }

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    row = next(item for item in result["resolved"] if item["callsite"]["site_id"] == dispatch["site_id"])
    assert row["resolution_kind"] == "initialized_object_domain_return_table"
    assert row["target"]["function_id"] == "fn:00009000"
    assert row["formal_identity_bindings"] == [
        {"caller_parameter_slot": 0, "target_parameter_slot": 0},
        {"caller_parameter_slot": 1, "target_parameter_slot": 1},
    ]


def test_resolves_direct_constant_table_slot():
    rodata = bytearray(0x20)
    rodata[8:12] = word(0x9001)
    memory = resolver.InitializedMemory.from_regions(
        [resolver.MemoryRegion(0x7000, bytes(rodata), source="fixture:table")]
    )
    slot_address = node("value:slot_address")
    target = node("value:target")
    add = op(
        "site:00001200:00001204:1",
        "INT_ADD",
        slot_address,
        node("const:table", offset=0x7000, constant=True),
        node("const:slot", offset=8, constant=True),
    )
    load = op("site:00001200:00001208:2", "LOAD", target, SPACE, slot_address)
    dispatch = op(
        "site:00001200:0000120c:3",
        "CALLIND",
        node("value:return"),
        target,
    )
    dispatch["call"] = {"kind": "CALLIND"}
    facts = {
        "functions": [
            function(0x1200, "dispatch", [add, load, dispatch]),
            function(0x9000, "operation"),
        ]
    }
    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)
    assert result["counts"]["resolved"] == 1
    row = result["resolved"][0]
    assert row["resolution_kind"] == "constant_api_table"
    assert row["slot"]["entry_address"] == "0x7008"
    assert row["target"]["function_id"] == "fn:00009000"


def elf_symbol(address, size, kind, name, *, writable=False):
    return resolver.MemorySymbol(
        address,
        size,
        kind,
        name=name,
        source="elf:fixture:.symtab",
        section=".fixture",
        writable=writable,
    )


def add_register_parameters(row, count, *, type_prefix):
    row["parameters"] = [
        {
            "index": slot,
            "name": f"p{slot}",
            "data_type": f"{type_prefix}{slot} *",
            "storage": f"r{slot}:4",
            "object_id": f"param:{row['entry'][2:]}:{slot}",
        }
        for slot in range(count)
    ]
    types = ", ".join(parameter["data_type"] for parameter in row["parameters"])
    row["signature"] = f"int __stdcall {row['name']}({types})"


def formal_dispatch_program(
    *,
    api_offset=8,
    slot_offset=0,
    parameter_count=1,
    actual_slots=(),
    call_address=0x1210,
    matching_signatures=False,
):
    parameters = []
    for slot in range(parameter_count):
        parameter = node(f"value:wrapper:p{slot}", name=f"p{slot}")
        parameter.update(
            {
                "object_id": f"param:00001200:{slot}",
                "parameter_slot": slot,
                "is_parameter": True,
                "is_input": True,
            }
        )
        parameters.append(parameter)

    api_address = node("value:wrapper:api-address")
    api = node("value:wrapper:api")
    target_address = api
    target_value = node("value:wrapper:target")
    operations = [
        op(
            "site:00001200:00001202:1",
            "PTRSUB",
            api_address,
            parameters[0],
            node("const:api-offset", offset=api_offset, constant=True),
        ),
        op("site:00001200:00001202:2", "LOAD", api, SPACE, api_address),
    ]
    if slot_offset:
        target_address = node("value:wrapper:slot-address")
        operations.append(
            op(
                "site:00001200:00001204:3",
                "INT_ADD",
                target_address,
                api,
                node("const:slot-offset", offset=slot_offset, constant=True),
            )
        )
    operations.append(
        op("site:00001200:00001204:4", "LOAD", target_value, SPACE, target_address)
    )
    dispatch = op(
        f"site:00001200:{call_address:08x}:5",
        "CALLIND",
        node("value:wrapper:return"),
        target_value,
        *(parameters[slot] for slot in actual_slots),
    )
    dispatch["call"] = {"kind": "CALLIND"}
    operations.append(dispatch)

    wrapper = function(0x1200, "dispatch_wrapper", operations)
    target = function(0x9000, "slot_target")
    add_register_parameters(wrapper, parameter_count, type_prefix="caller_type_")
    add_register_parameters(
        target,
        len(actual_slots) if actual_slots else parameter_count,
        type_prefix="caller_type_" if matching_signatures else "target_type_",
    )
    if matching_signatures:
        target["signature"] = wrapper["signature"].replace(wrapper["name"], target["name"])
    return {
        "language_id": "ARM:LE:32:v8",
        "functions": [wrapper, target],
        "symbols": [],
    }


def formal_dispatch_memory(
    *,
    api_offset=8,
    slot_offset=0,
    table_size=8,
    machine_wrapper=False,
    extra_target_reference=False,
):
    table = bytearray(max(table_size, slot_offset + 4))
    table[slot_offset : slot_offset + 4] = word(0x9001)
    device = bytearray(16)
    device[api_offset : api_offset + 4] = word(0x7000)
    regions = [
        resolver.MemoryRegion(0x7000, bytes(table), source="elf:fixture:api"),
        resolver.MemoryRegion(
            0x8000,
            bytes(device),
            source="elf:fixture:devices",
            writable=True,
        ),
        resolver.MemoryRegion(
            0x9000,
            bytes.fromhex("7047"),
            source="elf:fixture:text",
            executable=True,
        ),
    ]
    symbols = [
        elf_symbol(0x7000, table_size, "STT_OBJECT", "api_object"),
        elf_symbol(0x8000, 16, "STT_OBJECT", "receiver_object"),
        elf_symbol(0x9001, 2, "STT_FUNC", "slot_function"),
    ]
    if machine_wrapper:
        regions.append(
            resolver.MemoryRegion(
                0x1200,
                bytes.fromhex("10b484682468a44610bc6047"),
                source="elf:fixture:text",
                executable=True,
            )
        )
        symbols.append(elf_symbol(0x1201, 12, "STT_FUNC", "dispatch_function"))
    if extra_target_reference:
        regions.append(
            resolver.MemoryRegion(
                0x7100,
                word(0x9001),
                source="elf:fixture:second-api",
            )
        )
        symbols.append(elf_symbol(0x7100, 4, "STT_OBJECT", "second_api_object"))
    return resolver.InitializedMemory.from_regions(
        regions,
        symbols=symbols,
        machine="EM_ARM" if machine_wrapper else "",
    )


def test_signature_match_without_actual_formal_identity_stays_unresolved():
    facts = formal_dispatch_program(actual_slots=(), matching_signatures=True)
    memory = formal_dispatch_memory()

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["counts"] == {"callind": 1, "resolved": 0, "ambiguous": 0, "unresolved": 1}
    assert result["unresolved"][0]["reason"] == "actual_formal_identity_not_proven"


def test_adjacent_elf_object_cannot_supply_an_out_of_bounds_api_slot():
    facts = formal_dispatch_program(
        api_offset=4,
        slot_offset=8,
        actual_slots=(0,),
        matching_signatures=True,
    )
    memory = formal_dispatch_memory(api_offset=4, slot_offset=8, table_size=8)

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["counts"] == {"callind": 1, "resolved": 0, "ambiguous": 0, "unresolved": 1}
    assert result["unresolved"][0]["reason"] == "elf_device_api_slot_target_not_proven"


def test_resolves_high_pcode_actual_formal_identity_without_signature_matching():
    facts = formal_dispatch_program(parameter_count=2, actual_slots=(0, 1))
    memory = formal_dispatch_memory()

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["counts"] == {"callind": 1, "resolved": 1, "ambiguous": 0, "unresolved": 0}
    row = result["resolved"][0]
    assert row["resolution_kind"] == "elf_formal_device_api_table"
    assert row["formal_identity_bindings"] == [
        {"caller_parameter_slot": 0, "target_parameter_slot": 0},
        {"caller_parameter_slot": 1, "target_parameter_slot": 1},
    ]
    assert {item["kind"] for item in row["evidence"]} >= {
        "elf_device_object_api_table_slot",
        "high_pcode_actual_formal_identity",
    }


def test_resolves_register_preserving_tail_dispatch_with_machine_identity():
    facts = formal_dispatch_program(
        parameter_count=4,
        actual_slots=(),
        call_address=0x120A,
    )
    memory = formal_dispatch_memory(machine_wrapper=True)

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["counts"] == {"callind": 1, "resolved": 1, "ambiguous": 0, "unresolved": 0}
    row = result["resolved"][0]
    assert row["target"]["function_id"] == "fn:00009000"
    assert row["proof_scope"] == "all_elf_function_pointer_references"
    assert row["binding_scope"] == "target_function"
    assert row["target_formal_constant_bindings"] == [
        {
            "target_parameter_slot": 0,
            "value": "0x8000",
            "source": "all_elf_target_references_same_receiver_configuration",
            "binding_scope": "target_function",
        }
    ]
    assert "machine_abi_actual_formal_identity" in {
        item["kind"] for item in row["evidence"]
    }


def test_formal_dispatch_uses_fixed_arity_abi_to_reject_unrelated_tables():
    facts = formal_dispatch_program(
        parameter_count=4,
        actual_slots=(),
        call_address=0x120A,
    )
    unrelated = function(0xA000, "unrelated_slot_target")
    add_register_parameters(unrelated, 2, type_prefix="other_type_")
    facts["functions"].append(unrelated)

    memory = formal_dispatch_memory(machine_wrapper=True)
    memory.regions.extend(
        [
            resolver.MemoryRegion(
                0x7100, word(0xA001), source="elf:fixture:other-api"
            ),
            resolver.MemoryRegion(
                0x8100,
                word(0) + word(0) + word(0x7100) + word(0),
                source="elf:fixture:other-device",
                writable=True,
            ),
            resolver.MemoryRegion(
                0xA000,
                bytes.fromhex("7047"),
                source="elf:fixture:text",
                executable=True,
            ),
        ]
    )
    memory.symbols.extend(
        [
            resolver.MemorySymbol(
                0x7100, 4, "STT_OBJECT", name="other_api", source="elf:.symtab"
            ),
            resolver.MemorySymbol(
                0x8100, 16, "STT_OBJECT", name="other_receiver", source="elf:.symtab"
            ),
            resolver.MemorySymbol(
                0xA001,
                2,
                "STT_FUNC",
                name="unrelated_slot_target",
                source="elf:.symtab",
                executable=True,
            ),
        ]
    )

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["counts"] == {
        "callind": 1, "resolved": 1, "ambiguous": 0, "unresolved": 0,
    }
    row = result["resolved"][0]
    assert row["target"]["function_id"] == "fn:00009000"
    assert "fixed_arity_actual_formal_abi_compatibility" in {
        item["kind"] for item in row["evidence"]
    }


def test_extra_elf_target_reference_limits_binding_to_context():
    facts = formal_dispatch_program(actual_slots=(0,))
    memory = formal_dispatch_memory(extra_target_reference=True)

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["counts"] == {"callind": 1, "resolved": 1, "ambiguous": 0, "unresolved": 0}
    row = result["resolved"][0]
    assert row["proof_scope"] == "callsite_context"
    assert row["binding_scope"] == "context_only"
    assert "target_formal_constant_bindings" not in row
    scope = next(item for item in row["evidence"] if item["kind"] == "elf_target_reference_scope")
    assert scope["target_references"] == ["0x7000", "0x7100"]
    assert scope["explained_target_references"] == ["0x7000"]


def test_writable_receiver_object_is_not_immutable_dispatch_evidence():
    facts = formal_dispatch_program(actual_slots=(0,))
    memory = formal_dispatch_memory()
    memory.symbols = [
        resolver.MemorySymbol(
            symbol.address,
            symbol.size,
            symbol.kind,
            name=symbol.name,
            source=symbol.source,
            section=symbol.section,
            writable=(symbol.name == "receiver_object"),
            executable=symbol.executable,
        )
        for symbol in memory.symbols
    ]

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["counts"] == {
        "callind": 1, "resolved": 0, "ambiguous": 0, "unresolved": 1,
    }
    assert result["unresolved"][0]["reason"] == "elf_device_api_slot_target_not_proven"


def direct_return_dispatch_program(
    *,
    return_addresses=(0x7000,),
    receiver_access=False,
    renamed=False,
):
    getter_result = node("value:caller:getter-result")
    getter_call = op(
        "site:00001200:00001204:1",
        "CALL",
        getter_result,
        node("function:getter", offset=0x1100, address=True),
    )
    getter_call["call"] = {
        "kind": "CALL",
        "target_function_id": "fn:00001100",
        "target_function": "f_return_root" if renamed else "get_dispatch_root",
    }

    operations = [getter_call]
    table_value = getter_result
    if receiver_access:
        table_field_address = node("value:caller:table-field-address")
        table_value = node("value:caller:table")
        operations.extend(
            [
                op(
                    "site:00001200:00001208:2",
                    "PTRSUB",
                    table_field_address,
                    getter_result,
                    node("const:table-field", offset=4, constant=True),
                ),
                op(
                    "site:00001200:0000120c:3",
                    "LOAD",
                    table_value,
                    SPACE,
                    table_field_address,
                ),
            ]
        )

    slot_address = node("value:caller:slot-address")
    target = node("value:caller:target")
    operations.extend(
        [
            op(
                "site:00001200:00001210:4",
                "INT_ADD",
                slot_address,
                table_value,
                node("const:slot", offset=8, constant=True),
            ),
            op("site:00001200:00001214:5", "LOAD", target, SPACE, slot_address),
        ]
    )
    dispatch = op(
        "site:00001200:00001218:6",
        "CALLIND",
        node("value:caller:return"),
        target,
    )
    dispatch["call"] = {"kind": "CALLIND"}
    operations.append(dispatch)

    return_ops = []
    for index, address in enumerate(return_addresses):
        returned = node(
            f"const:getter:return:{index}",
            offset=address,
            constant=True,
            address=True,
        )
        return_ops.append(
            op(f"site:00001100:000011{index * 2 + 4:02x}:{index}", "RETURN", None, SPACE, returned)
        )

    return {
        "functions": [
            function(0x1100, "f_a91" if renamed else "get_dispatch_root", return_ops),
            function(0x1200, "f_24b" if renamed else "dispatch_through_getter", operations),
            function(0x9000, "f_771" if renamed else "first_operation"),
            function(0xA000, "f_88c" if renamed else "second_operation"),
        ],
        "symbols": [],
    }


def direct_return_dispatch_memory(*, receiver_access=False, ambiguous=False, executable=True):
    table_one = bytearray(12)
    table_one[8:12] = word(0x9001)
    table_two = bytearray(12)
    table_two[8:12] = word(0xA001)
    regions = [
        resolver.MemoryRegion(0x7000, bytes(table_one), source="elf:fixture:table-one"),
        resolver.MemoryRegion(
            0x9000,
            bytes.fromhex("7047"),
            source="elf:fixture:text-one",
            executable=executable,
        ),
    ]
    symbols = [
        elf_symbol(0x7000, 12, "STT_OBJECT", "obj_q1"),
        elf_symbol(0x9001, 2, "STT_FUNC", "fn_q1"),
    ]
    if receiver_access:
        receiver = bytearray(8)
        receiver[4:8] = word(0x7000)
        regions.append(
            resolver.MemoryRegion(0x8000, bytes(receiver), source="elf:fixture:receiver")
        )
        symbols.append(elf_symbol(0x8000, 8, "STT_OBJECT", "obj_rx"))
    if ambiguous:
        regions.extend(
            [
                resolver.MemoryRegion(0x7100, bytes(table_two), source="elf:fixture:table-two"),
                resolver.MemoryRegion(
                    0xA000,
                    bytes.fromhex("7047"),
                    source="elf:fixture:text-two",
                    executable=True,
                ),
            ]
        )
        symbols.extend(
            [
                elf_symbol(0x7100, 12, "STT_OBJECT", "obj_q2"),
                elf_symbol(0xA001, 2, "STT_FUNC", "fn_q2"),
            ]
        )
    return resolver.InitializedMemory.from_regions(regions, symbols=symbols)


def test_resolves_initialized_table_reached_through_direct_callee_return():
    result = resolver.resolve_device_dispatches(
        direct_return_dispatch_program(),
        initialized_memory=direct_return_dispatch_memory(),
    )

    assert result["counts"] == {"callind": 1, "resolved": 1, "ambiguous": 0, "unresolved": 0}
    row = result["resolved"][0]
    assert row["resolution_kind"] == "direct_callee_return_initialized_table"
    assert row["target"]["function_id"] == "fn:00009000"
    assert row["table"]["address"] == "0x7000"
    assert row["slot"]["offset"] == 8
    proof = next(
        item
        for item in row["evidence"]
        if item["kind"] == "high_pcode_direct_callee_return_access_path"
    )
    assert proof["return_edges"][0]["callee_function_id"] == "fn:00001100"


def test_resolves_table_loaded_from_receiver_returned_by_direct_callee():
    result = resolver.resolve_device_dispatches(
        direct_return_dispatch_program(return_addresses=(0x8000,), receiver_access=True),
        initialized_memory=direct_return_dispatch_memory(receiver_access=True),
    )

    assert result["counts"]["resolved"] == 1
    row = result["resolved"][0]
    assert row["resolution_kind"] == "direct_callee_return_initialized_table"
    assert row["table"]["address"] == "0x7000"
    assert row["slot"]["entry_address"] == "0x7008"


def test_direct_return_dispatch_is_independent_of_function_and_symbol_names():
    facts = direct_return_dispatch_program(renamed=True)
    memory = direct_return_dispatch_memory()
    memory.symbols = [
        resolver.MemorySymbol(
            symbol.address,
            symbol.size,
            symbol.kind,
            name=f"renamed_{index}",
            source=symbol.source,
            section=symbol.section,
            writable=symbol.writable,
            executable=symbol.executable,
        )
        for index, symbol in enumerate(memory.symbols)
    ]

    result = resolver.resolve_device_dispatches(facts, initialized_memory=memory)

    assert result["counts"]["resolved"] == 1
    assert result["resolved"][0]["target"]["function_id"] == "fn:00009000"


def test_multiple_direct_return_tables_remain_ambiguous():
    result = resolver.resolve_device_dispatches(
        direct_return_dispatch_program(return_addresses=(0x7000, 0x7100)),
        initialized_memory=direct_return_dispatch_memory(ambiguous=True),
    )

    assert result["counts"] == {"callind": 1, "resolved": 0, "ambiguous": 1, "unresolved": 0}
    row = result["ambiguous"][0]
    assert row["reason"] == "multiple_initialized_return_access_candidates"
    assert {candidate["target"]["function_id"] for candidate in row["candidates"]} == {
        "fn:00009000",
        "fn:0000a000",
    }


def test_direct_return_slot_with_non_executable_target_stays_unresolved():
    result = resolver.resolve_device_dispatches(
        direct_return_dispatch_program(),
        initialized_memory=direct_return_dispatch_memory(executable=False),
    )

    assert result["counts"] == {"callind": 1, "resolved": 0, "ambiguous": 0, "unresolved": 1}
    assert result["unresolved"][0]["reason"] == "initialized_return_access_target_not_uniquely_proven"
