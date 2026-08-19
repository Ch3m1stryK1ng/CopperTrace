#!/usr/bin/env python3
"""Export decompiler-neutral High P-code facts for Source Miner.

This script runs in a normal CPython process through PyGhidra.  It deliberately
does not classify sources.  It gives later miners stable instruction/op IDs,
stable storage-object IDs, High P-code def-use edges, calls, symbols, memory
blocks, and decompiled C evidence.

Example:

  GHIDRA_INSTALL_DIR=/opt/ghidra \
    python ghidra_export_source_facts.py firmware.elf --out program_facts.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "ct-mini-ghidra-high-pcode-v5-static-objects"
SCHEMA_CAPABILITIES = {
    "high_pcode": True,
    "ssa_def_use": True,
    "basic_blocks": True,
    "cfg_edges": True,
    "typed_branch_edges": True,
    "pcode_block_binding": True,
    "static_capacity_objects": True,
}


def schema_metadata() -> dict[str, Any]:
    """Return a stable marker for the ProgramFacts contract.

    The fingerprint is intentionally derived from the schema version and
    declared capabilities rather than the exporter implementation. Consumers
    can reject old flat High P-code caches without coupling to source hashes.
    """

    material = json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "capabilities": SCHEMA_CAPABILITIES,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return {
        "schema_version": SCHEMA_VERSION,
        "schema_fingerprint": hashlib.sha256(material).hexdigest(),
        "capabilities": dict(SCHEMA_CAPABILITIES),
    }


SCHEMA_FINGERPRINT = schema_metadata()["schema_fingerprint"]


def clean(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def hex_address(value: Any) -> str:
    try:
        return f"0x{int(value):x}"
    except Exception:
        try:
            return f"0x{int(value.getOffset()):x}"
        except Exception:
            return ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def java_iter(value: Any) -> Iterable[Any]:
    iterator = value.iterator() if hasattr(value, "iterator") else value
    if hasattr(iterator, "hasNext"):
        while iterator.hasNext():
            yield iterator.next()
        return
    for item in iterator:
        yield item


def safe(callable_, default: Any = None) -> Any:
    try:
        return callable_()
    except Exception:
        return default


def int_value(value: Any, default: int = -1) -> int:
    try:
        return int(value)
    except Exception:
        return default


def ordered_unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def address_space_name(varnode: Any) -> str:
    address = safe(varnode.getAddress)
    space = safe(address.getAddressSpace) if address is not None else None
    return clean(safe(space.getName, "")) if space is not None else ""


def seq_fields(op: Any) -> tuple[int, int]:
    seq = safe(op.getSeqnum)
    target = safe(seq.getTarget) if seq is not None else None
    target_offset = int(safe(target.getOffset, -1)) if target is not None else -1
    order = int(safe(seq.getTime, 0)) if seq is not None else 0
    return target_offset, order


def site_id(function_entry: int, op: Any) -> str:
    target, order = seq_fields(op)
    if target < 0:
        target = function_entry
    return f"site:{function_entry:08x}:{target:08x}:{order}"


def high_name(varnode: Any) -> str:
    high = safe(varnode.getHigh)
    if high is None:
        return ""
    symbol = safe(high.getSymbol)
    name = clean(safe(symbol.getName, "")) if symbol is not None else ""
    return name or clean(safe(high.getName, ""))


def high_data_type(varnode: Any) -> str:
    """Return Ghidra's recovered HighVariable type without interpreting it."""

    high = safe(varnode.getHigh)
    if high is None:
        return ""
    return clean(safe(high.getDataType, ""))


def high_metadata(varnode: Any) -> dict[str, Any]:
    high = safe(varnode.getHigh)
    symbol = safe(high.getSymbol) if high is not None else None
    if symbol is None:
        return {
            "high_name": high_name(varnode),
            "high_data_type": high_data_type(varnode),
            "is_parameter": False,
            "parameter_slot": None,
        }
    is_parameter = bool(safe(symbol.isParameter, False))
    slot = safe(symbol.getCategoryIndex) if is_parameter else None
    return {
        "high_name": clean(safe(symbol.getName, "")) or high_name(varnode),
        "high_data_type": high_data_type(varnode),
        "is_parameter": is_parameter,
        "parameter_slot": int(slot) if isinstance(slot, (int, float)) else None,
    }


def _data_type_extent(data_type: Any) -> int:
    return int_value(safe(data_type.getLength), -1) if data_type is not None else -1


def _array_element_count(data_type: Any) -> int:
    getter = getattr(data_type, "getNumElements", None) if data_type is not None else None
    return int_value(safe(getter), -1) if getter is not None else -1


def high_stack_array_objects(function_entry: int, high: Any) -> list[dict[str, Any]]:
    """Export exact stack-array extents recovered by the decompiler.

    A High P-code varnode width is only an access width.  Capacity evidence is
    taken from the HighSymbol array DataType and its single stack storage.
    """

    symbol_map = safe(high.getLocalSymbolMap) if high is not None else None
    iterator = safe(symbol_map.getSymbols) if symbol_map is not None else None
    if iterator is None:
        return []
    rows: list[dict[str, Any]] = []
    for symbol in java_iter(iterator):
        if bool(safe(symbol.isParameter, False)) or bool(safe(symbol.isGlobal, False)):
            continue
        data_type = safe(symbol.getDataType)
        elements = _array_element_count(data_type)
        extent = _data_type_extent(data_type)
        if elements <= 0 or extent <= 0:
            continue
        storage = safe(symbol.getStorage)
        if storage is None or not bool(safe(storage.isStackStorage, False)):
            continue
        if int_value(safe(storage.getVarnodeCount), 0) != 1:
            continue
        stack_offset = int_value(safe(storage.getStackOffset))
        rows.append({
            "object_id": f"stack:{function_entry:08x}:{stack_offset:x}:{extent}",
            "kind": "STACK_ARRAY",
            "function_id": f"fn:{function_entry:08x}",
            "name": clean(safe(symbol.getName, "")),
            "storage_space": "stack",
            "base_offset": stack_offset,
            "extent": extent,
            "element_count": elements,
            "data_type": clean(data_type),
            "writable": True,
            "extent_evidence": "ghidra_high_symbol_array_datatype",
        })
    return rows


def object_id(function_entry: int, varnode: Any) -> str:
    """Return storage identity, independent of an SSA definition."""

    space = address_space_name(varnode).lower() or "unknown"
    offset = int(safe(varnode.getOffset, 0) or 0)
    size = int(safe(varnode.getSize, 0) or 0)
    if bool(safe(varnode.isConstant, False)):
        return f"const:{offset:x}:{size}"
    if space in {"ram", "mem", "memory"}:
        return f"global:{offset:08x}:{size}"
    if space == "stack":
        return f"stack:{function_entry:08x}:{offset:x}:{size}"
    if bool(safe(varnode.isRegister, False)) or space == "register":
        return f"reg:{function_entry:08x}:{offset:x}:{size}"
    if bool(safe(varnode.isUnique, False)) or space == "unique":
        return f"unique:{function_entry:08x}:{offset:x}:{size}"
    return f"var:{function_entry:08x}:{space}:{offset:x}:{size}"


def value_id(function_entry: int, varnode: Any, *, object_identity: str) -> str:
    """Return the identity of one High P-code value/definition.

    `object_id` answers where data is stored. `value_id` answers which SSA
    value is flowing through a P-code edge. Keeping them separate prevents a
    later definition of the same parameter/stack slot from overwriting an
    earlier definition in the def-use index.
    """

    if bool(safe(varnode.isConstant, False)):
        return object_identity
    defining = safe(varnode.getDef)
    def_site = site_id(function_entry, defining) if defining is not None else "input"
    unique = safe(varnode.getUniqueId)
    unique_suffix = f":{int(unique)}" if isinstance(unique, (int, float)) else ""
    return f"value:{function_entry:08x}:{object_identity}:{def_site}{unique_suffix}"


def varnode_record(function_entry: int, varnode: Any) -> dict[str, Any]:
    defining = safe(varnode.getDef)
    def_site = site_id(function_entry, defining) if defining is not None else ""
    descendants: list[str] = []
    try:
        iterator = varnode.getDescendants()
        while iterator.hasNext():
            descendants.append(site_id(function_entry, iterator.next()))
    except Exception:
        pass
    address = safe(varnode.getAddress)
    metadata = high_metadata(varnode)
    oid = object_id(function_entry, varnode)
    if metadata["is_parameter"] and metadata["parameter_slot"] is not None:
        oid = f"param:{function_entry:08x}:{metadata['parameter_slot']}"
    return {
        "object_id": oid,
        "value_id": value_id(function_entry, varnode, object_identity=oid),
        "space": address_space_name(varnode),
        "offset": hex_address(safe(varnode.getOffset, 0)),
        "size": int(safe(varnode.getSize, 0) or 0),
        "address": clean(address),
        **metadata,
        "is_constant": bool(safe(varnode.isConstant, False)),
        "is_address": bool(safe(varnode.isAddress, False)),
        "is_register": bool(safe(varnode.isRegister, False)),
        "is_unique": bool(safe(varnode.isUnique, False)),
        "is_input": bool(safe(varnode.isInput, False)),
        "def_site_id": def_site,
        "use_site_ids": sorted(set(descendants)),
    }


def function_name_at(program: Any, address: Any) -> str:
    function = safe(lambda: program.getFunctionManager().getFunctionAt(address))
    return clean(safe(function.getName, "")) if function is not None else ""


def function_id_at(program: Any, address: Any) -> str:
    function = safe(lambda: program.getFunctionManager().getFunctionAt(address))
    if function is None:
        return ""
    entry = int(function.getEntryPoint().getOffset())
    return f"fn:{entry:08x}"


def pcode_record(
    program: Any,
    function_entry: int,
    op: Any,
    *,
    block_id: str,
) -> dict[str, Any]:
    mnemonic = clean(safe(op.getMnemonic, ""))
    inputs = [varnode_record(function_entry, op.getInput(i)) for i in range(int(op.getNumInputs()))]
    output = safe(op.getOutput)
    target, order = seq_fields(op)
    row: dict[str, Any] = {
        "site_id": site_id(function_entry, op),
        "instruction_address": f"0x{target:x}" if target >= 0 else "",
        "op_order": order,
        "opcode": int(safe(op.getOpcode, -1)),
        "mnemonic": mnemonic,
        "block_id": block_id,
        "output": varnode_record(function_entry, output) if output is not None else None,
        "inputs": inputs,
    }
    if mnemonic in {"CALL", "CALLIND", "CALLOTHER"}:
        target_address = safe(lambda: op.getInput(0).getAddress()) if inputs else None
        row["call"] = {
            "kind": mnemonic,
            "target_address": clean(target_address),
            "target_function": function_name_at(program, target_address) if mnemonic == "CALL" else "",
            "target_function_id": function_id_at(program, target_address) if mnemonic == "CALL" else "",
            "argument_object_ids": [item["object_id"] for item in inputs[1:]],
            "argument_value_ids": [item["value_id"] for item in inputs[1:]],
        }
    return row


def basic_block_id(function_entry: int, block_index: int | str) -> str:
    return f"block:{function_entry:08x}:{block_index}"


def normalize_cfg_records(
    function_entry: int,
    raw_blocks: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    """Normalize Ghidra block facts without inferring missing control-flow.

    Every predecessor/successor/branch relation in the result must be present
    in the corresponding raw record obtained from Ghidra. In particular, this
    helper does not manufacture a predecessor merely because the reverse
    successor relation was observed.
    """

    rows = [dict(row) for row in raw_blocks]
    rows.sort(key=lambda row: (int_value(row.get("index")), clean(row.get("start"))))
    known_indices = {
        int_value(row.get("index"))
        for row in rows
        if int_value(row.get("index")) >= 0
    }

    blocks: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    unresolved: set[str] = set()
    seen_edges: set[tuple[str, str, str]] = set()

    def normalized_indices(values: Any) -> list[int]:
        result = {
            int_value(value)
            for value in (values or [])
            if int_value(value) >= 0
        }
        return sorted(result)

    def target_id(index: int) -> str:
        if index not in known_indices:
            unresolved.add(basic_block_id(function_entry, index))
        return basic_block_id(function_entry, index)

    def add_edge(source: str, target: str, kind: str) -> None:
        key = (source, target, kind)
        if key in seen_edges:
            return
        seen_edges.add(key)
        edges.append({
            "source_block_id": source,
            "target_block_id": target,
            "kind": kind,
        })

    for raw in rows:
        index = int_value(raw.get("index"))
        if index < 0:
            continue
        block_id = basic_block_id(function_entry, index)
        predecessor_indices = normalized_indices(raw.get("predecessor_indices"))
        successor_indices = normalized_indices(raw.get("successor_indices"))
        true_index = int_value(raw.get("true_successor_index"))
        false_index = int_value(raw.get("false_successor_index"))
        true_id = target_id(true_index) if true_index >= 0 else ""
        false_id = target_id(false_index) if false_index >= 0 else ""

        blocks.append({
            "block_id": block_id,
            "index": index,
            "start": clean(raw.get("start")),
            "stop": clean(raw.get("stop")),
            "predecessor_block_ids": [target_id(item) for item in predecessor_indices],
            "successor_block_ids": [target_id(item) for item in successor_indices],
            "true_successor_block_id": true_id,
            "false_successor_block_id": false_id,
            "pcode_site_ids": ordered_unique(raw.get("pcode_site_ids") or []),
            "is_synthetic_unmapped": bool(raw.get("is_synthetic_unmapped", False)),
        })

        for successor_index in successor_indices:
            successor = target_id(successor_index)
            kinds = []
            if successor_index == true_index:
                kinds.append("true")
            if successor_index == false_index:
                kinds.append("false")
            if not kinds:
                kinds.append("flow")
            for kind in kinds:
                add_edge(block_id, successor, kind)

        # Preserve explicit branch targets even if a defensive Ghidra API call
        # failed to include them in getOut(). These are not inferred edges:
        # both targets came directly from getTrueOut()/getFalseOut().
        if true_id and true_index not in successor_indices:
            add_edge(block_id, true_id, "true")
        if false_id and false_index not in successor_indices:
            add_edge(block_id, false_id, "false")

    edges.sort(key=lambda row: (
        row["source_block_id"],
        row["target_block_id"],
        row["kind"],
    ))
    return {
        "basic_blocks": blocks,
        "cfg_edges": edges,
        "unresolved_block_references": sorted(unresolved),
    }


def block_index(block: Any) -> int:
    return int_value(safe(block.getIndex))


def referenced_block_indices(block: Any, direction: str) -> list[int]:
    if direction == "in":
        size = int_value(safe(block.getInSize, 0), 0)
        getter = block.getIn
    else:
        size = int_value(safe(block.getOutSize, 0), 0)
        getter = block.getOut
    result = []
    for index in range(max(size, 0)):
        target = safe(lambda index=index: getter(index))
        target_index = block_index(target) if target is not None else -1
        if target_index >= 0:
            result.append(target_index)
    return sorted(set(result))


def branch_successor_index(block: Any, branch: str) -> int:
    getter = getattr(block, "getTrueOut" if branch == "true" else "getFalseOut", None)
    if getter is None:
        return -1
    target = safe(getter)
    return block_index(target) if target is not None else -1


def extract_high_cfg(
    program: Any,
    function_entry: int,
    high: Any,
) -> dict[str, Any]:
    """Export High P-code blocks and bind every operation to one block."""

    raw_blocks: list[dict[str, Any]] = []
    block_by_site: dict[str, str] = {}
    block_order_ops: list[Any] = []
    blocks = list(java_iter(safe(high.getBasicBlocks, [])))

    for block in blocks:
        index = block_index(block)
        if index < 0:
            continue
        block_id = basic_block_id(function_entry, index)
        site_ids = []
        iterator = safe(block.getIterator)
        if iterator is not None:
            for op in java_iter(iterator):
                current_site = site_id(function_entry, op)
                if current_site in block_by_site:
                    continue
                block_by_site[current_site] = block_id
                site_ids.append(current_site)
                block_order_ops.append(op)
        successors = referenced_block_indices(block, "out")
        true_index = branch_successor_index(block, "true") if len(successors) > 1 else -1
        false_index = branch_successor_index(block, "false") if len(successors) > 1 else -1
        raw_blocks.append({
            "index": index,
            "start": hex_address(safe(block.getStart)),
            "stop": hex_address(safe(getattr(block, "getStop", lambda: None))),
            "predecessor_indices": referenced_block_indices(block, "in"),
            "successor_indices": successors,
            "true_successor_index": true_index,
            "false_successor_index": false_index,
            "pcode_site_ids": site_ids,
        })

    flat_ops: list[Any] = []
    iterator = safe(high.getPcodeOps)
    if iterator is not None:
        flat_ops = list(java_iter(iterator))
    ordered_ops = flat_ops or block_order_ops
    unmapped_id = basic_block_id(function_entry, "unmapped")
    unmapped_sites: list[str] = []
    ops: list[dict[str, Any]] = []
    for op in ordered_ops:
        current_site = site_id(function_entry, op)
        assigned_block = block_by_site.get(current_site, unmapped_id)
        if assigned_block == unmapped_id:
            unmapped_sites.append(current_site)
        ops.append(pcode_record(
            program,
            function_entry,
            op,
            block_id=assigned_block,
        ))

    normalized = normalize_cfg_records(function_entry, raw_blocks)
    if unmapped_sites:
        normalized["basic_blocks"].append({
            "block_id": unmapped_id,
            "index": None,
            "start": "",
            "stop": "",
            "predecessor_block_ids": [],
            "successor_block_ids": [],
            "true_successor_block_id": "",
            "false_successor_block_id": "",
            "pcode_site_ids": ordered_unique(unmapped_sites),
            "is_synthetic_unmapped": True,
        })
    if raw_blocks and not unmapped_sites:
        status = "complete"
    elif raw_blocks:
        status = "partial_unmapped"
    elif ops:
        status = "unmapped_fallback"
    else:
        status = "unavailable"
    normalized["cfg_status"] = status
    normalized["pcode_ops"] = ops
    return normalized


def decompile_function(program: Any, function: Any, timeout: int) -> dict[str, Any]:
    from ghidra.app.decompiler import DecompInterface  # type: ignore
    from ghidra.util.task import ConsoleTaskMonitor  # type: ignore

    entry = int(function.getEntryPoint().getOffset())
    interface = DecompInterface()
    interface.toggleCCode(True)
    interface.toggleSyntaxTree(True)
    interface.setSimplificationStyle("decompile")
    interface.openProgram(program)
    try:
        result = interface.decompileFunction(function, timeout, ConsoleTaskMonitor())
        if not bool(result.decompileCompleted()):
            return {
                "function_id": f"fn:{entry:08x}",
                "name": clean(function.getName()),
                "entry": f"0x{entry:x}",
                "error": clean(result.getErrorMessage()),
                "decompiled_c": "",
                "parameters": [],
                "static_objects": [],
                "pcode_ops": [],
                "basic_blocks": [],
                "cfg_edges": [],
                "cfg_status": "decompile_failed",
                "unresolved_block_references": [],
            }
        high = result.getHighFunction()
        ccode = str(result.getDecompiledFunction().getC() or "")
        parameters = []
        for index in range(int(function.getParameterCount())):
            parameter = function.getParameter(index)
            storage = clean(safe(parameter.getVariableStorage, ""))
            parameters.append({
                "index": index,
                "name": clean(parameter.getName()),
                "data_type": clean(parameter.getDataType()),
                "storage": storage,
                "object_id": f"param:{entry:08x}:{index}",
            })
        cfg = {
            "pcode_ops": [],
            "basic_blocks": [],
            "cfg_edges": [],
            "cfg_status": "high_function_unavailable",
            "unresolved_block_references": [],
        }
        if high is not None:
            cfg = extract_high_cfg(program, entry, high)
        static_objects = high_stack_array_objects(entry, high)
        return {
            "function_id": f"fn:{entry:08x}",
            "name": clean(function.getName()),
            "entry": f"0x{entry:x}",
            "end": hex_address(function.getBody().getMaxAddress()),
            "signature": clean(function.getSignature()),
            "is_thunk": bool(function.isThunk()),
            "decompiled_c": ccode,
            "parameters": parameters,
            "static_objects": static_objects,
            "pcode_ops": cfg["pcode_ops"],
            "basic_blocks": cfg["basic_blocks"],
            "cfg_edges": cfg["cfg_edges"],
            "cfg_status": cfg["cfg_status"],
            "unresolved_block_references": cfg["unresolved_block_references"],
        }
    finally:
        interface.dispose()


def memory_blocks(program: Any) -> list[dict[str, Any]]:
    rows = []
    for block in java_iter(program.getMemory().getBlocks()):
        rows.append({
            "name": clean(block.getName()),
            "start": hex_address(block.getStart()),
            "end": hex_address(block.getEnd()),
            "size": int(block.getSize()),
            "read": bool(block.isRead()),
            "write": bool(block.isWrite()),
            "execute": bool(block.isExecute()),
            "initialized": bool(block.isInitialized()),
        })
    return rows


def symbols(program: Any, limit: int) -> list[dict[str, Any]]:
    rows = []
    table = program.getSymbolTable()
    iterator = table.getAllSymbols(True)
    while iterator.hasNext() and (limit <= 0 or len(rows) < limit):
        symbol = iterator.next()
        address = symbol.getAddress()
        rows.append({
            "name": clean(symbol.getName()),
            "address": hex_address(address),
            "type": clean(symbol.getSymbolType()),
            "source": clean(symbol.getSource()),
            "object_id": f"global:{int(address.getOffset()):08x}" if address.isMemoryAddress() else "",
        })
    return rows


def ghidra_global_array_objects(program: Any) -> list[dict[str, Any]]:
    """Export writable global arrays whose DataType has an explicit extent."""

    rows: list[dict[str, Any]] = []
    iterator = safe(lambda: program.getListing().getDefinedData(True))
    if iterator is None:
        return rows
    memory = program.getMemory()
    for data in java_iter(iterator):
        data_type = safe(data.getDataType)
        elements = _array_element_count(data_type)
        extent = int_value(safe(data.getLength), -1)
        address = safe(data.getAddress)
        if elements <= 0 or extent <= 0 or address is None:
            continue
        block = safe(lambda address=address: memory.getBlock(address))
        if block is None or not bool(safe(block.isWrite, False)):
            continue
        base = int_value(safe(address.getOffset))
        rows.append({
            "object_id": f"global:{base:08x}:{extent}",
            "kind": "GLOBAL_ARRAY",
            "function_id": "",
            "name": clean(safe(data.getLabel, "")),
            "storage_space": "ram",
            "base_offset": base,
            "extent": extent,
            "element_count": elements,
            "data_type": clean(data_type),
            "writable": True,
            "section": clean(safe(block.getName, "")),
            "extent_evidence": "ghidra_defined_array_datatype",
        })
    return rows


def elf_global_objects(binary: Path, program: Any) -> list[dict[str, Any]]:
    """Read exact STT_OBJECT extents that Ghidra also maps as writable RAM."""

    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError:
        return []

    rows: list[dict[str, Any]] = []
    memory = program.getMemory()
    address_factory = program.getAddressFactory()
    default_space = address_factory.getDefaultAddressSpace()
    try:
        with binary.open("rb") as stream:
            elf = ELFFile(stream)
            for symbol_table in elf.iter_sections():
                if not isinstance(symbol_table, SymbolTableSection):
                    continue
                for symbol in symbol_table.iter_symbols():
                    entry = symbol.entry
                    if str(entry["st_info"]["type"]) != "STT_OBJECT":
                        continue
                    extent = int(entry["st_size"] or 0)
                    base = int(entry["st_value"] or 0)
                    section_index = entry["st_shndx"]
                    if extent <= 0 or base <= 0 or not isinstance(section_index, int):
                        continue
                    section = elf.get_section(section_index)
                    if section is None:
                        continue
                    writable = bool(int(section["sh_flags"]) & 0x1)
                    if not writable:
                        continue
                    address = safe(lambda base=base: default_space.getAddress(base))
                    block = safe(lambda address=address: memory.getBlock(address))
                    if address is None or block is None or not bool(safe(block.isWrite, False)):
                        continue
                    rows.append({
                        "object_id": f"global:{base:08x}:{extent}",
                        "kind": "GLOBAL_OBJECT",
                        "function_id": "",
                        "name": clean(symbol.name),
                        "storage_space": "ram",
                        "base_offset": base,
                        "extent": extent,
                        "element_count": None,
                        "data_type": "",
                        "writable": True,
                        "section": clean(section.name),
                        "memory_block": clean(safe(block.getName, "")),
                        "symbol_binding": str(entry["st_info"]["bind"]),
                        "extent_evidence": "elf_symbol_st_size_and_writable_memory_block",
                    })
    except (OSError, ValueError, TypeError):
        return []
    return rows


def normalize_static_objects(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate identical facts while preserving conflicting extents."""

    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for raw in rows:
        row = dict(raw)
        extent = int_value(row.get("extent"), -1)
        base = int_value(row.get("base_offset"))
        if extent <= 0 or not bool(row.get("writable", False)):
            continue
        row["extent"] = extent
        row["base_offset"] = base
        key = (
            str(row.get("storage_space", "")),
            str(row.get("function_id", "")),
            base,
            extent,
            str(row.get("extent_evidence", "")),
        )
        existing = unique.get(key)
        if existing is None or (not existing.get("name") and row.get("name")):
            unique[key] = row
    return sorted(
        unique.values(),
        key=lambda row: (
            str(row.get("storage_space", "")),
            str(row.get("function_id", "")),
            int(row.get("base_offset", 0)),
            int(row.get("extent", 0)),
            str(row.get("extent_evidence", "")),
        ),
    )


def architecture_facts(program: Any) -> dict[str, Any]:
    compiler = program.getCompilerSpec()
    stack_pointer = safe(compiler.getStackPointer)
    if stack_pointer is None:
        return {"stack_pointer": {}}
    address = safe(stack_pointer.getAddress)
    return {
        "stack_pointer": {
            "name": clean(safe(stack_pointer.getName, "")),
            "space": clean(safe(lambda: address.getAddressSpace().getName(), "")),
            "offset": int_value(safe(address.getOffset)),
            "size": int_value(safe(stack_pointer.getMinimumByteSize), 0),
        }
    }


def select_functions(program: Any, names: set[str], max_functions: int) -> list[Any]:
    rows = []
    iterator = program.getFunctionManager().getFunctions(True)
    while iterator.hasNext():
        function = iterator.next()
        if names and clean(function.getName()) not in names:
            continue
        rows.append(function)
        if max_functions > 0 and len(rows) >= max_functions:
            break
    return rows


def interrupt_vector_entries(program: Any) -> dict[int, list[dict[str, Any]]]:
    entries: dict[int, list[dict[str, Any]]] = {}
    memory = program.getMemory()
    address_space = program.getAddressFactory().getDefaultAddressSpace()
    for block in java_iter(memory.getBlocks()):
        name = clean(block.getName()).lower()
        if not any(token in name for token in ("vector", "isr", "irq")):
            continue
        size = int(block.getSize())
        if size < 4 or size > 0x10000:
            continue
        start = int(block.getStart().getOffset())
        for byte_offset in range(0, size - 3, 4):
            slot_address = address_space.getAddress(start + byte_offset)
            try:
                pointer = int(memory.getInt(slot_address)) & 0xFFFFFFFF
            except Exception:
                continue
            target_value = pointer & ~1
            try:
                target = address_space.getAddress(target_value)
                function = program.getFunctionManager().getFunctionAt(target)
            except Exception:
                function = None
            if function is None:
                continue
            entry = int(function.getEntryPoint().getOffset())
            entries.setdefault(entry, []).append({
                "block": clean(block.getName()),
                "slot": byte_offset // 4,
                "slot_address": f"0x{start + byte_offset:x}",
                "encoded_target": f"0x{pointer:x}",
            })
    return entries


def export(args: argparse.Namespace) -> dict[str, Any]:
    import pyghidra

    binary = args.binary.resolve()
    project_dir = args.project_dir.resolve()
    if args.fresh and project_dir.exists():
        shutil.rmtree(project_dir)
    project_dir.mkdir(parents=True, exist_ok=True)

    started = time.time()
    # Use PyGhidra directly rather than PyGhidra MCP.  The MCP wrapper returns
    # pseudo-C only and its project analysis callback also builds unrelated
    # Chroma indexes, which is both lossy and expensive for a fact exporter.
    with pyghidra.open_program(
        binary_path=binary,
        project_location=project_dir,
        project_name=args.project_name,
        analyze=True,
    ) as flat_api:
        from ghidra.framework import Application  # type: ignore

        program = flat_api.getCurrentProgram()
        selected = select_functions(program, set(args.function), args.max_functions)
        vector_entries = interrupt_vector_entries(program)
        function_rows = []
        failures = []
        for index, function in enumerate(selected, 1):
            try:
                row = decompile_function(program, function, args.timeout)
                entry = int(function.getEntryPoint().getOffset())
                row["is_interrupt_entry"] = entry in vector_entries
                row["interrupt_vector_slots"] = vector_entries.get(entry, [])
                function_rows.append(row)
            except Exception as exc:
                entry = int(function.getEntryPoint().getOffset())
                failures.append({
                    "function_id": f"fn:{entry:08x}",
                    "name": clean(function.getName()),
                    "entry": f"0x{entry:x}",
                    "error": f"{type(exc).__name__}: {exc}",
                })
            if not args.quiet and index % 50 == 0:
                print(f"exported {index}/{len(selected)} functions", file=sys.stderr, flush=True)
        metadata = schema_metadata()
        static_objects = normalize_static_objects(
            [
                row
                for function in function_rows
                for row in list(function.get("static_objects", []) or [])
            ]
            + ghidra_global_array_objects(program)
            + elf_global_objects(binary, program)
        )
        return {
            **metadata,
            "binary": str(binary),
            "binary_sha256": sha256_file(binary),
            "language_id": clean(program.getLanguageID()),
            "compiler_spec_id": clean(program.getCompilerSpec().getCompilerSpecID()),
            "image_base": hex_address(program.getImageBase()),
            "generated_by": "PyGhidra HighFunction exporter",
            "proof_boundary": "facts_only_no_source_classification",
            "analysis_provenance": {
                "ghidra_version": clean(Application.getApplicationVersion()),
                "analyze_program": True,
                "decompiler_simplification_style": "decompile",
                "emit_c_code": True,
                "emit_syntax_tree": True,
                "emit_high_pcode_basic_blocks": True,
                "program_facts_schema_fingerprint": metadata["schema_fingerprint"],
                "function_timeout_seconds": int(args.timeout),
            },
            "architecture": architecture_facts(program),
            "memory_blocks": memory_blocks(program),
            "symbols": symbols(program, args.symbol_limit),
            "static_objects": static_objects,
            "functions": function_rows,
            "failures": failures,
            "counts": {
                "selected_functions": len(selected),
                "exported_functions": len(function_rows),
                "failed_functions": len(failures),
                "pcode_ops": sum(len(row.get("pcode_ops", [])) for row in function_rows),
                "basic_blocks": sum(len(row.get("basic_blocks", [])) for row in function_rows),
                "cfg_edges": sum(len(row.get("cfg_edges", [])) for row in function_rows),
                "cfg_complete_functions": sum(
                    row.get("cfg_status") == "complete"
                    for row in function_rows
                ),
                "static_capacity_objects": len(static_objects),
            },
            "runtime_seconds": round(time.time() - started, 3),
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--project-dir", default=Path("/tmp/coppertrace_mini_ghidra"), type=Path)
    parser.add_argument("--project-name", default="ct_mini_source_facts")
    parser.add_argument("--function", action="append", default=[], help="Exact function name; repeatable. Default: all")
    parser.add_argument("--function-list-file", default=None, type=Path)
    parser.add_argument("--max-functions", default=0, type=int)
    parser.add_argument("--timeout", default=30, type=int)
    parser.add_argument("--symbol-limit", default=0, type=int)
    parser.add_argument("--fresh", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.function_list_file:
        args.function.extend(
            line.strip()
            for line in args.function_list_file.read_text(errors="replace").splitlines()
            if line.strip()
        )
    facts = export(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(facts, indent=2, sort_keys=False) + "\n")
    print(json.dumps(facts["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
