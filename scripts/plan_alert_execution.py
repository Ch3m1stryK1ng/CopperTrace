#!/usr/bin/env python3
"""Generate and verify one backend-independent Execution Plan."""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any

from validation_common import (
    canonical_address,
    load_json,
    reviewed_validation_entries,
    write_json,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "ct-mini-execution-plan-v1"
MAX_CONCRETE_INPUTS = 8
MAX_VERIFIER_ATTEMPTS = 3
INVALID_EFFECTS = {
    "INVALID_READ",
    "INVALID_WRITE",
    "UNMAPPED_ACCESS",
    "ILLEGAL_INSTRUCTION",
    "CONTROL_FLOW_FAULT",
    "CRASH",
}
PLAN_KEYS = {
    "schema_version",
    "plan_id",
    "alert_id",
    "binary_sha256",
    "source_binding",
    "input_templates",
    "events",
    "ordering_constraints",
    "sink_checkpoint",
    "expected_invalid_effects",
    "replay_count",
    "unresolved_assumptions",
    "evidence_refs",
}
FORBIDDEN_EVIDENCE_MARKERS = (
    "crashing_input",
    "/poc/",
    "bug-details",
    "public_expected",
    "cve_ground_truth",
)


def rows_by_id(document: dict[str, Any], key: str) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("id", "")): row
        for row in document.get(key, []) or []
        if row.get("id")
    }


def load_function_corpus(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_name: dict[str, dict[str, Any]] = {}
    by_address: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            by_name[str(row.get("name", ""))] = row
            address = str(row.get("addr", "")).lower().removeprefix("0x")
            if address:
                by_address[address] = row
    return by_name, by_address


def function_address_from_site(site_id: str) -> str:
    parts = site_id.split(":")
    return parts[1].lower().removeprefix("0x") if len(parts) >= 3 else ""


def compact_function(row: dict[str, Any], max_chars: int = 3600) -> dict[str, Any]:
    body = str(row.get("body", ""))
    if len(body) > max_chars:
        body = body[: max_chars // 2] + "\n/* ... */\n" + body[-max_chars // 2 :]
    return {
        "name": row.get("name", ""),
        "address": canonical_address("0x" + str(row.get("addr", "0"))),
        "body": body,
    }


def compact_source(row: dict[str, Any]) -> dict[str, Any]:
    proof = row.get("proof", {}) or {}
    return {
        "id": row.get("id", ""),
        "label": row.get("label", ""),
        "source_kind": row.get("source_kind", ""),
        "function": row.get("function", ""),
        "callee": row.get("callee", ""),
        "source_site": row.get("source_site", ""),
        "source_buffer": row.get("source_buffer", ""),
        "site_id": row.get("site_id", ""),
        "source_object_id": row.get("source_object_id", ""),
        "source_output": row.get("source_output", {}),
        "proof": {
            "kind": proof.get("kind", ""),
            "register_address": proof.get("register_address", ""),
            "register_role": proof.get("register_role", ""),
            "call_site_id": proof.get("call_site_id", ""),
            "callee_function_id": proof.get("callee_function_id", ""),
            "provenance": proof.get("provenance", []),
        },
        "decision": row.get("decision", ""),
    }


def compact_sink(row: dict[str, Any], selected_sites: set[str]) -> dict[str, Any]:
    return {
        "id": row.get("id", ""),
        "label": row.get("label", ""),
        "sink_kind": row.get("sink_kind", ""),
        "callee": row.get("callee", ""),
        "function": row.get("function", ""),
        "function_id": row.get("function_id", ""),
        "site_id": row.get("site_id", ""),
        "effect_site_id": row.get("effect_site_id", ""),
        "instruction_address": row.get("instruction_address", ""),
        "expr": row.get("expr", ""),
        "roles": row.get("roles", {}),
        "vulnerable_parameter_roles": row.get("vulnerable_parameter_roles", []),
        "vulnerable_parameters": row.get("vulnerable_parameters", []),
        "boundary_callsites": [
            callsite
            for callsite in row.get("boundary_callsites", []) or []
            if str(callsite.get("site_id", "")) in selected_sites
        ],
        "decision": row.get("decision", ""),
        "proof": row.get("proof", {}),
    }


def collect_underlying_source_ids(
    selected_sources: list[dict[str, Any]],
    source_map: dict[str, dict[str, Any]],
) -> list[str]:
    """Resolve deterministic Source provenance without relying on one schema spelling."""
    result: list[str] = []
    queued = list(selected_sources)
    visited: set[str] = set()
    while queued:
        source = queued.pop(0)
        source_id = str(source.get("id", ""))
        if source_id:
            visited.add(source_id)
        for provenance in (source.get("proof", {}) or {}).get("provenance", []) or []:
            referenced = [str(value) for value in provenance.get("underlying_source_ids", []) or []]
            direct = str(provenance.get("source_id", ""))
            if direct:
                referenced.append(direct)
            for referenced_id in referenced:
                if not referenced_id or referenced_id in visited:
                    continue
                referenced_source = source_map.get(referenced_id)
                if not referenced_source:
                    continue
                visited.add(referenced_id)
                result.append(referenced_id)
                queued.append(referenced_source)
    return result


def runtime_hardware_sources(
    source_map: dict[str, dict[str, Any]], allowed_registers: list[str]
) -> list[dict[str, Any]]:
    """Return deterministic MMIO sites that can deliver an allowed register.

    Static provenance remains the authority for Source association. Runtime
    calibration additionally needs every body-proved LOAD-to-buffer site for
    the same receive-data register because one driver contract may select a
    slow or fast implementation at runtime.
    """
    allowed = {canonical_address(value) for value in allowed_registers}
    result: list[dict[str, Any]] = []
    for source in source_map.values():
        proof = source.get("proof", {}) or {}
        register = canonical_address(proof.get("register_address"))
        if (
            source.get("decision") != "ACCEPT_DETERMINISTIC"
            or source.get("label") != "MMIO_READ"
            or register not in allowed
            or not source.get("site_id")
        ):
            continue
        result.append(source)
    return sorted(result, key=lambda row: (str(row.get("site_id", "")), str(row.get("id", ""))))


def _parse_hex_component(value: str) -> int | None:
    try:
        return int(value, 16)
    except (TypeError, ValueError):
        return None


def _object_base_address(object_id: str) -> int | None:
    parts = str(object_id).split(":")
    for index, part in enumerate(parts[:-1]):
        if part in {"global", "symbol", "ram"}:
            value = _parse_hex_component(parts[index + 1])
            if value is not None:
                return value
    return None


def _read_elf_u32(binary: Path, address: int) -> int | None:
    from elftools.elf.elffile import ELFFile

    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            start = int(section["sh_addr"])
            size = int(section["sh_size"])
            if section["sh_type"] == "SHT_NOBITS" or not (
                start <= address < start + size
            ):
                continue
            offset = address - start
            raw = section.data()[offset : offset + 4]
            return struct.unpack("<I", raw)[0] if len(raw) == 4 else None
    return None


def _pcode_index(
    program_facts: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_site: dict[str, dict[str, Any]] = {}
    by_output: dict[str, dict[str, Any]] = {}
    for function in program_facts.get("functions", []) or []:
        for operation in function.get("pcode_ops", []) or []:
            site_id = str(operation.get("site_id", ""))
            if site_id:
                by_site[site_id] = operation
            output = operation.get("output") or {}
            value_id = str(output.get("value_id", ""))
            if value_id:
                by_output[value_id] = operation
    return by_site, by_output


def _constant_value(varnode: dict[str, Any]) -> int | None:
    if not varnode.get("is_constant"):
        return None
    try:
        return int(str(varnode.get("offset", "0")), 0)
    except ValueError:
        return None


def _signed_constant(varnode: dict[str, Any]) -> int | None:
    value = _constant_value(varnode)
    if value is None:
        return None
    bits = int(varnode.get("size", 4)) * 8
    if bits and value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def _stack_pointer_offset(
    value_id: str,
    by_output: dict[str, dict[str, Any]],
    seen: set[str] | None = None,
) -> int | None:
    """Resolve a stack-relative pointer produced by High P-code PTRSUB/INT_ADD."""
    seen = set(seen or ())
    if not value_id or value_id in seen:
        return None
    seen.add(value_id)
    operation = by_output.get(value_id)
    if not operation:
        return None
    inputs = operation.get("inputs", []) or []
    if operation.get("mnemonic") in {"COPY", "CAST", "MULTIEQUAL", "INDIRECT"}:
        offsets = {
            offset
            for node in inputs
            for offset in [
                _stack_pointer_offset(str(node.get("value_id", "")), by_output, seen)
            ]
            if offset is not None
        }
        return next(iter(offsets)) if len(offsets) == 1 else None
    if operation.get("mnemonic") in {"PTRSUB", "INT_ADD"} and len(inputs) >= 2:
        delta = _signed_constant(inputs[-1])
        base = inputs[0]
        if delta is None:
            return None
        try:
            base_offset = int(str(base.get("offset", "-1")), 0)
        except ValueError:
            base_offset = -1
        if base.get("is_register") and base_offset == 0x54:
            return delta
        nested = _stack_pointer_offset(str(base.get("value_id", "")), by_output, seen)
        return nested + delta if nested is not None else None
    return None


def _reachable_memory_nodes(
    value_id: str,
    by_output: dict[str, dict[str, Any]],
    *,
    max_depth: int = 16,
) -> list[dict[str, Any]]:
    """Collect concrete stack/global values in a bounded High P-code def closure."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    worklist = [(value_id, 0)]
    seen: set[str] = set()
    while worklist:
        current, depth = worklist.pop()
        if not current or current in seen or depth > max_depth:
            continue
        seen.add(current)
        operation = by_output.get(current)
        if not operation:
            continue
        for node in [
            operation.get("output") or {},
            *(operation.get("inputs", []) or []),
        ]:
            object_id = str(node.get("object_id", ""))
            if object_id.startswith(("stack:", "global:")):
                rows[(object_id, str(node.get("value_id", "")))] = node
            if not node.get("is_constant"):
                worklist.append((str(node.get("value_id", "")), depth + 1))
    return list(rows.values())


def _affine_deltas_to_value(
    value_id: str,
    target_value_ids: set[str],
    by_output: dict[str, dict[str, Any]],
    *,
    max_depth: int = 16,
) -> set[int]:
    """Recover exact ``value = target + constant`` High P-code relations."""
    worklist = [(value_id, 0, 0)]
    seen: set[tuple[str, int]] = set()
    results: set[int] = set()
    transparent = {
        "COPY",
        "CAST",
        "INT_ZEXT",
        "INT_SEXT",
        "SUBPIECE",
        "INDIRECT",
        "MULTIEQUAL",
    }
    while worklist:
        current, delta, depth = worklist.pop()
        if current in target_value_ids:
            results.add(delta)
            continue
        state = (current, delta)
        if not current or state in seen or depth > max_depth:
            continue
        seen.add(state)
        operation = by_output.get(current)
        if not operation:
            continue
        mnemonic = str(operation.get("mnemonic", ""))
        inputs = operation.get("inputs", []) or []
        if mnemonic in transparent:
            for node in inputs:
                if not node.get("is_constant"):
                    worklist.append(
                        (str(node.get("value_id", "")), delta, depth + 1)
                    )
            continue
        if mnemonic in {"INT_ADD", "PTRSUB"}:
            constants = [
                _signed_constant(node) for node in inputs if node.get("is_constant")
            ]
            variables = [node for node in inputs if not node.get("is_constant")]
            if len(constants) == 1 and len(variables) == 1:
                adjustment = constants[0]
                if adjustment is not None:
                    worklist.append(
                        (
                            str(variables[0].get("value_id", "")),
                            delta + adjustment,
                            depth + 1,
                        )
                    )
    return results


def _source_pointer_offsets(
    value_id: str,
    *,
    source_base: int,
    by_output: dict[str, dict[str, Any]],
    binding_by_value: dict[str, list[dict[str, Any]]],
    binary: Path,
    seen: set[str] | None = None,
) -> set[int]:
    """Resolve exact source-object pointer offsets through High P-code definitions."""
    seen = set(seen or ())
    if not value_id or value_id in seen:
        return set()
    seen.add(value_id)

    offsets: set[int] = set()
    for binding in binding_by_value.get(value_id, []):
        if _object_base_address(str(binding.get("object_id", ""))) != source_base:
            continue
        value_object_id = str(binding.get("value_object_id", ""))
        parts = value_object_id.split(":")
        if parts and parts[0] == "global" and len(parts) >= 2:
            literal_address = _parse_hex_component(parts[1])
            static_pointer = (
                _read_elf_u32(binary, literal_address) if literal_address else None
            )
            if (
                static_pointer is not None
                and source_base <= static_pointer < source_base + 0x10000
            ):
                offsets.add(static_pointer - source_base)

    operation = by_output.get(value_id)
    if not operation:
        return offsets
    mnemonic = str(operation.get("mnemonic", ""))
    inputs = operation.get("inputs", []) or []
    if mnemonic in {"COPY", "CAST", "MULTIEQUAL", "INDIRECT"}:
        for input_node in inputs:
            offsets.update(
                _source_pointer_offsets(
                    str(input_node.get("value_id", "")),
                    source_base=source_base,
                    by_output=by_output,
                    binding_by_value=binding_by_value,
                    binary=binary,
                    seen=seen,
                )
            )
    elif mnemonic in {"PTRADD", "PTRSUB", "INT_ADD"} and inputs:
        base_offsets = _source_pointer_offsets(
            str(inputs[0].get("value_id", "")),
            source_base=source_base,
            by_output=by_output,
            binding_by_value=binding_by_value,
            binary=binary,
            seen=seen,
        )
        delta = 0
        constants = [_constant_value(node) for node in inputs[1:]]
        constants = [value for value in constants if value is not None]
        if mnemonic == "PTRADD" and constants:
            delta = constants[0] * (constants[1] if len(constants) > 1 else 1)
        elif constants:
            delta = constants[0]
        offsets.update(base + delta for base in base_offsets)
    return offsets


def build_payload_layout_facts(
    *,
    chain: dict[str, Any],
    sink: dict[str, Any],
    channel_graph: dict[str, Any],
    program_facts: dict[str, Any],
    binary: Path,
    selected_sites: set[str],
    selected_sources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Derive only exact payload facts already present in P-code/object evidence."""
    source_bases = {
        address
        for source in selected_sources
        for address in [_object_base_address(str(source.get("source_object_id", "")))]
        if address is not None
    }
    if len(source_bases) != 1:
        return []
    source_base = next(iter(source_bases))
    source_object_ids = {
        str(source.get("source_object_id", "")) for source in selected_sources
    }
    selected_function_ids = {
        "fn:" + site_id.split(":")[1]
        for site_id in selected_sites
        if len(site_id.split(":")) >= 3
    }
    by_site, by_output = _pcode_index(program_facts)
    binding_by_value: dict[str, list[dict[str, Any]]] = {}
    for binding in channel_graph.get("value_object_bindings", []) or []:
        binding_by_value.setdefault(str(binding.get("value_id", "")), []).append(
            binding
        )

    facts: list[dict[str, Any]] = []
    relevant_effect_addresses: list[int] = []
    for parameter in chain.get("parameter_results", []) or []:
        if parameter.get("role") != "len":
            continue
        for path_row in parameter.get("paths", []) or []:
            for edge in path_row.get("path", []) or []:
                if edge.get("kind") != "PRIMITIVE_MEMORY_EFFECT":
                    continue
                for effect in channel_graph.get("primitive_memory_effects", []) or []:
                    if effect.get("effect_id") == edge.get("effect_id"):
                        address = _parse_hex_component(
                            str(effect.get("instruction_address", "")).removeprefix(
                                "0x"
                            )
                        )
                        if address is not None:
                            relevant_effect_addresses.append(address)

    # Exact branch predicates on bytes loaded from the Source object.
    for operation in by_site.values():
        site_parts = str(operation.get("site_id", "")).split(":")
        operation_function = "fn:" + site_parts[1] if len(site_parts) >= 3 else ""
        if operation_function not in selected_function_ids:
            continue
        if operation.get("mnemonic") not in {"INT_EQUAL", "INT_NOTEQUAL"}:
            continue
        inputs = operation.get("inputs", []) or []
        constants = [_constant_value(node) for node in inputs]
        constant = next((value for value in constants if value is not None), None)
        variable = next(
            (node for node, value in zip(inputs, constants) if value is None), None
        )
        if constant is None or variable is None:
            continue
        definition = by_output.get(str(variable.get("value_id", "")))
        if not definition or definition.get("mnemonic") not in {
            "LOAD",
            "CAST",
            "INT_ZEXT",
        }:
            continue
        while definition and definition.get("mnemonic") in {"CAST", "INT_ZEXT"}:
            input_id = str(
                (definition.get("inputs", [{}]) or [{}])[0].get("value_id", "")
            )
            definition = by_output.get(input_id)
        if not definition or definition.get("mnemonic") != "LOAD":
            continue
        load_inputs = definition.get("inputs", []) or []
        if len(load_inputs) < 2:
            continue
        offsets = _source_pointer_offsets(
            str(load_inputs[1].get("value_id", "")),
            source_base=source_base,
            by_output=by_output,
            binding_by_value=binding_by_value,
            binary=binary,
        )
        if len(offsets) != 1:
            continue
        compare_output = str((operation.get("output") or {}).get("value_id", ""))
        branch_targets: list[int] = []
        for branch in by_site.values():
            if branch.get("mnemonic") != "CBRANCH":
                continue
            branch_inputs = branch.get("inputs", []) or []
            if not any(
                str(node.get("value_id", "")) == compare_output
                for node in branch_inputs
            ):
                continue
            for node in branch_inputs:
                if str(node.get("value_id", "")) == compare_output:
                    continue
                target = _parse_hex_component(
                    str(node.get("offset", "")).removeprefix("0x")
                )
                if target is not None:
                    branch_targets.append(target)
        controls_effect = any(
            target <= effect_address <= target + 0x40
            for target in branch_targets
            for effect_address in relevant_effect_addresses
        )
        facts.append(
            {
                "fact_id": f"payload-control:{operation['site_id']}",
                "kind": "SOURCE_BYTE_PREDICATE",
                "role": "packet_type",
                "source_object_ids": sorted(source_object_ids),
                "offset": next(iter(offsets)),
                "size": int((definition.get("output") or {}).get("size", 1)),
                "operator": "eq" if operation.get("mnemonic") == "INT_EQUAL" else "ne",
                "value": constant,
                "branch_targets": [
                    canonical_address(target) for target in sorted(set(branch_targets))
                ],
                "controls_selected_effect": controls_effect,
                "evidence_refs": [definition["site_id"], operation["site_id"]],
            }
        )

    effect_by_id = {
        str(effect.get("effect_id", "")): effect
        for effect in channel_graph.get("primitive_memory_effects", []) or []
    }
    for parameter in chain.get("parameter_results", []) or []:
        if parameter.get("role") != "len":
            continue
        for path_row in parameter.get("paths", []) or []:
            for edge in path_row.get("path", []) or []:
                if edge.get("kind") != "PRIMITIVE_MEMORY_EFFECT":
                    continue
                effect = effect_by_id.get(str(edge.get("effect_id", "")))
                if not effect or effect.get("effect_precision") != "EXACT_REGION":
                    continue
                source_region = (effect.get("source", {}) or {}).get("region", {}) or {}
                destination = effect.get("destination", {}) or {}
                destination_region = destination.get("region", {}) or {}
                destination_id = str(effect.get("destination_object_id", ""))
                source_offset = source_region.get("offset")
                copy_size = destination_region.get("size")
                if not isinstance(source_offset, int) or not isinstance(copy_size, int):
                    continue
                field_shapes: set[tuple[int, int]] = set()
                field_sites: set[str] = set()
                for binding in channel_graph.get("value_object_bindings", []) or []:
                    if (
                        binding.get("object_id") != destination_id
                        or binding.get("precision") != "EXACT"
                    ):
                        continue
                    access_path = binding.get("access_path", []) or []
                    if len(access_path) != 1 or not str(access_path[0]).startswith(
                        "byte_offset:"
                    ):
                        continue
                    field_offset = int(str(access_path[0]).split(":", 1)[1], 0)
                    value_object = str(binding.get("value_object_id", ""))
                    try:
                        field_size = int(value_object.rsplit(":", 1)[1], 0)
                    except ValueError:
                        continue
                    if field_size > copy_size or field_offset + field_size > copy_size:
                        continue
                    # Prefer the actual memory value width over a later widened register alias.
                    if value_object.startswith("stack:"):
                        field_shapes.add((field_offset, field_size))
                        if binding.get("def_site_id"):
                            field_sites.add(str(binding["def_site_id"]))
                if len(field_shapes) != 1:
                    continue
                field_offset, field_size = next(iter(field_shapes))
                facts.append(
                    {
                        "fact_id": f"payload-field:{effect['effect_id']}:len",
                        "kind": "COPIED_FIELD_TO_VULNERABLE_PARAMETER",
                        "role": "len",
                        "source_object_ids": sorted(source_object_ids),
                        "offset": source_offset + field_offset,
                        "size": field_size,
                        "encoding": "uint_le",
                        "copy_source_offset": source_offset,
                        "field_offset_within_copy": field_offset,
                        "evidence_refs": [
                            str(effect.get("site_id", "")),
                            *sorted(field_sites),
                            str(selected_sites and sorted(selected_sites)[0] or ""),
                        ],
                    }
                )

    # Resolve exact Source-object pointer alternatives used at the selected Sink callsites.
    role_indices = {
        str(row.get("role", "")): int(row.get("index", -1))
        for row in sink.get("vulnerable_parameters", []) or []
        if isinstance(row.get("index"), int)
    }
    for site_id in sorted(selected_sites):
        call = by_site.get(site_id)
        if not call or call.get("mnemonic") != "CALL":
            continue
        argument_ids = (call.get("call") or {}).get("argument_value_ids") or []
        src_index = role_indices.get("src", -1)
        if not 0 <= src_index < len(argument_ids):
            continue
        argument_value_id = str(argument_ids[src_index])
        argument_definition = by_output.get(argument_value_id)
        offsets: set[int] = set()
        if (
            relevant_effect_addresses
            and argument_definition
            and argument_definition.get("mnemonic") == "MULTIEQUAL"
        ):
            threshold = max(relevant_effect_addresses)
            for input_node in argument_definition.get("inputs", []) or []:
                input_definition = by_output.get(str(input_node.get("value_id", "")))
                input_address = _parse_hex_component(
                    str(
                        (input_definition or {}).get("instruction_address", "")
                    ).removeprefix("0x")
                )
                if input_address is None or input_address < threshold:
                    continue
                offsets.update(
                    _source_pointer_offsets(
                        str(input_node.get("value_id", "")),
                        source_base=source_base,
                        by_output=by_output,
                        binding_by_value=binding_by_value,
                        binary=binary,
                    )
                )
        if not offsets:
            offsets = _source_pointer_offsets(
                argument_value_id,
                source_base=source_base,
                by_output=by_output,
                binding_by_value=binding_by_value,
                binary=binary,
            )
        if offsets:
            facts.append(
                {
                    "fact_id": f"payload-region:{site_id}:src",
                    "kind": "SOURCE_POINTER_TO_VULNERABLE_PARAMETER",
                    "role": "src",
                    "source_object_ids": sorted(source_object_ids),
                    "offset_candidates": sorted(offsets),
                    "evidence_refs": [site_id],
                }
            )
    return facts


def build_source_call_sequence(
    *,
    selected_sources: list[dict[str, Any]],
    program_facts: dict[str, Any],
    binary: Path,
) -> list[dict[str, Any]]:
    """Expose receive-call order and exact dependencies between transactions."""
    function_map = {
        str(row.get("function_id", "")): row
        for row in program_facts.get("functions", []) or []
    }
    function_by_name = {
        str(row.get("name", "")): row
        for row in program_facts.get("functions", []) or []
    }
    rows: list[dict[str, Any]] = []
    for source in selected_sources:
        source_site = str(source.get("site_id", ""))
        function_id = str(source.get("function_id", ""))
        callee = str(source.get("callee", ""))
        selected_parts = source_site.split(":")
        selected_address = (
            _parse_hex_component(selected_parts[2])
            if len(selected_parts) >= 3
            else None
        )
        function = function_map.get(function_id, {})
        callee_function = function_by_name.get(callee, {})
        formal_names = {
            int(row.get("index", -1)): str(row.get("name", ""))
            for row in callee_function.get("parameters", []) or []
        }
        _, by_output = _pcode_index({"functions": [function]})
        calls: list[dict[str, Any]] = []
        call_operations: list[dict[str, Any]] = []
        for operation in function.get("pcode_ops", []) or []:
            call = operation.get("call") or {}
            if call.get("target_function") != callee:
                continue
            address = _parse_hex_component(
                str(operation.get("instruction_address", "")).removeprefix("0x")
            )
            if (
                selected_address is not None
                and address is not None
                and address > selected_address
            ):
                continue
            arguments = []
            for index, node in enumerate((operation.get("inputs", []) or [])[1:]):
                arguments.append(
                    {
                        "index": index,
                        "value_id": node.get("value_id", ""),
                        "name": node.get("high_name", ""),
                        "formal_name": formal_names.get(index, ""),
                        "type": node.get("high_data_type", ""),
                        "constant": _constant_value(node),
                    }
                )
            calls.append(
                {
                    "site_id": operation.get("site_id", ""),
                    "instruction_address": operation.get("instruction_address", ""),
                    "callee": callee,
                    "arguments": arguments,
                    "selected_source_call": operation.get("site_id") == source_site,
                }
            )
            call_operations.append(operation)
        if calls:
            dependencies: list[dict[str, Any]] = []
            selected_index = next(
                (
                    index
                    for index, call in enumerate(calls)
                    if call["selected_source_call"]
                ),
                -1,
            )
            source_base = _object_base_address(str(source.get("source_object_id", "")))
            output_arg_index = -1
            if selected_index >= 0:
                selected_inputs = (
                    call_operations[selected_index].get("inputs", []) or []
                )[1:]
                pointer_matches: list[int] = []
                output_value_id = str(
                    (source.get("source_output") or {}).get("value_id", "")
                )
                for index, node in enumerate(selected_inputs):
                    if output_value_id and str(node.get("value_id", "")) == output_value_id:
                        pointer_matches.append(index)
                        continue
                    if source_base is None:
                        continue
                    object_id = str(node.get("object_id", ""))
                    object_base = _object_base_address(object_id)
                    literal = None
                    if object_id.startswith("global:"):
                        literal_addr = _parse_hex_component(object_id.split(":")[1])
                        literal = (
                            _read_elf_u32(binary, literal_addr)
                            if literal_addr
                            else None
                        )
                    if object_base == source_base or literal == source_base:
                        pointer_matches.append(index)
                if len(pointer_matches) == 1:
                    output_arg_index = pointer_matches[0]

            if selected_index > 0 and output_arg_index >= 0:
                selected_arguments = calls[selected_index]["arguments"]
                length_args = [
                    row
                    for row in selected_arguments
                    if row.get("index") != output_arg_index
                    and row.get("constant") is None
                    and any(
                        token
                        in (
                            str(row.get("name", ""))
                            + " "
                            + str(row.get("formal_name", ""))
                        ).lower()
                        for token in ("len", "size", "length")
                    )
                ]
                for length_arg in length_args:
                    memory_nodes = _reachable_memory_nodes(
                        str(length_arg.get("value_id", "")), by_output
                    )
                    for prior_index in range(selected_index):
                        prior_call = calls[prior_index]
                        prior_operation = call_operations[prior_index]
                        prior_inputs = (prior_operation.get("inputs", []) or [])[1:]
                        if output_arg_index >= len(prior_inputs):
                            continue
                        stack_base = _stack_pointer_offset(
                            str(prior_inputs[output_arg_index].get("value_id", "")),
                            by_output,
                        )
                        output_extent = next(
                            (
                                int(row["constant"])
                                for row in prior_call["arguments"]
                                if row.get("index") > output_arg_index
                                and isinstance(row.get("constant"), int)
                            ),
                            None,
                        )
                        if stack_base is None or output_extent is None:
                            continue
                        matches: list[tuple[int, int, str]] = []
                        for node in memory_nodes:
                            object_id = str(node.get("object_id", ""))
                            parts = object_id.split(":")
                            if len(parts) < 4 or parts[0] != "stack":
                                continue
                            try:
                                field_offset = int(parts[2], 16)
                                field_size = int(parts[3], 0)
                            except ValueError:
                                continue
                            relative = field_offset - stack_base
                            if 0 <= relative and relative + field_size <= output_extent:
                                matches.append(
                                    (
                                        relative,
                                        field_size,
                                        str(node.get("value_id", "")),
                                    )
                                )
                        shapes = {(offset, size) for offset, size, _ in matches}
                        if len(shapes) != 1:
                            continue
                        offset, size = next(iter(shapes))
                        target_values = {
                            value_id
                            for match_offset, match_size, value_id in matches
                            if (match_offset, match_size) == (offset, size)
                        }
                        affine_deltas = _affine_deltas_to_value(
                            str(length_arg.get("value_id", "")),
                            target_values,
                            by_output,
                        )
                        if len(affine_deltas) != 1:
                            continue
                        dependency = {
                            "fact_id": (
                                f"transaction-length:{prior_call['site_id']}:{offset}:"
                                f"{calls[selected_index]['site_id']}"
                            ),
                            "kind": "PRIOR_OUTPUT_FIELD_TO_RECEIVE_LENGTH",
                            "producer_call_index": prior_index,
                            "producer_call_site_id": prior_call["site_id"],
                            "consumer_call_index": selected_index,
                            "consumer_call_site_id": calls[selected_index]["site_id"],
                            "output_argument_index": output_arg_index,
                            "consumer_length_argument_index": int(length_arg["index"]),
                            "offset": offset,
                            "size": size,
                            "encoding": "uint_le",
                            "consumer_relation": {
                                "kind": "AFFINE_ADD",
                                "constant": next(iter(affine_deltas)),
                            },
                            "evidence_refs": sorted(
                                {
                                    prior_call["site_id"],
                                    calls[selected_index]["site_id"],
                                    *(value_id for _, _, value_id in matches),
                                }
                            ),
                        }
                        if not any(
                            row.get("fact_id") == dependency["fact_id"]
                            for row in dependencies
                        ):
                            dependencies.append(dependency)
            rows.append(
                {
                    "source_id": source.get("id", ""),
                    "function_id": function_id,
                    "calls_in_instruction_order": calls,
                    "inter_transaction_dependencies": dependencies,
                }
            )
    return rows


def build_evidence_packet(
    *,
    selection: dict[str, Any],
    chains_doc: dict[str, Any],
    sinks_doc: dict[str, Any],
    sources_doc: dict[str, Any],
    channel_graph_doc: dict[str, Any],
    program_facts_doc: dict[str, Any],
    binary: Path,
    functions_jsonl: Path,
) -> dict[str, Any]:
    alert_id = str(selection["alert_id"])
    chain = next(
        row
        for row in chains_doc.get("chains", []) or []
        if str(row.get("chain_id", "")) == alert_id
    )
    sink = rows_by_id(sinks_doc, "sink_startpoints")[str(selection["sink_id"])]
    source_map = rows_by_id(sources_doc, "confirmed_sources")
    selected_sources = [
        source_map[sid] for sid in selection.get("source_ids", []) if sid in source_map
    ]
    underlying_ids = collect_underlying_source_ids(selected_sources, source_map)
    underlying_sources = [source_map[source_id] for source_id in underlying_ids]

    by_name, by_address = load_function_corpus(functions_jsonl)
    requested_functions: list[dict[str, Any]] = []
    seen_functions: set[str] = set()

    def add_function(row: dict[str, Any] | None) -> None:
        if not row:
            return
        identity = str(row.get("addr") or row.get("name"))
        if identity in seen_functions:
            return
        seen_functions.add(identity)
        requested_functions.append(compact_function(row))

    add_function(by_name.get(str(chain.get("sink_function", ""))))
    add_function(by_name.get(str(sink.get("function", ""))))
    for site_id in selection.get("source_backed_callsite_ids", []) or []:
        add_function(by_address.get(function_address_from_site(site_id)))
    for source in selected_sources + underlying_sources:
        add_function(by_name.get(str(source.get("function", ""))))
        add_function(by_name.get(str(source.get("callee", ""))))

    allowed_registers: list[str] = []
    for source in underlying_sources:
        proof = source.get("proof", {}) or {}
        address = canonical_address(proof.get("register_address"))
        if address and address not in allowed_registers:
            allowed_registers.append(address)
    runtime_sources = runtime_hardware_sources(source_map, allowed_registers)

    selected_site_ids = set(selection.get("source_backed_callsite_ids", []) or [])
    payload_layout_facts = build_payload_layout_facts(
        chain=chain,
        sink=sink,
        channel_graph=channel_graph_doc,
        program_facts=program_facts_doc,
        binary=binary,
        selected_sites=selected_site_ids,
        selected_sources=selected_sources,
    )
    source_call_sequence = build_source_call_sequence(
        selected_sources=selected_sources,
        program_facts=program_facts_doc,
        binary=binary,
    )
    return {
        "unchanged_alert": chain,
        "selection_references": selection,
        "sink_definition": compact_sink(sink, selected_site_ids),
        "source_definitions": [compact_source(row) for row in selected_sources],
        "upstream_hardware_sources": [
            compact_source(row) for row in underlying_sources
        ],
        "runtime_hardware_sources": [
            compact_source(row) for row in runtime_sources
        ],
        "allowed_register_addresses": allowed_registers,
        "payload_layout_facts": payload_layout_facts,
        "source_call_sequence": source_call_sequence,
        "decompiled_functions": requested_functions,
        "policy": {
            "known_cve_material_available": False,
            "known_poc_available": False,
            "known_fuzzware_config_available": False,
            "raw_fuzzware_bytes_must_not_be_generated": True,
            "source_boundary_injection_required": True,
            "max_concrete_inputs": MAX_CONCRETE_INPUTS,
        },
    }


def _exact_keys(value: dict[str, Any], keys: set[str], where: str) -> None:
    if set(value) != keys:
        raise ValueError(
            f"{where} keys differ: missing={sorted(keys - set(value))}, extra={sorted(set(value) - keys)}"
        )


def validate_plan(
    plan: dict[str, Any],
    *,
    packet: dict[str, Any],
    binary_sha256: str,
) -> None:
    _exact_keys(plan, PLAN_KEYS, "plan")
    if plan["schema_version"] != SCHEMA_VERSION:
        raise ValueError("unexpected execution plan schema")
    alert = packet["unchanged_alert"]
    selection = packet["selection_references"]
    if plan["alert_id"] != alert["chain_id"]:
        raise ValueError("plan alert_id does not match unchanged Alert")
    if plan["binary_sha256"] != binary_sha256:
        raise ValueError("plan binary hash mismatch")
    source_binding = plan["source_binding"]
    _exact_keys(
        source_binding,
        {
            "source_id",
            "source_site_id",
            "delivery",
            "hardware_source_ids",
            "register_addresses",
        },
        "source_binding",
    )
    source_rows = packet["source_definitions"] + packet["upstream_hardware_sources"]
    allowed_sources = {str(row.get("id", "")): row for row in source_rows}
    if source_binding["source_id"] not in allowed_sources:
        raise ValueError("source_binding references a Source outside the Alert lineage")
    if source_binding["source_site_id"] != allowed_sources[
        source_binding["source_id"]
    ].get("site_id"):
        raise ValueError("source_binding SiteId mismatch")
    allowed_hardware = {
        str(row.get("id", "")) for row in packet["upstream_hardware_sources"]
    }
    if not set(source_binding["hardware_source_ids"]).issubset(allowed_hardware):
        raise ValueError("hardware Source is outside the verified Source lineage")
    allowed_registers = set(packet["allowed_register_addresses"])
    if not set(map(str.lower, source_binding["register_addresses"])).issubset(
        allowed_registers
    ):
        raise ValueError("plan invented an unverified MMIO register address")
    if (
        source_binding["delivery"] == "MMIO"
        and not source_binding["register_addresses"]
    ):
        raise ValueError("MMIO delivery has no verified register address")

    templates = plan["input_templates"]
    if not 1 <= len(templates) <= 8:
        raise ValueError("execution plan needs one to eight input templates")
    template_ids: set[str] = set()
    total_limit = 0
    for template in templates:
        _exact_keys(
            template,
            {
                "template_id",
                "byte_length",
                "fill_byte",
                "payload_start",
                "payload_start_evidence_ref",
                "fields",
                "concretization_limit",
            },
            "template",
        )
        template_id = str(template["template_id"])
        if not template_id or template_id in template_ids:
            raise ValueError("template IDs must be unique")
        template_ids.add(template_id)
        byte_length = int(template["byte_length"])
        if not 1 <= byte_length <= 4096:
            raise ValueError("template byte_length outside v1 limit")
        if not 0 <= int(template["fill_byte"]) <= 255:
            raise ValueError("fill_byte is not a byte")
        limit = int(template["concretization_limit"])
        if not 1 <= limit <= MAX_CONCRETE_INPUTS:
            raise ValueError("template concretization_limit outside v1 limit")
        total_limit += limit
        names: set[str] = set()
        layout_facts = {
            str(row.get("fact_id", "")): row
            for row in packet.get("payload_layout_facts", []) or []
        }
        payload_start = template["payload_start"]
        payload_ref = str(template["payload_start_evidence_ref"] or "")
        if payload_start is not None:
            payload_fact = layout_facts.get(payload_ref)
            if not payload_fact or payload_fact.get("role") != "src":
                raise ValueError(
                    "payload_start is not bound to a verified src layout fact"
                )
            if int(payload_start) not in payload_fact.get("offset_candidates", []):
                raise ValueError(
                    "payload_start differs from verified Source pointer offsets"
                )
        for field in template["fields"]:
            _exact_keys(
                field,
                {
                    "name",
                    "role",
                    "offset",
                    "size",
                    "encoding",
                    "candidates",
                    "evidence_ref",
                },
                "field",
            )
            if field["name"] in names:
                raise ValueError("field names must be unique within a template")
            names.add(field["name"])
            offset, size = int(field["offset"]), int(field["size"])
            if offset < 0 or size <= 0 or offset + size > byte_length:
                raise ValueError("field lies outside semantic payload")
            if field["encoding"] not in {"uint_le", "uint_be", "bytes_hex"}:
                raise ValueError("unsupported field encoding")
            if not field["candidates"]:
                raise ValueError("field has no candidates")
            evidence_fact = layout_facts.get(str(field["evidence_ref"]))
            role = str(field["role"])
            if role in {"packet_type", "len"}:
                if not evidence_fact or evidence_fact.get("role") != role:
                    raise ValueError(f"{role} field lacks an exact payload-layout fact")
                if int(field["offset"]) != int(evidence_fact.get("offset", -1)):
                    raise ValueError(
                        f"{role} field offset differs from P-code evidence"
                    )
                if int(field["size"]) != int(evidence_fact.get("size", -1)):
                    raise ValueError(f"{role} field width differs from P-code evidence")
                if role == "packet_type" and not evidence_fact.get(
                    "controls_selected_effect"
                ):
                    raise ValueError(
                        "packet_type predicate does not control the selected Sink path"
                    )
            for candidate in field["candidates"]:
                if field["encoding"] == "bytes_hex":
                    text = str(candidate)
                    if not re.fullmatch(r"[0-9a-fA-F]*", text) or len(text) != size * 2:
                        raise ValueError("bytes_hex candidate has wrong width")
                else:
                    if not isinstance(candidate, int) or not 0 <= candidate < (
                        1 << (8 * size)
                    ):
                        raise ValueError("integer candidate has wrong width")
            if role == "packet_type" and evidence_fact.get("operator") == "eq":
                if evidence_fact.get("value") not in field["candidates"]:
                    raise ValueError(
                        "packet_type candidates do not satisfy the verified branch"
                    )
    if total_limit > MAX_CONCRETE_INPUTS:
        raise ValueError("plan exceeds the global concrete-input budget")

    static_receive_call_count = max(
        (
            len(row.get("calls_in_instruction_order", []) or [])
            for row in packet.get("source_call_sequence", []) or []
        ),
        default=1,
    )
    ordered_source_ordinal = 0
    for event in sorted(plan["events"], key=lambda row: int(row["order"])):
        if event.get("kind") == "SOURCE_PAYLOAD":
            event.setdefault(
                "call_index", ordered_source_ordinal % static_receive_call_count
            )
            event.setdefault(
                "transaction_group",
                ordered_source_ordinal // static_receive_call_count,
            )
            ordered_source_ordinal += 1
        _exact_keys(
            event,
            {
                "event_id",
                "kind",
                "order",
                "template_id",
                "register_address",
                "irq",
                "trigger_address",
                "call_index",
                "transaction_group",
            },
            "event",
        )
        if event["kind"] == "SOURCE_PAYLOAD":
            if event["template_id"] not in template_ids:
                raise ValueError("SOURCE_PAYLOAD event references an unknown template")
            address = str(event["register_address"] or "").lower()
            if (
                source_binding["delivery"] == "MMIO"
                and address not in allowed_registers
            ):
                raise ValueError(
                    "SOURCE_PAYLOAD event uses an unverified MMIO register"
                )
            call_index = int(event["call_index"])
            transaction_group = int(event["transaction_group"])
            if call_index < 0:
                raise ValueError("SOURCE_PAYLOAD call_index must be nonnegative")
            if transaction_group < 0:
                raise ValueError(
                    "SOURCE_PAYLOAD transaction_group must be nonnegative"
                )
        elif event["kind"] == "INTERRUPT":
            if not isinstance(event["irq"], int):
                raise ValueError("INTERRUPT event lacks an IRQ")
    source_events = [
        event for event in plan["events"] if event["kind"] == "SOURCE_PAYLOAD"
    ]
    source_events.sort(key=lambda row: int(row["order"]))
    required_transactions = static_receive_call_count
    if len(source_events) < required_transactions:
        raise ValueError(
            f"plan has {len(source_events)} Source payload event(s), but static call order requires "
            f"at least {required_transactions} receive transaction(s)"
        )
    templates_by_id = {str(row["template_id"]): row for row in templates}
    longest_sequence = max(
        packet.get("source_call_sequence", []) or [{}],
        key=lambda row: len(row.get("calls_in_instruction_order", []) or []),
    )
    static_call_count = len(
        longest_sequence.get("calls_in_instruction_order", []) or []
    )
    if static_call_count:
        for event in source_events:
            if int(event["call_index"]) >= static_call_count:
                raise ValueError(
                    "SOURCE_PAYLOAD call_index exceeds the static receive sequence"
                )
        group_rows: dict[int, list[dict[str, Any]]] = {}
        for event in source_events:
            group_rows.setdefault(int(event["transaction_group"]), []).append(event)
        expected_groups = list(range(max(group_rows, default=-1) + 1))
        if sorted(group_rows) != expected_groups:
            raise ValueError("transaction_group values must be contiguous")
        for group, rows in group_rows.items():
            ordered_calls = [int(row["call_index"]) for row in rows]
            if ordered_calls != sorted(ordered_calls):
                raise ValueError(
                    f"Source calls in transaction_group {group} are out of order"
                )
            if len(set(ordered_calls)) != len(ordered_calls):
                raise ValueError(
                    f"transaction_group {group} repeats a static receive call"
                )
            expected_calls = list(range(static_call_count))
            if ordered_calls != expected_calls:
                raise ValueError(
                    f"transaction_group {group} does not cover the complete static "
                    f"receive sequence {expected_calls}"
                )
    for call_index, call in enumerate(
        longest_sequence.get("calls_in_instruction_order", []) or []
    ):
        first_group_events = [
            row for row in source_events if int(row["transaction_group"]) == 0
        ]
        if call_index >= len(first_group_events):
            break
        constant_lengths = [
            int(argument["constant"])
            for argument in call.get("arguments", []) or []
            if argument.get("constant") is not None
            and any(
                token
                in (
                    str(argument.get("name", ""))
                    + " "
                    + str(argument.get("formal_name", ""))
                ).lower()
                for token in ("len", "size", "length")
            )
        ]
        if len(constant_lengths) == 1:
            template = templates_by_id[
                first_group_events[call_index]["template_id"]
            ]
            if int(template["byte_length"]) != constant_lengths[0]:
                raise ValueError(
                    "Source event byte_length conflicts with the exact call extent"
                )
    for sequence in packet.get("source_call_sequence", []) or []:
        calls = sequence.get("calls_in_instruction_order", []) or []
        for group in sorted(
            {int(row["transaction_group"]) for row in source_events}
        ):
            group_events = [
                row
                for row in source_events
                if int(row["transaction_group"]) == group
            ]
            by_call_index = {
                int(row["call_index"]): row for row in group_events
            }
            for dependency in sequence.get("inter_transaction_dependencies", []) or []:
                producer_index = int(dependency.get("producer_call_index", -1))
                consumer_index = int(dependency.get("consumer_call_index", -1))
                if producer_index not in by_call_index or consumer_index not in by_call_index:
                    continue
                if not 0 <= producer_index < consumer_index < len(calls):
                    raise ValueError("invalid static inter-transaction dependency")
                producer_template = templates_by_id[
                    by_call_index[producer_index]["template_id"]
                ]
                consumer_template = templates_by_id[
                    by_call_index[consumer_index]["template_id"]
                ]
                matching_fields = [
                    field
                    for field in producer_template.get("fields", []) or []
                    if field.get("role") == "header"
                    and int(field.get("offset", -1)) == int(dependency.get("offset", -2))
                    and int(field.get("size", -1)) == int(dependency.get("size", -2))
                    and field.get("evidence_ref") == dependency.get("fact_id")
                ]
                if len(matching_fields) != 1:
                    raise ValueError(
                        "prior receive transaction lacks the exact field that controls "
                        "the selected receive length"
                    )
                relation = dependency.get("consumer_relation") or {}
                required_producer = int(consumer_template["byte_length"])
                if relation.get("kind") == "AFFINE_ADD":
                    required_producer -= int(relation.get("constant", 0))
                if required_producer not in matching_fields[0]["candidates"]:
                    raise ValueError(
                        "prior transaction length field does not request the selected payload size"
                    )
    if len({int(event["order"]) for event in plan["events"]}) != len(plan["events"]):
        raise ValueError("event order values must be unique")
    if not all(isinstance(item, str) for item in plan["ordering_constraints"]):
        raise ValueError("ordering_constraints must contain plain strings")
    if not all(isinstance(item, str) for item in plan["unresolved_assumptions"]):
        raise ValueError("unresolved_assumptions must contain plain strings")

    checkpoint = plan["sink_checkpoint"]
    _exact_keys(
        checkpoint,
        {
            "sink_id",
            "effect_site_id",
            "effect_address",
            "boundary_site_ids",
            "vulnerable_parameter_roles",
        },
        "sink_checkpoint",
    )
    sink = packet["sink_definition"]
    if checkpoint["sink_id"] != selection["sink_id"]:
        raise ValueError("sink checkpoint ID mismatch")
    if checkpoint["effect_site_id"] != selection["sink_site_id"]:
        raise ValueError("sink checkpoint SiteId mismatch")
    expected_address = canonical_address(sink.get("instruction_address"))
    if canonical_address(checkpoint["effect_address"]) != expected_address:
        raise ValueError("sink effect address mismatch")
    allowed_boundary_sites = set(selection.get("source_backed_callsite_ids", []))
    if not set(checkpoint["boundary_site_ids"]).issubset(allowed_boundary_sites):
        raise ValueError("sink checkpoint references an unsupported boundary callsite")
    if not set(checkpoint["vulnerable_parameter_roles"]).issubset(
        set(sink.get("vulnerable_parameter_roles", []) or [])
    ):
        raise ValueError("sink checkpoint invented a vulnerable parameter role")
    if not set(plan["expected_invalid_effects"]).issubset(INVALID_EFFECTS):
        raise ValueError("plan contains an unsupported invalid effect")
    if not 2 <= int(plan["replay_count"]) <= 5:
        raise ValueError("replay_count outside v1 range")


def resolve_plan_evidence(
    candidate: dict[str, Any], packet: dict[str, Any]
) -> dict[str, Any]:
    """Apply only evidence-preserving, uniquely determined plan repairs.

    The LLM chooses the semantic layout. This resolver is deliberately unable
    to invent a field or offset: it can bind a chosen offset to the sole
    matching P-code fact, remove unsupported fields, and tighten exploration
    limits to the number of concrete combinations already requested.
    """
    plan = copy.deepcopy(candidate)
    for event in plan.get("events", []) or []:
        if not isinstance(event, dict):
            continue
        event.setdefault("irq", None)
        event.setdefault("trigger_address", None)
        event.setdefault("transaction_group", 0)
    facts = packet.get("payload_layout_facts", []) or []
    transaction_facts = [
        dependency
        for sequence in packet.get("source_call_sequence", []) or []
        for dependency in sequence.get("inter_transaction_dependencies", []) or []
    ]
    valid_roles = {"packet_type", "header", "len", "payload", "other"}
    source_rows = {
        str(row.get("id", "")): row
        for row in packet.get("source_definitions", []) or []
        if row.get("id")
    }
    hardware_rows = {
        str(row.get("id", "")): row
        for row in packet.get("upstream_hardware_sources", []) or []
        if row.get("id")
    }
    source_binding = plan.get("source_binding") or {}
    selected_source = source_rows.get(str(source_binding.get("source_id", "")))
    if selected_source:
        source_binding["source_site_id"] = selected_source.get("site_id", "")
        if len(hardware_rows) == 1:
            hardware_id, hardware = next(iter(hardware_rows.items()))
            source_binding["hardware_source_ids"] = [hardware_id]
            register = canonical_address(
                ((hardware.get("proof") or {}).get("register_address"))
            )
            if source_binding.get("delivery") == "MMIO" and register:
                source_binding["register_addresses"] = [register]
                for event in plan.get("events", []) or []:
                    if event.get("kind") == "SOURCE_PAYLOAD":
                        event["register_address"] = register
    for template in plan.get("input_templates", []) or []:
        if not isinstance(template, dict):
            continue
        fill_byte = template.get("fill_byte")
        if isinstance(fill_byte, str):
            try:
                template["fill_byte"] = int(fill_byte, 0)
            except ValueError:
                pass
        payload_start = template.get("payload_start")
        if payload_start is not None:
            matches = [
                row
                for row in facts
                if row.get("role") == "src"
                and int(payload_start) in (row.get("offset_candidates", []) or [])
            ]
            if len(matches) == 1:
                template["payload_start_evidence_ref"] = matches[0].get("fact_id")
            else:
                template["payload_start"] = None
                template["payload_start_evidence_ref"] = None

        fields = template.get("fields", []) or []
        supported_fields: list[dict[str, Any]] = []
        combinations = 1
        for field in fields:
            if not isinstance(field, dict) or field.get("role") not in valid_roles:
                continue
            role = str(field.get("role"))
            if field.get("encoding") in {"uint_le", "uint_be"}:
                normalized_candidates: list[Any] = []
                for value in field.get("candidates", []) or []:
                    if isinstance(value, str):
                        try:
                            value = int(value, 0)
                        except ValueError:
                            pass
                    normalized_candidates.append(value)
                field["candidates"] = normalized_candidates
            if role in {"packet_type", "len"}:
                matches = [
                    row
                    for row in facts
                    if row.get("role") == role
                    and int(row.get("offset", -1)) == int(field.get("offset", -2))
                    and int(row.get("size", -1)) == int(field.get("size", -2))
                ]
                if role == "packet_type":
                    candidate_values = set(field.get("candidates", []) or [])
                    controlled = [
                        row
                        for row in matches
                        if row.get("controls_selected_effect")
                        and row.get("operator") == "eq"
                        and row.get("value") in candidate_values
                    ]
                    if controlled:
                        matches = controlled
                if len(matches) == 1:
                    field["evidence_ref"] = matches[0].get("fact_id")
                else:
                    continue
            elif role == "header":
                matches = [
                    row
                    for row in transaction_facts
                    if int(row.get("offset", -1)) == int(field.get("offset", -2))
                    and int(row.get("size", -1)) == int(field.get("size", -2))
                ]
                if len(matches) == 1:
                    field["evidence_ref"] = matches[0].get("fact_id")
            combinations *= max(1, len(field.get("candidates", []) or []))
            supported_fields.append(field)
        template["fields"] = supported_fields
        template["concretization_limit"] = max(
            1, min(MAX_CONCRETE_INPUTS, combinations)
        )

    templates_by_id = {
        str(row.get("template_id", "")): row
        for row in plan.get("input_templates", []) or []
        if isinstance(row, dict)
    }
    source_events = sorted(
        (
            row
            for row in plan.get("events", []) or []
            if isinstance(row, dict) and row.get("kind") == "SOURCE_PAYLOAD"
        ),
        key=lambda row: int(row.get("order", 0)),
    )
    static_call_count = max(
        (
            len(row.get("calls_in_instruction_order", []) or [])
            for row in packet.get("source_call_sequence", []) or []
        ),
        default=1,
    )
    complete_groups = False
    if source_events and len(source_events) % static_call_count == 0:
        grouped_calls: dict[int, list[int]] = {}
        for event in source_events:
            grouped_calls.setdefault(
                int(event.get("transaction_group", 0)), []
            ).append(int(event.get("call_index", -1)))
        complete_groups = (
            sorted(grouped_calls) == list(range(len(grouped_calls)))
            and all(
                calls == list(range(static_call_count))
                for calls in grouped_calls.values()
            )
        )
    for ordinal, event in enumerate(source_events):
        if not complete_groups:
            # call_index/transaction_group are adapter mechanics. Their unique
            # value is fixed by the recovered receive-call order, so repair an
            # LLM grouping mistake without changing any semantic payload byte.
            event["call_index"] = ordinal % static_call_count
            event["transaction_group"] = ordinal // static_call_count
        else:
            event.setdefault("call_index", ordinal % static_call_count)
            event.setdefault("transaction_group", ordinal // static_call_count)

    longest_sequence = max(
        packet.get("source_call_sequence", []) or [{}],
        key=lambda row: len(row.get("calls_in_instruction_order", []) or []),
    )
    calls = longest_sequence.get("calls_in_instruction_order", []) or []
    template_call_indexes: dict[str, set[int]] = {}
    for event in source_events:
        template_call_indexes.setdefault(str(event.get("template_id", "")), set()).add(
            int(event.get("call_index", -1))
        )
    for template_id, call_indexes in template_call_indexes.items():
        if len(call_indexes) != 1:
            continue
        call_index = next(iter(call_indexes))
        if not 0 <= call_index < len(calls):
            continue
        constant_lengths = [
            int(argument["constant"])
            for argument in calls[call_index].get("arguments", []) or []
            if argument.get("constant") is not None
            and any(
                token
                in (
                    str(argument.get("name", ""))
                    + " "
                    + str(argument.get("formal_name", ""))
                ).lower()
                for token in ("len", "size", "length")
            )
        ]
        if len(constant_lengths) != 1:
            continue
        template = templates_by_id.get(template_id)
        if not template:
            continue
        exact_length = constant_lengths[0]
        template["byte_length"] = exact_length
        template["fields"] = [
            field
            for field in template.get("fields", []) or []
            if int(field.get("offset", -1)) >= 0
            and int(field.get("size", 0)) > 0
            and int(field.get("offset", -1)) + int(field.get("size", 0))
            <= exact_length
        ]
    for sequence in packet.get("source_call_sequence", []) or []:
        for dependency in sequence.get("inter_transaction_dependencies", []) or []:
            producer_index = int(dependency.get("producer_call_index", -1))
            consumer_index = int(dependency.get("consumer_call_index", -1))
            for group in sorted(
                {int(row.get("transaction_group", 0)) for row in source_events}
            ):
                group_events = {
                    int(row.get("call_index", -1)): row
                    for row in source_events
                    if int(row.get("transaction_group", 0)) == group
                }
                if producer_index not in group_events or consumer_index not in group_events:
                    continue
                producer = templates_by_id.get(
                    str(group_events[producer_index].get("template_id", ""))
                )
                consumer = templates_by_id.get(
                    str(group_events[consumer_index].get("template_id", ""))
                )
                if not producer or not consumer:
                    continue
                offset = int(dependency["offset"])
                size = int(dependency["size"])
                required_value = int(consumer["byte_length"])
                relation = dependency.get("consumer_relation") or {}
                if relation.get("kind") == "AFFINE_ADD":
                    required_value -= int(relation.get("constant", 0))
                if required_value < 0:
                    continue
                fields = producer.get("fields", []) or []
                exact = [
                    field
                    for field in fields
                    if field.get("role") == "header"
                    and int(field.get("offset", -1)) == offset
                    and int(field.get("size", -1)) == size
                ]
                if exact:
                    field = exact[0]
                    field["evidence_ref"] = dependency["fact_id"]
                    field["candidates"] = sorted(
                        {*(field.get("candidates", []) or []), required_value}
                    )
                else:
                    fields = [
                        field
                        for field in fields
                        if int(field.get("offset", 0)) + int(field.get("size", 0)) <= offset
                        or int(field.get("offset", 0)) >= offset + size
                    ]
                    fields.append(
                        {
                            "name": f"next_transaction_length_{offset}",
                            "role": "header",
                            "offset": offset,
                            "size": size,
                            "encoding": str(dependency.get("encoding", "uint_le")),
                            "candidates": [required_value],
                            "evidence_ref": dependency["fact_id"],
                        }
                    )
                    producer["fields"] = sorted(
                        fields, key=lambda row: int(row["offset"])
                    )

    for template in templates_by_id.values():
        combinations = 1
        for field in template.get("fields", []) or []:
            combinations *= max(1, len(field.get("candidates", []) or []))
        template["concretization_limit"] = max(
            1, min(MAX_CONCRETE_INPUTS, combinations)
        )
    return plan


SYSTEM_PROMPT = """You plan bounded execution validation for one firmware Static Alert.
Return only one JSON object. Use only the supplied evidence. Do not use CVE knowledge,
known PoCs, known crashing inputs, or vulnerability-specific configurations. Do not
emit Fuzzware raw bytes. Describe a semantic peripheral payload and required events.
Every function, SiteId, Source, Sink, register address, field relation, and parameter
must be cited from supplied evidence. Unknown hardware timing stays in
unresolved_assumptions. A crash alone is not a PoC.
"""


def prompt_for_packet(packet: dict[str, Any], binary_sha256: str) -> str:
    contract = {
        "schema_version": SCHEMA_VERSION,
        "required_keys": sorted(PLAN_KEYS),
        "binary_sha256": binary_sha256,
        "rules": [
            f"One plan may concretize at most {MAX_CONCRETE_INPUTS} semantic payloads.",
            "Every input template byte_length is an integer from 1 through 4096.",
            "Fields use uint_le, uint_be, or fixed-width bytes_hex candidates.",
            "MMIO register addresses must come from allowed_register_addresses.",
            "Use at least two deterministic replays.",
            "Use only invalid effects exposed by ordinary Fuzzware execution/logs.",
            "SOURCE_PAYLOAD events reference one input template and one verified data register.",
            "Use source_call_sequence to model every receive transaction needed before the selected Source call.",
            "A repeated peripheral transaction uses a new contiguous transaction_group and restarts call_index at zero.",
            "call_index identifies one static receive call; transaction_group identifies one dynamic frame or message.",
            "Honor each inter_transaction_dependency and its consumer_relation. AFFINE_ADD means consumer byte_length equals the decoded producer field plus the stated constant.",
            "When a receive call has an exact constant length argument, its event template must have exactly that byte_length.",
            "For a preliminary receive transaction, inspect the supplied decompiled function and choose fields that satisfy every explicit local Check dominating the next receive call.",
            "packet_type and len fields must copy exact payload_layout_facts.",
            "A payload_start must cite a src layout fact. A malformed len may exceed actual byte_length.",
            "ordering_constraints and unresolved_assumptions are arrays of plain strings, never objects.",
            "Events have unique order values and include every receive transaction in source_call_sequence.",
        ],
        "example_shape": {
            "schema_version": SCHEMA_VERSION,
            "plan_id": "plan:<alert_id>",
            "alert_id": "<exact alert id>",
            "binary_sha256": binary_sha256,
            "source_binding": {
                "source_id": "<offered source>",
                "source_site_id": "<exact SiteId>",
                "delivery": "MMIO",
                "hardware_source_ids": [],
                "register_addresses": [],
            },
            "input_templates": [],
            "events": [
                {
                    "event_id": "source-payload-1",
                    "kind": "SOURCE_PAYLOAD",
                    "order": 0,
                    "template_id": "packet-1",
                    "call_index": 0,
                    "transaction_group": 0,
                    "register_address": "<verified address or null>",
                    "irq": None,
                    "trigger_address": None,
                }
            ],
            "ordering_constraints": [],
            "sink_checkpoint": {
                "sink_id": "<exact sink id>",
                "effect_site_id": "<exact SiteId>",
                "effect_address": "<exact instruction address>",
                "boundary_site_ids": [],
                "vulnerable_parameter_roles": [],
            },
            "expected_invalid_effects": ["INVALID_READ", "INVALID_WRITE", "CRASH"],
            "replay_count": 2,
            "unresolved_assumptions": [],
            "evidence_refs": [],
        },
        "input_template_keys": [
            "template_id",
            "byte_length",
            "fill_byte",
            "payload_start",
            "payload_start_evidence_ref",
            "fields",
            "concretization_limit",
        ],
        "field_keys": [
            "name",
            "role",
            "offset",
            "size",
            "encoding",
            "candidates",
            "evidence_ref",
        ],
    }
    alert = packet["unchanged_alert"]
    selected_source_ids = {
        str(row.get("id", "")) for row in packet.get("source_definitions", []) or []
    }
    parameter_view = []
    for parameter in alert.get("parameter_results", []) or []:
        selected_paths = [
            {
                "source_id": path.get("source_id", ""),
                "source_site_id": path.get("source_site_id", ""),
                "path_precision": path.get("path_precision", ""),
                "path": [
                    {
                        key: edge.get(key)
                        for key in (
                            "kind",
                            "site_id",
                            "effect_id",
                            "effect_kind",
                            "object_id",
                            "parameter_slot",
                        )
                        if edge.get(key) not in (None, "")
                    }
                    for edge in path.get("path", []) or []
                ],
            }
            for path in parameter.get("paths", []) or []
            if str(path.get("source_id", "")) in selected_source_ids
        ]
        parameter_view.append(
            {
                "role": parameter.get("role", ""),
                "start_value_id": parameter.get("start_value_id", ""),
                "status": parameter.get("status", ""),
                "paths": selected_paths,
                "blockers": parameter.get("blockers", []),
            }
        )
    alert_view = {
        key: alert.get(key)
        for key in (
            "chain_id",
            "sink_id",
            "sink_site_id",
            "sink_function_id",
            "sink_function",
            "sink_callee",
            "sink_label",
            "status",
            "vulnerability_status",
        )
    }
    alert_view["parameter_results"] = parameter_view
    selected_functions = {
        str(alert.get("sink_function", "")),
        str((packet.get("sink_definition") or {}).get("function", "")),
        *[
            str(row.get("function", ""))
            for row in packet.get("source_definitions", []) or []
        ],
        *[
            str(row.get("callee", ""))
            for row in packet.get("source_definitions", []) or []
        ],
    }
    context_function_ids = {
        str(function_id)
        for function_id in (
            (packet.get("execution_context", {}) or {}).get(
                "included_function_ids", []
            )
            or []
        )
    }
    decompiled_functions = [
        row
        for row in packet.get("decompiled_functions", []) or []
        if str(row.get("name", "")) in selected_functions
        or str(row.get("function_id", "")) in context_function_ids
    ]
    llm_packet = {
        **{
            key: value
            for key, value in packet.items()
            if key
            not in {
                "unchanged_alert",
                "decompiled_functions",
                "upstream_hardware_sources",
                "runtime_hardware_sources",
            }
        },
        "decompiled_functions": decompiled_functions,
        "upstream_hardware_sources": [
            {
                "id": row.get("id", ""),
                "label": row.get("label", ""),
                "function": row.get("function", ""),
                "site_id": row.get("site_id", ""),
                "source_object_id": row.get("source_object_id", ""),
                "proof": {
                    "kind": (row.get("proof", {}) or {}).get("kind", ""),
                    "register_address": (row.get("proof", {}) or {}).get(
                        "register_address", ""
                    ),
                    "register_role": (row.get("proof", {}) or {}).get(
                        "register_role", ""
                    ),
                },
            }
            for row in packet.get("upstream_hardware_sources", []) or []
        ],
        "alert_artifact": {
            "chain_id": alert.get("chain_id", ""),
            "sha256": hashlib.sha256(
                json.dumps(alert, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "note": "The stored Alert is unchanged; only graph-search enumeration is omitted from this planning view.",
        },
        "alert_view": alert_view,
    }
    return (
        "Produce an Execution Plan matching this contract:\n"
        + json.dumps(contract, indent=2, sort_keys=True)
        + "\n\nEvidence packet:\n"
        + json.dumps(llm_packet, sort_keys=True, separators=(",", ":"))
    )


def repair_prompt(
    candidate: dict[str, Any],
    error: str,
    packet: dict[str, Any],
    binary_sha256: str,
) -> str:
    required_transactions = max(
        (
            len(row.get("calls_in_instruction_order", []) or [])
            for row in packet.get("source_call_sequence", []) or []
        ),
        default=1,
    )
    src_facts = [
        {
            "fact_id": row.get("fact_id"),
            "offset_candidates": row.get("offset_candidates"),
        }
        for row in packet.get("payload_layout_facts", []) or []
        if row.get("role") == "src"
    ]
    field_facts = [
        {
            "fact_id": row.get("fact_id"),
            "role": row.get("role"),
            "offset": row.get("offset"),
            "size": row.get("size"),
            "value": row.get("value"),
            "controls_selected_effect": row.get("controls_selected_effect", False),
        }
        for row in packet.get("payload_layout_facts", []) or []
        if row.get("role") in {"packet_type", "len"}
    ]
    transaction_facts = [
        dependency
        for sequence in packet.get("source_call_sequence", []) or []
        for dependency in sequence.get("inter_transaction_dependencies", []) or []
    ]
    return (
        "Repair the rejected Execution Plan. Return only one complete JSON object. "
        "Do not explain. Keep exactly the allowed top-level and nested keys.\n"
        f"Verifier error: {error}\n"
        f"Allowed top-level keys: {sorted(PLAN_KEYS)}\n"
        "input_template keys: template_id, byte_length, fill_byte, payload_start, "
        "payload_start_evidence_ref, fields, concretization_limit.\n"
        "field keys: name, role, offset, size, encoding, candidates, evidence_ref. "
        "Integer encodings require integer candidates, not hex strings; candidates cannot be empty.\n"
        "Do not create a role=src field: payload_start represents the Source pointer offset. "
        f"The sum of all concretization_limit values cannot exceed {MAX_CONCRETE_INPUTS}.\n"
        "Every template byte_length is an integer from 1 through 4096. A receive call with "
        "an exact constant length argument must use exactly that byte_length.\n"
        "event keys: event_id, kind, order, template_id, call_index, transaction_group, "
        "register_address, irq, trigger_address. "
        "Event orders are unique. ordering_constraints and unresolved_assumptions contain strings.\n"
        f"The static call sequence requires at least {required_transactions} ordered "
        "SOURCE_PAYLOAD events in every transaction_group. Use contiguous transaction_group "
        "values starting at zero; restart call_index at zero in each group and model each "
        "receive call in the supplied order. Every group must contain call_index values "
        "0 through static_call_count-1. For example, two static receive calls repeated for "
        "two dynamic frames require four events: (group 0, calls 0/1), then "
        "(group 1, calls 0/1). Preliminary "
        "transactions may use role=other and payload_start=null; the selected transaction uses "
        "the exact packet_type/len/src facts below.\n"
        "A preliminary transaction must satisfy explicit local Checks in the supplied decompiled "
        "function that dominate the next receive call; do not choose a field value that returns "
        "before that call.\n"
        "For every inter-transaction fact below, add one role=header field to the producer "
        "template at the exact offset/size and cite fact_id. If consumer_relation is AFFINE_ADD, "
        "choose a positive consumer byte_length and set the producer field candidate to "
        "consumer byte_length minus the stated constant. Do not cover that byte with a larger "
        "catch-all field.\n"
        f"binary_sha256: {binary_sha256}\n"
        "Allowed payload_start facts (payload_start_evidence_ref must be one exact fact_id):\n"
        + json.dumps(src_facts, separators=(",", ":"))
        + "\nAllowed field facts (field evidence_ref must be one exact fact_id):\n"
        + json.dumps(field_facts, separators=(",", ":"))
        + "\nInter-transaction facts:\n"
        + json.dumps(transaction_facts, separators=(",", ":"))
        + "\n"
        "Exact payload facts:\n"
        + json.dumps(packet.get("payload_layout_facts", []), separators=(",", ":"))
        + "\nSource call sequence:\n"
        + json.dumps(packet.get("source_call_sequence", []), separators=(",", ":"))
        + "\nRejected JSON:\n"
        + json.dumps(candidate, separators=(",", ":"))
    )


def load_sourceagent(root: Path) -> None:
    try:
        from dotenv import load_dotenv

        load_dotenv(root / ".env")
    except ImportError:
        pass
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))


async def call_llm(prompt: str, sourceagent_root: Path, model: str | None) -> str:
    load_sourceagent(sourceagent_root)
    from sourceagent.llm.llm import LLM

    llm = LLM(model=model)
    # MiniMax M2.7 may spend most of a 4K completion budget on internal
    # reasoning for a long evidence packet and return no visible JSON.
    llm.config.max_tokens = max(int(llm.config.max_tokens), 16384)
    try:
        llm.update_config(temperature=0.0)
    except Exception:
        pass
    last_status = ""
    for attempt in range(2):
        response = await asyncio.wait_for(
            llm.generate(
                system_prompt=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                metadata={
                    "analysis_stage": "ct-mini-execution-plan-v1",
                    "attempt": attempt + 1,
                },
            ),
            timeout=180,
        )
        content = str(response.content or "").strip()
        if content:
            return content
        last_status = f"finish_reason={response.finish_reason}, model={response.model}"
    raise RuntimeError(f"LLM returned no execution plan after retry: {last_status}")


def parse_model_json(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    value = json.loads(normalize_bare_hex_literals(stripped))
    if not isinstance(value, dict):
        raise ValueError("model response is not a JSON object")
    return value


def normalize_bare_hex_literals(text: str) -> str:
    """Normalize JSON5-style bare hex integers without touching strings."""
    output: list[str] = []
    index = 0
    in_string = False
    escaped = False
    while index < len(text):
        char = text[index]
        if in_string:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
            output.append(char)
            index += 1
            continue
        if text[index : index + 2].lower() == "0x":
            end = index + 2
            while end < len(text) and text[end] in "0123456789abcdefABCDEF":
                end += 1
            if end > index + 2:
                output.append(str(int(text[index:end], 16)))
                index = end
                continue
        output.append(char)
        index += 1
    return "".join(output)


def assert_no_forbidden_inputs(paths: list[Path]) -> None:
    for path in paths:
        lower = str(path).lower().replace("\\", "/")
        if any(marker in lower for marker in FORBIDDEN_EVIDENCE_MARKERS):
            raise ValueError(f"forbidden vulnerability-answer evidence path: {path}")


def merge_execution_context(
    packet: dict[str, Any], context_packet: dict[str, Any]
) -> dict[str, Any]:
    """Merge only read-only runtime context; the stored Alert remains unchanged."""
    merged = dict(packet)
    context = context_packet.get("execution_context")
    if isinstance(context, dict):
        merged["execution_context"] = context
    functions = {
        str(row.get("function_id", "")): row
        for row in merged.get("decompiled_functions", []) or []
        if row.get("function_id")
    }
    for row in context_packet.get("decompiled_functions", []) or []:
        function_id = str(row.get("function_id", ""))
        if function_id:
            functions.setdefault(function_id, row)
    merged["decompiled_functions"] = list(functions.values())
    return merged


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reviewed-alerts", required=True, type=Path)
    parser.add_argument("--chains", required=True, type=Path)
    parser.add_argument("--sinks", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--channel-graph", required=True, type=Path)
    parser.add_argument("--program-facts", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--functions-jsonl", required=True, type=Path)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--alert-id")
    parser.add_argument(
        "--sourceagent-root", type=Path, default=ROOT
    )
    parser.add_argument("--model")
    parser.add_argument("--response-file", type=Path)
    parser.add_argument("--execution-context", type=Path)
    parser.add_argument("--evidence-out", type=Path)
    parser.add_argument("--raw-response-out", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    assert_no_forbidden_inputs(
        [
            args.reviewed_alerts,
            args.chains,
            args.sinks,
            args.sources,
            args.channel_graph,
            args.program_facts,
            args.binary,
            args.functions_jsonl,
            *([args.execution_context] if args.execution_context else []),
        ]
    )

    queue_entries = reviewed_validation_entries(load_json(args.reviewed_alerts))
    selections = [alert for _queue, alert in queue_entries]
    if args.alert_id:
        selections = [row for row in selections if row.get("alert_id") == args.alert_id]
    if len(selections) != 1:
        raise ValueError(
            f"planner requires exactly one queued TruPoC Alert, got {len(selections)}"
        )
    packet = build_evidence_packet(
        selection=selections[0],
        chains_doc=load_json(args.chains),
        sinks_doc=load_json(args.sinks),
        sources_doc=load_json(args.sources),
        channel_graph_doc=load_json(args.channel_graph),
        program_facts_doc=load_json(args.program_facts),
        binary=args.binary,
        functions_jsonl=args.functions_jsonl,
    )
    if args.execution_context:
        packet = merge_execution_context(packet, load_json(args.execution_context))
    if args.evidence_out:
        write_json(args.evidence_out, packet)
    prompt = prompt_for_packet(packet, args.binary_sha256)
    validation_error = ""
    plan: dict[str, Any] | None = None
    # One initial plan and one verifier-guided correction are allowed. Runtime
    # feedback never enters this planning loop.
    attempts = MAX_VERIFIER_ATTEMPTS
    response_text = ""
    rejected_candidate: dict[str, Any] | None = None
    for attempt in range(attempts):
        if args.response_file and attempt == 0:
            response_text = args.response_file.read_text(encoding="utf-8")
        else:
            attempt_prompt = (
                repair_prompt(
                    rejected_candidate, validation_error, packet, args.binary_sha256
                )
                if validation_error and rejected_candidate is not None
                else prompt
            )
            response_text = asyncio.run(
                call_llm(attempt_prompt, args.sourceagent_root, args.model)
            )
        if args.raw_response_out:
            args.raw_response_out.parent.mkdir(parents=True, exist_ok=True)
            args.raw_response_out.write_text(response_text, encoding="utf-8")
        try:
            candidate_plan = parse_model_json(response_text)
            rejected_candidate = candidate_plan
            candidate_plan = resolve_plan_evidence(candidate_plan, packet)
            validate_plan(
                candidate_plan, packet=packet, binary_sha256=args.binary_sha256
            )
            plan = candidate_plan
            break
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            validation_error = str(error)
    if plan is None:
        raise ValueError(
            f"LLM execution plan remained invalid after {attempts} attempt(s): "
            f"{validation_error}"
        )
    write_json(args.out, plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
