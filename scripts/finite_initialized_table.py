#!/usr/bin/env python3
"""Bounded recovery of MMIO addresses through immutable pointer tables.

This module recognizes two deliberately narrow High P-code shapes::

    slot = PTRADD(table_base, selector, pointer_size)
    base = LOAD(slot)
    addr = INT_ADD(base, constant_offset)
    data = LOAD(addr)

and an initialized array-of-structures variant::

    slot = table_base + selector * structure_size + constant_field_offset
    base = LOAD(slot)
    addr = base + constant_register_offset
    data = LOAD(addr)

``table_base`` must be the exact start of an initialized, non-writable ELF
``STT_OBJECT``.  Its object extent and the proved constant stride supply the
finite selector domain.  The implementation only reads bytes already present
in the ELF; it does not use symbolic execution, names, source text, or
firmware-specific shortcuts.
"""

from __future__ import annotations

from typing import Any

import device_dispatch_resolver


SCHEMA_VERSION = "ct-mini-finite-initialized-table-v1"
DEFAULT_MAX_TABLE_ENTRIES = 256


def _parse_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def _value_id(node: dict[str, Any] | None) -> str:
    return str((node or {}).get("value_id", "") or (node or {}).get("object_id", ""))


def _literal(node: dict[str, Any] | None, *, allow_address: bool = False) -> int | None:
    node = dict(node or {})
    if bool(node.get("is_constant")):
        return _parse_int(node.get("offset"))
    if allow_address and bool(node.get("is_address")):
        if str(node.get("space", "")).lower() in {"", "ram", "mem", "memory"}:
            return _parse_int(node.get("offset"))
    return None


def _definition(
    node: dict[str, Any] | None,
    definitions: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    return definitions.get(_value_id(node))


_TRANSPARENT_OPS = {"CAST", "COPY", "INDIRECT"}


def _transparent_input(op: dict[str, Any]) -> dict[str, Any] | None:
    inputs = [dict(node or {}) for node in list(op.get("inputs", []) or [])]
    mnemonic = str(op.get("mnemonic", ""))
    if mnemonic in {"CAST", "COPY"} and len(inputs) == 1:
        return inputs[0]
    if mnemonic == "INDIRECT" and inputs:
        # High P-code INDIRECT carries an operation-reference as its second
        # input.  The first input is the value being forwarded.
        return inputs[0]
    if mnemonic == "MULTIEQUAL" and inputs:
        object_ids = {str(node.get("object_id", "")) for node in inputs}
        if len(object_ids) == 1 and "" not in object_ids:
            return inputs[0]
    return None


def _unwrap_node(
    node: dict[str, Any] | None,
    definitions: dict[str, dict[str, Any]],
    *,
    max_steps: int = 16,
) -> tuple[dict[str, Any], list[str]]:
    current = dict(node or {})
    sites: list[str] = []
    seen: set[str] = set()
    for _ in range(max_steps):
        value_id = _value_id(current)
        if not value_id or value_id in seen:
            break
        seen.add(value_id)
        op = definitions.get(value_id)
        if not op:
            break
        forwarded = _transparent_input(op)
        if forwarded is None:
            break
        sites.append(str(op.get("site_id", "")))
        current = forwarded
    return current, [site for site in sites if site]


def _unwrapped_definition(
    node: dict[str, Any] | None,
    definitions: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any] | None, list[str]]:
    unwrapped, sites = _unwrap_node(node, definitions)
    return definitions.get(_value_id(unwrapped)), sites


def _immutable_object_base(
    node: dict[str, Any],
    initialized_memory: device_dispatch_resolver.InitializedMemory,
) -> tuple[int | None, dict[str, Any]]:
    literal = _literal(node, allow_address=True)
    if literal is None:
        return None, {"reason": "table_base_is_not_constant_or_initialized_literal"}

    direct_extents = initialized_memory.exact_object_extents(literal)
    if len(direct_extents) == 1:
        return literal, {
            "kind": "direct_immutable_object_address",
            "literal_address": f"0x{literal:x}",
        }

    literal_region = initialized_memory.region_at(literal, initialized_memory.pointer_size)
    if literal_region is not None and not literal_region.writable:
        pointee = initialized_memory.read_ptr(literal)
        if pointee is not None and len(initialized_memory.exact_object_extents(pointee)) == 1:
            return pointee, {
                "kind": "initialized_pointer_literal",
                "literal_address": f"0x{literal:x}",
                "literal_value": f"0x{pointee:x}",
                "literal_region": literal_region.source,
            }

    # Preserve a syntactically exact direct base so the caller can report the
    # more useful `immutable_table_extent_not_unique` blocker.  No address is
    # enumerated unless the later exact-object and initialized-byte checks pass.
    return literal, {
        "kind": "direct_address_pending_extent_proof",
        "literal_address": f"0x{literal:x}",
    }


def _scaled_selector(
    node: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any] | None, int | None, str]:
    op, _ = _unwrapped_definition(node, definitions)
    if not op or str(op.get("mnemonic", "")) != "INT_MULT":
        return None, None, ""
    inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
    if len(inputs) != 2:
        return None, None, str(op.get("site_id", ""))
    constant_index = next(
        (index for index, item in enumerate(inputs) if _literal(item) is not None),
        None,
    )
    if constant_index is None:
        return None, None, str(op.get("site_id", ""))
    return inputs[1 - constant_index], _literal(inputs[constant_index]), str(
        op.get("site_id", "")
    )


def _structure_table_address(
    node: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
    initialized_memory: device_dispatch_resolver.InitializedMemory,
) -> dict[str, Any] | None:
    address_op, transparent_sites = _unwrapped_definition(node, definitions)
    if not address_op:
        return None
    mnemonic = str(address_op.get("mnemonic", ""))
    inputs = [dict(item or {}) for item in list(address_op.get("inputs", []) or [])]

    if mnemonic == "PTRADD" and len(inputs) == 3:
        stride = _literal(inputs[2])
        table_base, base_evidence = _immutable_object_base(inputs[0], initialized_memory)
        if table_base is None or stride is None:
            return None
        return {
            "table_base": table_base,
            "selector": inputs[1],
            "stride": stride,
            "field_offset": 0,
            "address_site_id": str(address_op.get("site_id", "")),
            "scaled_selector_site_id": "",
            "transparent_site_ids": transparent_sites,
            "base_evidence": base_evidence,
        }

    if mnemonic != "INT_ADD" or len(inputs) != 2:
        return None
    for scaled_index in (0, 1):
        selector, stride, scaled_site = _scaled_selector(
            inputs[scaled_index], definitions
        )
        if selector is None or stride is None:
            continue
        base_node, base_sites = _unwrap_node(inputs[1 - scaled_index], definitions)
        field_offset = 0
        base_op = definitions.get(_value_id(base_node))
        if base_op and str(base_op.get("mnemonic", "")) == "INT_ADD":
            base_inputs = [
                dict(item or {}) for item in list(base_op.get("inputs", []) or [])
            ]
            constant_index = next(
                (
                    index
                    for index, item in enumerate(base_inputs)
                    if _literal(item) is not None
                ),
                None,
            )
            if constant_index is not None and len(base_inputs) == 2:
                field_offset = int(_literal(base_inputs[constant_index]) or 0)
                base_node, nested_sites = _unwrap_node(
                    base_inputs[1 - constant_index], definitions
                )
                base_sites.extend(nested_sites)
        table_base, base_evidence = _immutable_object_base(
            base_node, initialized_memory
        )
        if table_base is None:
            continue
        return {
            "table_base": table_base,
            "selector": selector,
            "stride": stride,
            "field_offset": field_offset,
            "address_site_id": str(address_op.get("site_id", "")),
            "scaled_selector_site_id": scaled_site,
            "transparent_site_ids": transparent_sites + base_sites,
            "base_evidence": base_evidence,
        }
    return None


def _unresolved(reason: str, **evidence: Any) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "unresolved",
        "reason": reason,
        "address_candidates": [],
        "evidence": evidence,
    }


def enumerate_computed_mmio_load(
    load: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
    initialized_memory: device_dispatch_resolver.InitializedMemory | None,
    *,
    max_entries: int = DEFAULT_MAX_TABLE_ENTRIES,
) -> dict[str, Any]:
    """Enumerate address candidates for one restricted computed-MMIO LOAD.

    ``no_match`` means that the High P-code shape is absent.  ``unresolved``
    means that the shape is present but its ELF-backed finite-domain proof is
    incomplete.  Only ``enumerated`` carries addresses that a caller may
    submit to hardware metadata resolution.
    """

    load_inputs = list(load.get("inputs", []) or [])
    if str(load.get("mnemonic", "")) != "LOAD" or len(load_inputs) < 2:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "no_match",
            "reason": "final_operation_is_not_load",
            "address_candidates": [],
        }

    address_op, final_address_transparent_sites = _unwrapped_definition(
        dict(load_inputs[1] or {}), definitions
    )
    if not address_op or str(address_op.get("mnemonic", "")) != "INT_ADD":
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "no_match",
            "reason": "final_address_is_not_int_add",
            "address_candidates": [],
        }
    address_inputs = list(address_op.get("inputs", []) or [])
    if len(address_inputs) != 2:
        return _unresolved(
            "register_add_arity_not_two",
            final_load_site_id=str(load.get("site_id", "")),
            register_add_site_id=str(address_op.get("site_id", "")),
        )

    constant_index = next(
        (index for index, node in enumerate(address_inputs) if _literal(node) is not None),
        None,
    )
    if constant_index is None:
        return _unresolved(
            "register_offset_not_constant",
            final_load_site_id=str(load.get("site_id", "")),
            register_add_site_id=str(address_op.get("site_id", "")),
        )
    base_index = 1 - constant_index
    register_offset = _literal(address_inputs[constant_index])
    base_load, register_base_transparent_sites = _unwrapped_definition(
        dict(address_inputs[base_index] or {}), definitions
    )
    if not base_load or str(base_load.get("mnemonic", "")) != "LOAD":
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "no_match",
            "reason": "register_base_is_not_table_load",
            "address_candidates": [],
        }
    base_load_inputs = list(base_load.get("inputs", []) or [])
    if len(base_load_inputs) < 2:
        return _unresolved(
            "table_base_load_has_no_address",
            final_load_site_id=str(load.get("site_id", "")),
            table_load_site_id=str(base_load.get("site_id", "")),
        )

    if initialized_memory is None:
        return _unresolved(
            "initialized_elf_memory_unavailable",
            final_load_site_id=str(load.get("site_id", "")),
            table_load_site_id=str(base_load.get("site_id", "")),
        )

    pointer_size = int(initialized_memory.pointer_size)
    table_address = _structure_table_address(
        dict(base_load_inputs[1] or {}), definitions, initialized_memory
    )
    if table_address is None:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "no_match",
            "reason": "table_slot_is_not_supported_finite_address",
            "address_candidates": [],
        }
    scale = _parse_int(table_address.get("stride"))
    if scale is None or scale <= 0:
        return _unresolved(
            "table_stride_is_not_positive_constant",
            observed_stride=scale,
            table_address_site_id=str(table_address.get("address_site_id", "")),
        )
    field_offset = _parse_int(table_address.get("field_offset"))
    if field_offset is None or field_offset < 0 or field_offset + pointer_size > scale:
        return _unresolved(
            "table_pointer_field_exceeds_structure_stride",
            pointer_size=pointer_size,
            observed_stride=scale,
            field_offset=field_offset,
        )
    table_base = _parse_int(table_address.get("table_base"))
    if table_base is None:
        return _unresolved("table_base_is_not_resolved")

    extents = initialized_memory.exact_object_extents(table_base)
    if len(extents) != 1:
        return _unresolved(
            "immutable_table_extent_not_unique",
            table_base=f"0x{table_base:x}",
            matching_extent_count=len(extents),
            table_address_site_id=str(table_address.get("address_site_id", "")),
        )
    extent = extents[0]
    extent_size = int(extent.get("size", 0) or 0)
    if bool(extent.get("writable")):
        return _unresolved(
            "table_object_is_writable",
            table_base=f"0x{table_base:x}",
            table_extent=extent,
        )
    backing = initialized_memory.region_at(table_base, extent_size)
    if backing is None:
        return _unresolved(
            "table_bytes_not_initialized",
            table_base=f"0x{table_base:x}",
            table_extent=extent,
        )
    if backing.writable:
        return _unresolved(
            "table_backing_region_is_writable",
            table_base=f"0x{table_base:x}",
            table_extent=extent,
            backing_region=backing.source,
        )
    if extent_size <= 0 or extent_size % scale != 0:
        return _unresolved(
            "table_extent_is_not_stride_aligned",
            table_base=f"0x{table_base:x}",
            table_size=extent_size,
            table_stride=scale,
        )
    entry_count = extent_size // scale
    if entry_count > max_entries:
        return _unresolved(
            "finite_table_entry_budget_exceeded",
            table_base=f"0x{table_base:x}",
            entry_count=entry_count,
            max_entries=max_entries,
        )

    entries: list[dict[str, Any]] = []
    for index in range(entry_count):
        entry_address = table_base + index * scale + field_offset
        base_value = initialized_memory.read_ptr(entry_address)
        if base_value is None:
            return _unresolved(
                "table_entry_bytes_unavailable",
                table_base=f"0x{table_base:x}",
                table_entry_address=f"0x{entry_address:x}",
                table_index=index,
            )
        final_address = int(base_value) + int(register_offset)
        entries.append(
            {
                "index": index,
                "table_entry_address": f"0x{entry_address:x}",
                "base_address": f"0x{int(base_value):x}",
                "computed_address": f"0x{final_address:x}",
            }
        )

    peripheral_entries = [
        row
        for row in entries
        if 0x40000000 <= int(str(row["computed_address"]), 0) < 0x60000000
    ]
    if not peripheral_entries:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "no_match",
            "reason": "enumerated_addresses_are_not_peripheral_mmio",
            "address_candidates": [],
        }
    if len(peripheral_entries) != len(entries):
        return _unresolved(
            "table_contains_non_mmio_base",
            table_base=f"0x{table_base:x}",
            table_entries=entries,
        )

    addresses = sorted(
        {int(str(row["computed_address"]), 0) for row in peripheral_entries}
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "enumerated",
        "reason": "",
        "address_candidates": addresses,
        "proof_kind": (
            "finite_initialized_table_computed_mmio"
            if scale == pointer_size and field_offset == 0
            else "finite_initialized_struct_table_computed_mmio"
        ),
        "final_load_site_id": str(load.get("site_id", "")),
        "register_add_site_id": str(address_op.get("site_id", "")),
        "table_load_site_id": str(base_load.get("site_id", "")),
        "table_address_site_id": str(table_address.get("address_site_id", "")),
        "scaled_selector_site_id": str(
            table_address.get("scaled_selector_site_id", "")
        ),
        "transparent_site_ids": sorted(
            {
                *final_address_transparent_sites,
                *register_base_transparent_sites,
                *list(table_address.get("transparent_site_ids", []) or []),
            }
        ),
        "selector_value_id": _value_id(dict(table_address.get("selector", {}) or {})),
        "selector_domain": {
            "kind": "exact_immutable_table_extent",
            "entry_count": entry_count,
            "indices": [0, entry_count - 1],
        },
        "pointer_size": pointer_size,
        "table_stride": scale,
        "table_field_offset": field_offset,
        "register_offset": int(register_offset),
        "table_base": table_base,
        "table_base_evidence": dict(table_address.get("base_evidence", {}) or {}),
        "table_extent": extent,
        "table_entries": entries,
        "backing_region": {
            "source": backing.source,
            "start": f"0x{backing.start:x}",
            "end": f"0x{backing.end:x}",
            "writable": backing.writable,
        },
    }
