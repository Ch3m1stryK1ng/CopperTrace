#!/usr/bin/env python3
"""Propagate admitted Source lineage into values and memory objects.

This module deliberately does not discover Sources.  It consumes accepted
Source definitions plus already recovered High P-code effects and records
where those definitions are still represented as bytes or object references.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from typing import Any

import dataflow_objects
import memory_access_facts


DATA_VALUE_TRANSFER_OPS = {
    "BOOL_AND",
    "BOOL_NEGATE",
    "BOOL_OR",
    "BOOL_XOR",
    "CAST",
    "COPY",
    "FLOAT_ABS",
    "FLOAT_ADD",
    "FLOAT_CEIL",
    "FLOAT_DIV",
    "FLOAT_EQUAL",
    "FLOAT_FLOAT2FLOAT",
    "FLOAT_FLOOR",
    "FLOAT_INT2FLOAT",
    "FLOAT_LESS",
    "FLOAT_LESSEQUAL",
    "FLOAT_MULT",
    "FLOAT_NAN",
    "FLOAT_NEG",
    "FLOAT_NOTEQUAL",
    "FLOAT_ROUND",
    "FLOAT_SQRT",
    "FLOAT_SUB",
    "FLOAT_TRUNC",
    "INDIRECT",
    "INT_2COMP",
    "INT_ADD",
    "INT_AND",
    "INT_CARRY",
    "INT_DIV",
    "INT_EQUAL",
    "INT_LEFT",
    "INT_LESS",
    "INT_LESSEQUAL",
    "INT_MULT",
    "INT_NEGATE",
    "INT_NOTEQUAL",
    "INT_OR",
    "INT_REM",
    "INT_RIGHT",
    "INT_SBORROW",
    "INT_SCARRY",
    "INT_SDIV",
    "INT_SEXT",
    "INT_SLESS",
    "INT_SLESSEQUAL",
    "INT_SREM",
    "INT_SRIGHT",
    "INT_SUB",
    "INT_XOR",
    "INT_ZEXT",
    "MULTIEQUAL",
    "PIECE",
    "PTRADD",
    "PTRSUB",
    "SUBPIECE",
}

OBJECT_REFERENCE_TRANSFER_OPS = {
    "CAST",
    "COPY",
    "MULTIEQUAL",
    "PTRADD",
    "PTRSUB",
}


def _association_id(parts: tuple[str, ...]) -> str:
    token = hashlib.sha256("|".join(parts).encode()).hexdigest()[:20]
    return f"source-association:{token}"


def _call_actuals(op: dict[str, Any]) -> list[dict[str, Any]]:
    inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
    argument_ids = [
        str(item)
        for item in list(dict(op.get("call", {}) or {}).get("argument_value_ids", []) or [])
        if str(item)
    ]
    if argument_ids:
        by_value = {str(item.get("value_id", "")): item for item in inputs}
        resolved = [by_value[value_id] for value_id in argument_ids if value_id in by_value]
        if len(resolved) == len(argument_ids):
            return resolved
    return inputs[1:] if inputs else []


def _formal_atom(function: dict[str, Any], slot: int) -> str:
    candidates: set[str] = set()
    for parameter in list(function.get("parameters", []) or []):
        parameter = dict(parameter or {})
        candidate_slot = parameter.get(
            "parameter_slot", parameter.get("index")
        )
        if candidate_slot == slot and str(parameter.get("value_id", "")):
            candidates.add(str(parameter["value_id"]))
    for op in list(function.get("pcode_ops", []) or []):
        nodes = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
        if isinstance(op.get("output"), dict):
            nodes.append(dict(op["output"]))
        for node in nodes:
            if (
                node.get("parameter_slot") == slot
                and bool(node.get("is_input"))
                and str(node.get("value_id", ""))
            ):
                candidates.add(str(node["value_id"]))
    return next(iter(candidates)) if len(candidates) == 1 else ""


def _source_definition_ids(
    sources: dict[str, Any],
) -> tuple[dict[str, str], dict[str, str]]:
    source_to_definition: dict[str, str] = {}
    definition_to_source: dict[str, str] = {}
    for definition in list(sources.get("source_definitions", []) or []):
        definition = dict(definition or {})
        source_id = str(definition.get("source_id", ""))
        definition_id = str(definition.get("source_definition_id", ""))
        if source_id and definition_id:
            source_to_definition[source_id] = definition_id
            definition_to_source[definition_id] = source_id
    return source_to_definition, definition_to_source


def _nodes_by_atom(
    functions: dict[str, dict[str, Any]],
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Index the original High P-code varnodes used by each function."""

    result: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    seen: set[tuple[str, str, str, str]] = set()
    for function_id, function in functions.items():
        nodes = [
            dict(parameter or {})
            for parameter in list(function.get("parameters", []) or [])
        ]
        for op in list(function.get("pcode_ops", []) or []):
            nodes.extend(
                dict(item or {})
                for item in list(op.get("inputs", []) or [])
            )
            if isinstance(op.get("output"), dict):
                nodes.append(dict(op["output"]))
        for node in nodes:
            atom_id = dataflow_objects.identity(node)
            if not atom_id:
                continue
            key = (
                function_id,
                atom_id,
                str(node.get("def_site_id", "")),
                str(node.get("high_data_type", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            result[(function_id, atom_id)].append(node)
    return dict(result)


def _binding_roots(binding: dict[str, Any]) -> set[str]:
    region = dict(binding.get("region", {}) or {})
    return {
        str(binding.get("object_id", "")),
        str(binding.get("base_object_id", "")),
        str(binding.get("root_object_id", "")),
        str(region.get("object_id", "")),
        str(region.get("base_object_id", "")),
    } - {""}


def _memory_read_relation(
    association_region: dict[str, Any],
    read: memory_access_facts.ReadFact,
) -> str:
    """Classify one LOAD against a Source-associated memory Region."""

    if not association_region:
        return "MAY_OVERLAP"
    offset = association_region.get("offset")
    extent = association_region.get(
        "extent", association_region.get("size")
    )
    if not isinstance(offset, int) or not isinstance(extent, int) or extent <= 0:
        return "MAY_OVERLAP"
    if read.selector_terms:
        return "MAY_OVERLAP"
    if not isinstance(read.region_offset, int) or not isinstance(
        read.region_extent, int
    ):
        return "MAY_OVERLAP"
    left = (offset, offset + extent)
    right = (
        int(read.region_offset),
        int(read.region_offset) + int(read.region_extent),
    )
    return (
        "EXACT_OVERLAP"
        if max(left[0], right[0]) < min(left[1], right[1])
        else "DISJOINT"
    )


def _binding_region(binding: dict[str, Any]) -> dict[str, Any]:
    region = dict(binding.get("region", {}) or {})
    object_id = str(binding.get("object_id", "") or region.get("object_id", ""))
    base_object_id = str(
        binding.get("base_object_id", "")
        or binding.get("root_object_id", "")
        or region.get("base_object_id", "")
        or object_id
    )
    if object_id:
        region["object_id"] = object_id
    if base_object_id:
        region["base_object_id"] = base_object_id
    region.setdefault("offset", 0)
    region.setdefault("extent", "unknown")
    return region


def _explicit_state_transfers(
    functions: dict[str, dict[str, Any]],
    call_edges: list[dict[str, Any]] | None = None,
) -> tuple[
    dict[tuple[str, str], list[dict[str, Any]]],
    dict[tuple[str, str], list[dict[str, Any]]],
]:
    """Build separate data-value and pointer-reference transfer graphs."""

    value_transfers: dict[
        tuple[str, str], list[dict[str, Any]]
    ] = defaultdict(list)
    reference_transfers: dict[
        tuple[str, str], list[dict[str, Any]]
    ] = defaultdict(list)
    returns_by_function: dict[str, list[tuple[str, str]]] = defaultdict(list)
    targets_by_site: dict[str, set[str]] = defaultdict(set)
    for edge in list(call_edges or []):
        target_id = str(dict(edge or {}).get("dst_node_id", ""))
        site_id = str(dict(edge or {}).get("site_id", ""))
        if site_id and target_id and not target_id.startswith("unknown-call-target:"):
            targets_by_site[site_id].add(target_id)
    for function_id, function in functions.items():
        for op in list(function.get("pcode_ops", []) or []):
            mnemonic = str(op.get("mnemonic", ""))
            site_id = str(op.get("site_id", ""))
            output = dict(op.get("output", {}) or {})
            output_atom = dataflow_objects.identity(output)
            raw_inputs = [
                dict(item or {})
                for item in list(op.get("inputs", []) or [])
            ]
            value_inputs = [
                item for item in raw_inputs if not bool(item.get("is_constant"))
            ]
            if mnemonic in DATA_VALUE_TRANSFER_OPS and output_atom:
                for item in value_inputs:
                    input_atom = dataflow_objects.identity(item)
                    if input_atom:
                        value_transfers[(function_id, input_atom)].append(
                            {
                                "function_id": function_id,
                                "atom_id": output_atom,
                                "relation_kind": f"SSA_{mnemonic}",
                                "site_id": site_id,
                            }
                        )
            if mnemonic in OBJECT_REFERENCE_TRANSFER_OPS and output_atom:
                reference_inputs = raw_inputs
                if mnemonic in {"CAST", "COPY", "PTRADD", "PTRSUB"}:
                    # For pointer arithmetic only the base pointer preserves
                    # pointee identity. Index/offset operands do not.
                    reference_inputs = raw_inputs[:1]
                required_atoms = [
                    dataflow_objects.identity(item) for item in raw_inputs
                ]
                for item in reference_inputs:
                    if bool(item.get("is_constant")):
                        continue
                    input_atom = dataflow_objects.identity(item)
                    if input_atom:
                        reference_transfers[(function_id, input_atom)].append(
                            {
                                "function_id": function_id,
                                "atom_id": output_atom,
                                "relation_kind": f"SSA_{mnemonic}",
                                "site_id": site_id,
                                "mnemonic": mnemonic,
                                "required_input_atoms": required_atoms
                                if mnemonic == "MULTIEQUAL"
                                else [],
                            }
                        )
            if mnemonic == "RETURN":
                for item in (
                    value_inputs[1:] if len(value_inputs) > 1 else value_inputs
                ):
                    atom_id = dataflow_objects.identity(item)
                    if atom_id:
                        returns_by_function[function_id].append((atom_id, site_id))

    for caller_id, caller in functions.items():
        for op in list(caller.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) not in {"CALL", "CALLIND"}:
                continue
            site_id = str(op.get("site_id", ""))
            target_ids = set(targets_by_site.get(site_id, set()))
            direct_target = str(
                dict(op.get("call", {}) or {}).get("target_function_id", "")
            )
            if direct_target:
                target_ids.add(direct_target)
            for target_id in sorted(target_ids):
                target = functions.get(target_id)
                if target is None:
                    continue
                for slot, actual in enumerate(_call_actuals(op)):
                    actual_atom = dataflow_objects.identity(actual)
                    formal_atom = _formal_atom(target, slot)
                    if actual_atom and formal_atom:
                        transfer = {
                            "function_id": target_id,
                            "atom_id": formal_atom,
                            "relation_kind": "RESOLVED_CALL_ACTUAL_FORMAL",
                            "site_id": site_id,
                        }
                        value_transfers[(caller_id, actual_atom)].append(transfer)
                        reference_transfers[(caller_id, actual_atom)].append(
                            dict(transfer)
                        )
                output_atom = dataflow_objects.identity(
                    dict(op.get("output", {}) or {})
                )
                if output_atom:
                    for return_atom, return_site in returns_by_function.get(
                        target_id, []
                    ):
                        transfer = {
                            "function_id": caller_id,
                            "atom_id": output_atom,
                            "relation_kind": "RESOLVED_CALL_RETURN",
                            "site_id": site_id,
                            "return_site_id": return_site,
                        }
                        value_transfers[(target_id, return_atom)].append(transfer)
                        reference_transfers[(target_id, return_atom)].append(
                            dict(transfer)
                        )
    return dict(value_transfers), dict(reference_transfers)


def build_source_associations(
    program_facts: dict[str, Any],
    sources: dict[str, Any],
    *,
    value_provenance: dict[
        tuple[str, str], dict[str, dict[str, Any]]
    ],
    channel_edges: list[dict[str, Any]],
    runtime: dataflow_objects.RuntimeObjectIndex,
    seed_associations: list[dict[str, Any]] | None = None,
    access_index: memory_access_facts.MemoryAccessFactIndex | None = None,
    primitive_memory_effects: list[dict[str, Any]] | None = None,
    call_output_effects: list[dict[str, Any]] | None = None,
    call_edges: list[dict[str, Any]] | None = None,
    max_channel_depth: int = 8,
    max_steps: int = 50000,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Build a fixed-point Source association index.

    VALUE associations come from the existing exact High P-code provenance
    engine.  MEMORY_CONTENT associations come from body-proved Region writes.
    OBJECT_REFERENCE associations are added when a pointer actual refers to an
    object whose content already carries a Source definition.
    """

    functions = {
        str(function.get("function_id", "")): function
        for function in list(program_facts.get("functions", []) or [])
        if str(function.get("function_id", ""))
    }
    source_to_definition, definition_to_source = _source_definition_ids(sources)
    definition_decisions = {
        str(dict(definition or {}).get("source_definition_id", "")): str(
            dict(definition or {}).get("decision", "")
        )
        for definition in list(sources.get("source_definitions", []) or [])
    }
    nodes_by_atom = _nodes_by_atom(functions)
    rows: dict[tuple[Any, ...], dict[str, Any]] = {}
    rows_by_id: dict[str, dict[str, Any]] = {}
    reference_lineages_by_atom: dict[
        tuple[str, str], set[tuple[str, str]]
    ] = defaultdict(set)
    blockers: list[dict[str, Any]] = []
    queue: deque[tuple[Any, ...]] = deque()
    calls_to_function: dict[str, list[tuple[str, dict[str, Any]]]] = (
        defaultdict(list)
    )
    loads_by_address_atom: dict[
        tuple[str, str], list[dict[str, Any]]
    ] = defaultdict(list)
    targets_by_site: dict[str, set[str]] = defaultdict(set)
    for edge in list(call_edges or []):
        edge = dict(edge or {})
        site_id = str(edge.get("site_id", ""))
        target_id = str(edge.get("dst_node_id", ""))
        if site_id and target_id and not target_id.startswith("unknown-call-target:"):
            targets_by_site[site_id].add(target_id)

    for caller_id, caller in functions.items():
        for op in list(caller.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) == "LOAD":
                inputs = [
                    dict(item or {})
                    for item in list(op.get("inputs", []) or [])
                ]
                output = dict(op.get("output", {}) or {})
                address_atom = (
                    dataflow_objects.identity(inputs[-1]) if inputs else ""
                )
                loaded_atom = dataflow_objects.identity(output)
                if address_atom and loaded_atom:
                    loads_by_address_atom[(caller_id, address_atom)].append(
                        {
                            "site_id": str(op.get("site_id", "")),
                            "loaded_atom_id": loaded_atom,
                        }
                    )
            if str(op.get("mnemonic", "")) not in {"CALL", "CALLIND"}:
                continue
            site_id = str(op.get("site_id", ""))
            target_ids = set(targets_by_site.get(site_id, set()))
            direct_target = str(
                dict(op.get("call", {}) or {}).get("target_function_id", "")
            )
            if direct_target:
                target_ids.add(direct_target)
            for target_id in target_ids:
                calls_to_function[target_id].append((caller_id, op))

    def add(
        *,
        source_definition_id: str,
        source_id: str,
        state_kind: str,
        function_id: str = "",
        atom_id: str = "",
        object_id: str = "",
        region: dict[str, Any] | None = None,
        pointee_object_id: str = "",
        predecessor_id: str = "",
        relation_kind: str,
        site_id: str = "",
        precision: str = "EXACT",
        evidence: dict[str, Any] | None = None,
        channel_depth: int = 0,
        source_output_role: str = "",
        extent_for_role: str = "",
    ) -> bool:
        normalized_region = dict(region or {})
        normalized_depth = max(0, int(channel_depth or 0))
        predecessor = rows_by_id.get(predecessor_id, {}) if predecessor_id else {}
        normalized_output_role = str(
            source_output_role or predecessor.get("source_output_role", "")
        )
        normalized_extent_for_role = str(
            extent_for_role or predecessor.get("extent_for_role", "")
        )
        if normalized_depth > max_channel_depth:
            blockers.append(
                {
                    "reason": "source_association_channel_depth_limit_reached",
                    "source_definition_id": source_definition_id,
                    "function_id": function_id,
                    "atom_id": atom_id,
                    "object_id": object_id,
                    "site_id": site_id,
                    "evidence": {
                        "channel_depth": normalized_depth,
                        "max_channel_depth": max_channel_depth,
                    },
                }
            )
            return False
        # Channel depth is a search cost, not part of the propagated data-flow
        # state.  Keeping one row per depth duplicates the same Source/value or
        # Source/Region association after every CCC round and can make the RDA
        # artifact grow geometrically.  The shortest, most precise witness
        # dominates longer witnesses for the same semantic state.
        key = (
            source_definition_id,
            state_kind,
            function_id,
            atom_id,
            object_id,
            pointee_object_id,
            str(normalized_region.get("base_object_id", "")),
            str(normalized_region.get("offset", "")),
            str(normalized_region.get("extent", normalized_region.get("size", ""))),
            normalized_output_role,
            normalized_extent_for_role,
        )
        if not source_definition_id:
            return False
        association_id = _association_id(tuple(str(item) for item in key))
        existing = rows.get(key)
        if existing is not None:
            existing_depth = int(existing.get("channel_depth", 0) or 0)
            existing_exact = str(existing.get("precision", "MAY")) == "EXACT"
            incoming_exact = str(precision or "MAY") == "EXACT"
            better_witness = normalized_depth < existing_depth or (
                normalized_depth == existing_depth
                and incoming_exact
                and not existing_exact
            )
            if not better_witness:
                return False
            existing.update(
                {
                    "predecessor_association_id": predecessor_id,
                    "relation_kind": relation_kind,
                    "site_id": site_id,
                    "precision": precision,
                    "channel_depth": normalized_depth,
                    "evidence": dict(evidence or {}),
                }
            )
            queue.append(key)
            return True
        rows[key] = {
            "association_id": association_id,
            "source_definition_id": source_definition_id,
            "source_id": source_id,
            "source_decision": definition_decisions.get(
                source_definition_id, ""
            ),
            "state_kind": state_kind,
            "function_id": function_id,
            "atom_id": atom_id,
            "object_id": object_id,
            "region": normalized_region,
            "pointee_object_id": pointee_object_id,
            "predecessor_association_id": predecessor_id,
            "relation_kind": relation_kind,
            "site_id": site_id,
            "precision": precision,
            "channel_depth": normalized_depth,
            "source_output_role": normalized_output_role,
            "extent_for_role": normalized_extent_for_role,
            "evidence": dict(evidence or {}),
        }
        rows_by_id[association_id] = rows[key]
        if (
            state_kind == "OBJECT_REFERENCE"
            and function_id
            and atom_id
            and pointee_object_id
        ):
            reference_lineages_by_atom[(function_id, atom_id)].add(
                (source_definition_id, pointee_object_id)
            )
        queue.append(key)
        return True

    for (function_id, value_id), definitions in sorted(value_provenance.items()):
        for definition_id, provenance in sorted(definitions.items()):
            add(
                source_definition_id=definition_id,
                source_id=definition_to_source.get(definition_id, ""),
                state_kind="VALUE",
                function_id=function_id,
                atom_id=value_id,
                relation_kind="LOCAL_OR_CALL_VALUE_PROVENANCE",
                precision="EXACT",
                evidence={"transfers": list(provenance.get("transfers", []) or [])},
                channel_depth=0,
            )

    # A Source that writes through an output pointer defines memory content,
    # not merely the pointer value. Resolve the reported output varnode back
    # to the concrete caller object before any forward propagation.
    for definition in list(sources.get("source_definitions", []) or []):
        definition = dict(definition or {})
        if str(definition.get("decision", "")) not in {
            "ACCEPT_DETERMINISTIC",
            "ACCEPT_HEURISTIC",
        }:
            continue
        definition_id = str(definition.get("source_definition_id", ""))
        source_id = str(definition.get("source_id", ""))
        function_id = str(definition.get("function_id", ""))
        for output in list(definition.get("outputs", []) or []):
            output = dict(output or {})
            output_kind = str(output.get("kind", ""))
            output_role = str(output.get("role", ""))
            output_extent_for_role = str(output.get("extent_for_role", ""))
            if output_kind == "scalar_value":
                scalar_atom_id = str(output.get("value_id", ""))
                if scalar_atom_id:
                    add(
                        source_definition_id=definition_id,
                        source_id=source_id,
                        state_kind="VALUE",
                        function_id=function_id,
                        atom_id=scalar_atom_id,
                        relation_kind="SOURCE_DEFINITION_SCALAR_OUTPUT",
                        site_id=str(definition.get("site_id", "")),
                        precision="EXACT",
                        evidence={
                            "binding_status": str(
                                output.get("binding_status", "")
                            )
                        },
                        channel_depth=0,
                        source_output_role=output_role,
                        extent_for_role=output_extent_for_role,
                    )
                continue
            if output_kind != "memory_object":
                continue
            atom_id = str(output.get("value_id", ""))
            resolved_bindings: dict[str, dict[str, Any]] = {}
            for node in nodes_by_atom.get((function_id, atom_id), []):
                binding = runtime.resolve(node, function_id)
                object_id = str((binding or {}).get("object_id", ""))
                if object_id:
                    resolved_bindings[object_id] = dict(binding or {})
            if len(resolved_bindings) != 1:
                blockers.append(
                    {
                        "reason": "source_memory_output_object_not_unique",
                        "source_definition_id": definition_id,
                        "source_id": source_id,
                        "function_id": function_id,
                        "atom_id": atom_id,
                        "evidence": {
                            "reported_object_id": str(
                                output.get("object_id", "")
                            ),
                            "resolved_object_ids": sorted(resolved_bindings),
                        },
                    }
                )
                continue
            binding = next(iter(resolved_bindings.values()))
            object_id = str(binding.get("object_id", ""))
            add(
                source_definition_id=definition_id,
                source_id=source_id,
                state_kind="MEMORY_CONTENT",
                function_id=function_id,
                atom_id=atom_id,
                object_id=object_id,
                region=_binding_region(binding),
                relation_kind="SOURCE_DEFINITION_MEMORY_OUTPUT",
                site_id=str(definition.get("site_id", "")),
                precision=str(binding.get("precision", "EXACT") or "EXACT"),
                evidence={
                    "binding_status": str(
                        output.get("binding_status", "")
                    ),
                    "reported_object_id": str(output.get("object_id", "")),
                    "runtime_binding": binding,
                },
                channel_depth=0,
                source_output_role=output_role,
                extent_for_role=output_extent_for_role,
            )

            parameter_slots = {
                int(node.get("parameter_slot"))
                for node in nodes_by_atom.get((function_id, atom_id), [])
                if isinstance(node.get("parameter_slot"), int)
            }
            if not parameter_slots:
                match = re.search(r"param:[^:]+:(\d+)", atom_id)
                if match:
                    parameter_slots.add(int(match.group(1)))
            if len(parameter_slots) != 1:
                continue
            output_slot = next(iter(parameter_slots))
            for caller_id, call_op in calls_to_function.get(function_id, []):
                actuals = _call_actuals(call_op)
                if output_slot >= len(actuals):
                    blockers.append(
                        {
                            "reason": "source_output_actual_missing",
                            "source_definition_id": definition_id,
                            "function_id": caller_id,
                            "site_id": str(call_op.get("site_id", "")),
                            "parameter_slot": output_slot,
                        }
                    )
                    continue
                actual = actuals[output_slot]
                actual_binding = runtime.resolve(actual, caller_id)
                actual_object_id = str(
                    (actual_binding or {}).get("object_id", "")
                )
                if not actual_object_id:
                    blockers.append(
                        {
                            "reason": "source_output_actual_object_unresolved",
                            "source_definition_id": definition_id,
                            "function_id": caller_id,
                            "site_id": str(call_op.get("site_id", "")),
                            "parameter_slot": output_slot,
                            "actual_atom_id": dataflow_objects.identity(actual),
                        }
                    )
                    continue
                add(
                    source_definition_id=definition_id,
                    source_id=source_id,
                    state_kind="MEMORY_CONTENT",
                    function_id=caller_id,
                    atom_id=dataflow_objects.identity(actual),
                    object_id=actual_object_id,
                    region=_binding_region(actual_binding or {}),
                    predecessor_id="",
                    relation_kind="SOURCE_OUTPUT_ACTUAL_BINDING",
                    site_id=str(call_op.get("site_id", "")),
                    precision=(
                        "EXACT"
                        if str(definition.get("decision", ""))
                        == "ACCEPT_DETERMINISTIC"
                        and str(
                            (actual_binding or {}).get("precision", "EXACT")
                        )
                        == "EXACT"
                        else "MAY"
                    ),
                    evidence={
                        "source_function_id": function_id,
                        "output_parameter_slot": output_slot,
                        "actual_binding": dict(actual_binding or {}),
                    },
                    channel_depth=0,
                )

    for edge in channel_edges:
        if str(edge.get("edge_kind", "")) != "CHANNEL_WRITE":
            continue
        source_ids = {
            str(item)
            for item in (
                list(edge.get("source_ids", []) or [])
                + [edge.get("source_id", "")]
            )
            if str(item)
        }
        for source_id in sorted(source_ids):
            definition_id = source_to_definition.get(source_id, "")
            if not definition_id:
                continue
            add(
                source_definition_id=definition_id,
                source_id=source_id,
                state_kind="MEMORY_CONTENT",
                function_id=str(edge.get("src_node_id", "")),
                atom_id=str(edge.get("value_atom_id", "")),
                object_id=str(edge.get("object_id", "")),
                region=dict(edge.get("region", {}) or {}),
                relation_kind="PRIMITIVE_OR_EXACT_REGION_WRITE",
                site_id=str(edge.get("site_id", "")),
                precision=str(edge.get("analysis_precision", "MAY") or "MAY"),
                evidence={"channel_edge_id": str(edge.get("edge_id", ""))},
                channel_depth=int(edge.get("channel_depth", 0) or 0),
            )

    for seed in list(seed_associations or []):
        seed = dict(seed or {})
        add(
            source_definition_id=str(seed.get("source_definition_id", "")),
            source_id=str(seed.get("source_id", "")),
            state_kind=str(seed.get("state_kind", "OBJECT_REFERENCE")),
            function_id=str(seed.get("function_id", "")),
            atom_id=str(seed.get("atom_id", "")),
            object_id=str(seed.get("object_id", "")),
            region=dict(seed.get("region", {}) or {}),
            pointee_object_id=str(seed.get("pointee_object_id", "")),
            predecessor_id=str(seed.get("predecessor_association_id", "")),
            relation_kind=str(
                seed.get("relation_kind", "CHANNEL_RELATION_TRANSFER")
            ),
            site_id=str(seed.get("site_id", "")),
            precision=str(seed.get("precision", "MAY")),
            evidence=dict(seed.get("evidence", {}) or {}),
            channel_depth=int(seed.get("channel_depth", 0) or 0),
        )

    value_transfers, reference_transfers = _explicit_state_transfers(
        functions, call_edges
    )
    call_actuals: list[dict[str, Any]] = []
    for caller_id, caller in functions.items():
        for op in list(caller.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) not in {"CALL", "CALLIND"}:
                continue
            site_id = str(op.get("site_id", ""))
            target_ids = set(targets_by_site.get(site_id, set()))
            direct_target = str(
                dict(op.get("call", {}) or {}).get("target_function_id", "")
            )
            if direct_target:
                target_ids.add(direct_target)
            for target_id in sorted(target_ids):
                target = functions.get(target_id)
                if target is None:
                    continue
                for slot, actual in enumerate(_call_actuals(op)):
                    binding = runtime.resolve(actual, caller_id)
                    roots = {
                        str((binding or {}).get("object_id", "")),
                        str((binding or {}).get("root_object_id", "")),
                    } - {""}
                    call_actuals.append(
                        {
                            "caller_function_id": caller_id,
                            "target_function_id": target_id,
                            "site_id": site_id,
                            "slot": slot,
                            "actual_atom_id": dataflow_objects.identity(actual),
                            "formal_atom_id": _formal_atom(target, slot),
                            "actual_object_id": str(
                                (binding or {}).get("object_id", "")
                            ),
                            "roots": roots,
                        }
                    )

    writes_by_atom: dict[
        tuple[str, str], list[memory_access_facts.WriteFact]
    ] = defaultdict(list)
    if access_index is not None:
        for fact in access_index.write_facts:
            writes_by_atom[(fact.function_id, fact.stored_atom_id)].append(fact)
    primitive_effect_rows = [
        dict(effect or {})
        for effect in list(primitive_memory_effects or [])
        if str(effect.get("effect_kind", "")) == "PRIMITIVE_MEMORY_COPY"
    ]
    call_output_effects_by_atom: dict[
        tuple[str, str], list[dict[str, Any]]
    ] = defaultdict(list)
    for raw_effect in list(call_output_effects or []):
        effect = dict(raw_effect or {})
        caller_id = str(effect.get("caller_function_id", ""))
        callee_id = str(effect.get("callee_function_id", ""))
        stored = dict(effect.get("stored_value", {}) or {})
        stored_atom = str(stored.get("atom_id", ""))
        if stored_atom:
            owner = (
                callee_id
                if str(stored.get("lineage_kind", ""))
                == "CALLEE_LOCAL_SSA_VALUE"
                else caller_id
            )
            if owner:
                call_output_effects_by_atom[(owner, stored_atom)].append(effect)
        for binding in list(effect.get("formal_value_bindings", []) or []):
            binding = dict(binding or {})
            atom_id = str(binding.get("atom_id", ""))
            if caller_id and atom_id:
                call_output_effects_by_atom[(caller_id, atom_id)].append(effect)

    steps = 0
    while queue and steps < max_steps:
        key = queue.popleft()
        steps += 1
        row = rows[key]
        state_kind = str(row.get("state_kind", ""))
        function_id = str(row.get("function_id", ""))
        atom_id = str(row.get("atom_id", ""))
        depth = int(row.get("channel_depth", 0) or 0)

        if state_kind in {"VALUE", "OBJECT_REFERENCE"} and function_id and atom_id:
            transfers = (
                reference_transfers
                if state_kind == "OBJECT_REFERENCE"
                else value_transfers
            )
            for transfer in transfers.get((function_id, atom_id), []):
                if (
                    state_kind == "OBJECT_REFERENCE"
                    and str(transfer.get("mnemonic", "")) == "MULTIEQUAL"
                ):
                    lineage = (
                        str(row.get("source_definition_id", "")),
                        str(row.get("pointee_object_id", "")),
                    )
                    required_atoms = [
                        str(item)
                        for item in list(
                            transfer.get("required_input_atoms", []) or []
                        )
                    ]
                    if (
                        not lineage[1]
                        or not required_atoms
                        or any(not item for item in required_atoms)
                        or any(
                            lineage
                            not in reference_lineages_by_atom.get(
                                (function_id, required_atom), set()
                            )
                            for required_atom in required_atoms
                        )
                    ):
                        continue
                add(
                    source_definition_id=str(row.get("source_definition_id", "")),
                    source_id=str(row.get("source_id", "")),
                    state_kind=state_kind,
                    function_id=str(transfer.get("function_id", "")),
                    atom_id=str(transfer.get("atom_id", "")),
                    pointee_object_id=str(row.get("pointee_object_id", "")),
                    predecessor_id=str(row.get("association_id", "")),
                    relation_kind=str(transfer.get("relation_kind", "")),
                    site_id=str(transfer.get("site_id", "")),
                    precision=str(row.get("precision", "MAY")),
                    evidence={
                        "return_site_id": str(
                            transfer.get("return_site_id", "")
                        )
                    },
                    channel_depth=depth,
                )

            if state_kind in {"OBJECT_REFERENCE", "VALUE"}:
                for load in loads_by_address_atom.get(
                    (function_id, atom_id), []
                ):
                    add(
                        source_definition_id=str(
                            row.get("source_definition_id", "")
                        ),
                        source_id=str(row.get("source_id", "")),
                        state_kind="VALUE",
                        function_id=function_id,
                        atom_id=str(load.get("loaded_atom_id", "")),
                        predecessor_id=str(row.get("association_id", "")),
                        relation_kind=(
                            "LOAD_THROUGH_SOURCE_OBJECT_REFERENCE"
                            if state_kind == "OBJECT_REFERENCE"
                            else "LOAD_THROUGH_SOURCE_VALUE_POINTER"
                        ),
                        site_id=str(load.get("site_id", "")),
                        precision=(
                            str(row.get("precision", "MAY"))
                            if state_kind == "OBJECT_REFERENCE"
                            else "MAY"
                        ),
                        evidence={
                            "address_atom_id": atom_id,
                            "pointee_object_id": str(
                                row.get("pointee_object_id", "")
                            ),
                        },
                        channel_depth=depth,
                    )

            for write in writes_by_atom.get((function_id, atom_id), []):
                region = {
                    "object_id": write.aggregate_object_id,
                    "base_object_id": write.base_object_id,
                    "offset": write.region_offset,
                    "extent": write.region_extent,
                    "field_path": list(write.field_path),
                    "selector_terms": list(write.selector_terms),
                }
                add(
                    source_definition_id=str(row.get("source_definition_id", "")),
                    source_id=str(row.get("source_id", "")),
                    state_kind=(
                        "OBJECT_REFERENCE"
                        if state_kind == "OBJECT_REFERENCE"
                        else "MEMORY_CONTENT"
                    ),
                    function_id=write.function_id,
                    atom_id=write.stored_atom_id,
                    object_id=write.aggregate_object_id,
                    region=region,
                    pointee_object_id=str(row.get("pointee_object_id", "")),
                    predecessor_id=str(row.get("association_id", "")),
                    relation_kind=(
                        "CONCRETE_STORE_REFERENCE"
                        if state_kind == "OBJECT_REFERENCE"
                        else "CONCRETE_STORE_VALUE"
                    ),
                    site_id=write.site_id,
                    precision=(
                        "MAY"
                        if write.recognition == "heuristic"
                        else str(row.get("precision", "EXACT"))
                    ),
                    evidence={"access_edge_id": write.access_edge_id},
                    channel_depth=depth,
                )

            for effect in call_output_effects_by_atom.get(
                (function_id, atom_id), []
            ):
                destination = dict(effect.get("destination", {}) or {})
                destination_object_id = str(destination.get("object_id", ""))
                if not destination_object_id:
                    continue
                effect_precision = str(
                    effect.get("analysis_precision", "EXACT") or "EXACT"
                )
                add(
                    source_definition_id=str(
                        row.get("source_definition_id", "")
                    ),
                    source_id=str(row.get("source_id", "")),
                    state_kind=(
                        "OBJECT_REFERENCE"
                        if state_kind == "OBJECT_REFERENCE"
                        else "MEMORY_CONTENT"
                    ),
                    function_id=str(effect.get("caller_function_id", "")),
                    atom_id=str(destination.get("actual_atom_id", "")),
                    object_id=destination_object_id,
                    region={
                        "object_id": destination_object_id,
                        "base_object_id": str(
                            destination.get(
                                "base_object_id", destination_object_id
                            )
                        ),
                        "offset": int(destination.get("offset", 0) or 0),
                        "extent": int(destination.get("extent", 1) or 1),
                        "region_id": str(destination.get("region_id", "")),
                    },
                    pointee_object_id=str(
                        row.get("pointee_object_id", "")
                    ),
                    predecessor_id=str(row.get("association_id", "")),
                    relation_kind="CALL_OUTPUT_EFFECT",
                    site_id=str(effect.get("call_site_id", "")),
                    precision=(
                        "EXACT"
                        if str(row.get("precision", "")) == "EXACT"
                        and effect_precision == "EXACT"
                        else "MAY"
                    ),
                    evidence={
                        "effect_id": str(effect.get("effect_id", "")),
                        "callee_function_id": str(
                            effect.get("callee_function_id", "")
                        ),
                        "callee_store_site_id": str(
                            effect.get("callee_store_site_id", "")
                        ),
                        "analysis_precision": effect_precision,
                    },
                    channel_depth=depth,
                )

        if state_kind in {"MEMORY_CONTENT", "OBJECT_REFERENCE"}:
            roots = {
                str(row.get("object_id", "")),
                str(row.get("pointee_object_id", "")),
                str(dict(row.get("region", {}) or {}).get("object_id", "")),
                str(dict(row.get("region", {}) or {}).get("base_object_id", "")),
            } - {""}
            if state_kind == "MEMORY_CONTENT" and access_index is not None:
                for aggregate_object_id, reads in (
                    access_index.reads_by_object.items()
                ):
                    if aggregate_object_id not in roots:
                        continue
                    for read in reads:
                        relation = _memory_read_relation(
                            dict(row.get("region", {}) or {}), read
                        )
                        if relation == "DISJOINT" or not read.loaded_atom_id:
                            continue
                        add(
                            source_definition_id=str(
                                row.get("source_definition_id", "")
                            ),
                            source_id=str(row.get("source_id", "")),
                            state_kind="VALUE",
                            function_id=read.function_id,
                            atom_id=read.loaded_atom_id,
                            object_id="",
                            predecessor_id=str(row.get("association_id", "")),
                            relation_kind=(
                                "CONCRETE_LOAD_FROM_SOURCE_MEMORY"
                            ),
                            site_id=read.site_id,
                            precision=(
                                "EXACT"
                                if str(row.get("precision", "")) == "EXACT"
                                and read.recognition != "heuristic"
                                and relation == "EXACT_OVERLAP"
                                else "MAY"
                            ),
                            evidence={
                                "access_edge_id": read.access_edge_id,
                                "aggregate_object_id": aggregate_object_id,
                                "region_relation": relation,
                            },
                            channel_depth=depth,
                        )
            for effect in primitive_effect_rows:
                source_binding = dict(effect.get("source", {}) or {})
                if not roots.intersection(_binding_roots(source_binding)):
                    continue
                destination_binding = dict(
                    effect.get("destination", {}) or {}
                )
                destination_object_id = str(
                    destination_binding.get("object_id", "")
                )
                destination_atom_id = str(
                    destination_binding.get("atom_id", "")
                    or destination_binding.get("value_id", "")
                )
                if not destination_object_id or not destination_atom_id:
                    continue
                effect_precision = str(
                    effect.get("effect_precision", "MAY_REGION")
                )
                add(
                    source_definition_id=str(
                        row.get("source_definition_id", "")
                    ),
                    source_id=str(row.get("source_id", "")),
                    state_kind="MEMORY_CONTENT",
                    function_id=str(effect.get("function_id", "")),
                    atom_id=destination_atom_id,
                    object_id=destination_object_id,
                    region=_binding_region(destination_binding),
                    predecessor_id=str(row.get("association_id", "")),
                    relation_kind="PROVED_PRIMITIVE_MEMORY_EFFECT",
                    site_id=str(effect.get("site_id", "")),
                    precision=(
                        "EXACT"
                        if (
                            str(row.get("precision", "")) == "EXACT"
                            and effect_precision == "EXACT"
                        )
                        else "MAY"
                    ),
                    evidence={
                        "effect_id": str(effect.get("effect_id", "")),
                        "effect_kind": str(effect.get("effect_kind", "")),
                        "effect_precision": effect_precision,
                    },
                    channel_depth=depth,
                )
            for actual in call_actuals if state_kind == "MEMORY_CONTENT" else []:
                if not roots.intersection(set(actual.get("roots", set()))):
                    continue
                pointee = str(
                    dict(row.get("region", {}) or {}).get(
                        "object_id", row.get("object_id", "")
                    )
                )
                add(
                    source_definition_id=str(row.get("source_definition_id", "")),
                    source_id=str(row.get("source_id", "")),
                    state_kind="OBJECT_REFERENCE",
                    function_id=str(actual.get("caller_function_id", "")),
                    atom_id=str(actual.get("actual_atom_id", "")),
                    object_id=str(actual.get("actual_object_id", "")),
                    pointee_object_id=pointee,
                    predecessor_id=str(row.get("association_id", "")),
                    relation_kind="SOURCE_ASSOCIATED_CALL_ACTUAL",
                    site_id=str(actual.get("site_id", "")),
                    precision=str(row.get("precision", "MAY")),
                    evidence={
                        "callee_function_id": str(
                            actual.get("target_function_id", "")
                        ),
                        "parameter_slot": int(actual.get("slot", 0) or 0),
                    },
                    channel_depth=depth,
                )

    if queue:
        blockers.append(
            {
                "reason": "source_association_budget_exhausted",
                "evidence": {
                    "max_steps": max_steps,
                    "association_count": len(rows),
                    "remaining_work_items": len(queue),
                },
            }
        )
    return (
        sorted(rows.values(), key=lambda row: str(row["association_id"])),
        blockers,
    )


def channel_relation_seeds(
    edges: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert admitted Channelgraph reads into next-hop association seeds."""

    seeds: list[dict[str, Any]] = []
    for edge in edges:
        if str(edge.get("edge_kind", "")) != "CHANNEL_READ":
            continue
        transfer = str(edge.get("transfer_semantics", ""))
        reference = dict(edge.get("reference_binding", {}) or {})
        lineage_ids = [
            str(item)
            for item in list(edge.get("source_lineage_ids", []) or [])
            if str(item)
        ]
        source_ids = [
            str(item)
            for item in (
                list(edge.get("source_ids", []) or [])
                + [edge.get("source_id", "")]
            )
            if str(item)
        ]
        if transfer not in {"MEMORY_CONTENT", "OBJECT_REFERENCE"} or not lineage_ids:
            continue
        next_depth = int(edge.get("channel_depth", 0) or 0) + 1
        for index, definition_id in enumerate(lineage_ids):
            seeds.append(
                {
                    "source_definition_id": definition_id,
                    "source_id": source_ids[min(index, len(source_ids) - 1)]
                    if source_ids
                    else "",
                    "state_kind": (
                        "OBJECT_REFERENCE"
                        if transfer == "OBJECT_REFERENCE"
                        else "VALUE"
                    ),
                    "function_id": str(edge.get("dst_node_id", "")),
                    "atom_id": str(
                        reference.get("consumer_atom_id", "")
                        or edge.get("loaded_atom_id", "")
                        or edge.get("value_atom_id", "")
                    ),
                    "object_id": str(edge.get("value_object_id", "")),
                    "pointee_object_id": str(
                        reference.get("pointee_object_id", "")
                    ),
                    "relation_kind": (
                        "CHANNEL_READ_OBJECT_REFERENCE"
                        if transfer == "OBJECT_REFERENCE"
                        else "CHANNEL_READ_MEMORY_CONTENT"
                    ),
                    "site_id": str(edge.get("site_id", "")),
                    "precision": str(edge.get("analysis_precision", "MAY")),
                    "channel_depth": next_depth,
                    "evidence": {
                        "channel_edge_id": str(edge.get("edge_id", "")),
                    },
                }
            )
    return seeds


def association_index(
    rows: list[dict[str, Any]],
) -> tuple[
    dict[tuple[str, str], list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    by_atom: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        function_id = str(row.get("function_id", ""))
        atom_id = str(row.get("atom_id", ""))
        if function_id and atom_id:
            by_atom[(function_id, atom_id)].append(row)
        for object_id in {
            str(row.get("object_id", "")),
            str(row.get("pointee_object_id", "")),
            str(dict(row.get("region", {}) or {}).get("object_id", "")),
        }:
            if object_id:
                by_object[object_id].append(row)
    return dict(by_atom), dict(by_object)
