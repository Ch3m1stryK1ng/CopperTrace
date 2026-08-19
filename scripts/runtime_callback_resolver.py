#!/usr/bin/env python3
"""Recover runtime callback CALL relations from High P-code memory effects.

The resolver is deliberately name-independent.  It connects a function
pointer stored in a concrete Region to a later ``LOAD -> CALLIND`` from the
same Region.  Function-pointer values may arrive through bounded wrapper
actual/formal chains.  A singleton target is exact; a complete finite target
set is retained as MAY relations rather than collapsed to an arbitrary target.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict, deque
from typing import Any

import dataflow_objects
import memory_access_facts


TRANSPARENT_OPS = {
    "COPY",
    "CAST",
    "INDIRECT",
    "INT_ZEXT",
    "INT_SEXT",
    "SUBPIECE",
}


def _identity(node: dict[str, Any] | None) -> str:
    return dataflow_objects.identity(dict(node or {}))


def _parameter_slot(node: dict[str, Any]) -> int | None:
    slot = node.get("parameter_slot")
    return slot if isinstance(slot, int) else None


def _parse_address(node: dict[str, Any]) -> int | None:
    if str(node.get("space", "")) not in {"global", "ram", "const"} and not bool(
        node.get("is_address")
    ):
        return None
    raw = node.get("offset")
    try:
        return int(str(raw), 0)
    except (TypeError, ValueError):
        try:
            return int(str(raw), 16)
        except (TypeError, ValueError):
            return None


def _object_address(object_id: str) -> int | None:
    for token in str(object_id).split(":"):
        if not re.fullmatch(r"[0-9a-fA-F]{6,16}", token):
            continue
        try:
            return int(token, 16)
        except ValueError:
            continue
    return None


def _same_base_object(left: str, right: str) -> bool:
    if not left or not right:
        return False
    if left == right:
        return True
    left_address = _object_address(left)
    right_address = _object_address(right)
    return left_address is not None and left_address == right_address


def _access_path_offset(path: list[Any]) -> int | None:
    total = 0
    for raw in path:
        item = str(raw)
        if item == "deref":
            total = 0
            continue
        if item.startswith(("byte_offset:", "field_offset:")):
            try:
                total += int(item.split(":", 1)[1], 0)
            except ValueError:
                return None
            continue
        return None
    return total


def _site_address(site_id: str) -> int | None:
    parts = str(site_id).split(":")
    if len(parts) < 3:
        return None
    try:
        return int(parts[-2], 16)
    except ValueError:
        return None


def _call_actuals(op: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(item or {}) for item in list(op.get("inputs", []) or [])[1:]]


def _definitions(
    functions: dict[str, dict[str, Any]],
) -> tuple[
    dict[str, tuple[str, dict[str, Any]]],
    dict[str, tuple[str, dict[str, Any]]],
]:
    by_atom: dict[str, tuple[str, dict[str, Any]]] = {}
    by_site: dict[str, tuple[str, dict[str, Any]]] = {}
    for function_id, function in functions.items():
        for op in list(function.get("pcode_ops", []) or []):
            site_id = str(op.get("site_id", ""))
            if site_id:
                by_site[site_id] = (function_id, op)
            atom = _identity(dict(op.get("output", {}) or {}))
            if atom:
                by_atom[atom] = (function_id, op)
    return by_atom, by_site


def _definition(
    function_id: str,
    node: dict[str, Any],
    by_atom: dict[str, tuple[str, dict[str, Any]]],
    by_site: dict[str, tuple[str, dict[str, Any]]],
) -> dict[str, Any] | None:
    entry = by_atom.get(_identity(node))
    if entry and entry[0] == function_id:
        return entry[1]
    entry = by_site.get(str(node.get("def_site_id", "")))
    return entry[1] if entry and entry[0] == function_id else None


def _trace_function_values(
    function_id: str,
    node: dict[str, Any],
    *,
    function_by_entry: dict[int, str],
    literal_words: dict[int, int],
    by_atom: dict[str, tuple[str, dict[str, Any]]],
    by_site: dict[str, tuple[str, dict[str, Any]]],
    max_steps: int = 64,
) -> tuple[set[str], set[int], list[str]]:
    """Return concrete function targets and formal slots reaching ``node``."""

    targets: set[str] = set()
    formals: set[int] = set()
    proof_sites: list[str] = []
    queue: deque[dict[str, Any]] = deque([dict(node or {})])
    seen: set[str] = set()
    steps = 0
    while queue and steps < max_steps:
        current = queue.popleft()
        atom = _identity(current)
        if atom and atom in seen:
            continue
        if atom:
            seen.add(atom)
        steps += 1
        slot = _parameter_slot(current)
        if slot is not None:
            formals.add(slot)
            continue
        address = _parse_address(current)
        if address is not None:
            direct_target = function_by_entry.get(address & ~1)
            if direct_target:
                targets.add(direct_target)
                continue
            # Address-tied High P-code values can denote a read-only literal
            # slot instead of the pointer stored there.  The initialized ELF
            # word is concrete evidence; clearing the ARM Thumb bit yields the
            # function entry used by Ghidra.
            initialized = literal_words.get(address & ~3)
            literal_target = (
                function_by_entry.get(initialized & ~1)
                if initialized is not None
                else None
            )
            if literal_target:
                targets.add(literal_target)
                continue
        op = _definition(function_id, current, by_atom, by_site)
        if not op:
            continue
        mnemonic = str(op.get("mnemonic", ""))
        if mnemonic not in TRANSPARENT_OPS | {"MULTIEQUAL"}:
            continue
        proof_sites.append(str(op.get("site_id", "")))
        for raw in list(op.get("inputs", []) or []):
            item = dict(raw or {})
            if not bool(item.get("is_constant")):
                queue.append(item)
    return targets, formals, sorted(set(proof_sites) - {""})


def _call_targets_by_site(
    call_edges: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in call_edges:
        target = str(edge.get("dst_node_id", ""))
        if target and not target.startswith("unknown-call-target:"):
            rows[str(edge.get("site_id", ""))].append(edge)
    return dict(rows)


def _resolve_formal_targets(
    function_id: str,
    slot: int,
    *,
    functions: dict[str, dict[str, Any]],
    function_by_entry: dict[int, str],
    literal_words: dict[int, int],
    call_edges: list[dict[str, Any]],
    by_atom: dict[str, tuple[str, dict[str, Any]]],
    by_site: dict[str, tuple[str, dict[str, Any]]],
    max_depth: int,
    max_targets: int,
) -> tuple[set[str], list[dict[str, Any]], bool]:
    """Resolve a formal callback through exact caller actuals and wrappers."""

    calls_to: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in call_edges:
        target = str(edge.get("dst_node_id", ""))
        if target and not target.startswith("unknown-call-target:"):
            calls_to[target].append(edge)
    ops = {
        str(op.get("site_id", "")): (function_id_, op)
        for function_id_, function in functions.items()
        for op in list(function.get("pcode_ops", []) or [])
        if str(op.get("site_id", ""))
    }
    queue: deque[tuple[str, int, int]] = deque([(function_id, slot, 0)])
    seen: set[tuple[str, int]] = set()
    targets: set[str] = set()
    evidence: list[dict[str, Any]] = []
    over_budget = False
    while queue:
        callee_id, formal_slot, depth = queue.popleft()
        key = (callee_id, formal_slot)
        if key in seen:
            continue
        seen.add(key)
        if depth > max_depth:
            over_budget = True
            continue
        for edge in calls_to.get(callee_id, []):
            site_id = str(edge.get("site_id", ""))
            caller_id, op = ops.get(site_id, ("", {}))
            actuals = _call_actuals(op)
            if not caller_id or formal_slot >= len(actuals):
                continue
            actual = actuals[formal_slot]
            concrete, formals, proof_sites = _trace_function_values(
                caller_id,
                actual,
                function_by_entry=function_by_entry,
                literal_words=literal_words,
                by_atom=by_atom,
                by_site=by_site,
            )
            targets.update(concrete)
            evidence.append(
                {
                    "call_edge_id": str(edge.get("edge_id", "")),
                    "call_site_id": site_id,
                    "caller_function_id": caller_id,
                    "callee_function_id": callee_id,
                    "formal_slot": formal_slot,
                    "actual_atom_id": _identity(actual),
                    "transparent_site_ids": proof_sites,
                }
            )
            for caller_slot in formals:
                queue.append((caller_id, caller_slot, depth + 1))
            if len(targets) > max_targets:
                return targets, evidence, True
    return targets, evidence, over_budget


def _target_load(
    function_id: str,
    node: dict[str, Any],
    *,
    by_atom: dict[str, tuple[str, dict[str, Any]]],
    by_site: dict[str, tuple[str, dict[str, Any]]],
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> dict[str, Any] | None:
    if depth > 24:
        return None
    atom = _identity(node)
    if not atom or atom in seen:
        return None
    op = _definition(function_id, node, by_atom, by_site)
    if not op:
        return None
    mnemonic = str(op.get("mnemonic", ""))
    if mnemonic == "LOAD":
        return op
    if mnemonic not in TRANSPARENT_OPS:
        return None
    candidates = [
        _target_load(
            function_id,
            dict(raw or {}),
            by_atom=by_atom,
            by_site=by_site,
            depth=depth + 1,
            seen=seen | {atom},
        )
        for raw in list(op.get("inputs", []) or [])
        if not bool(dict(raw or {}).get("is_constant"))
    ]
    candidates = [candidate for candidate in candidates if candidate]
    sites = {str(candidate.get("site_id", "")) for candidate in candidates}
    return candidates[0] if len(sites) == 1 else None


def _make_call_edge(
    caller_id: str,
    op: dict[str, Any],
    target_id: str,
    *,
    runtime: dataflow_objects.RuntimeObjectIndex,
    recognition: str,
    precision: str,
    target_count: int,
    evidence: dict[str, Any],
) -> dict[str, Any]:
    site_id = str(op.get("site_id", ""))
    actuals = _call_actuals(op)
    bindings: list[dict[str, Any]] = []
    resolved_ids: list[str] = []
    access_paths: list[list[str]] = []
    for slot, actual in enumerate(actuals):
        resolved = runtime.resolve(actual, caller_id)
        object_id = str((resolved or {}).get("object_id", "")) or str(
            actual.get("object_id", "")
        )
        resolved_ids.append(object_id)
        access_paths.append(list((resolved or {}).get("access_path", []) or []))
        bindings.append(
            {
                "slot": slot,
                "atom_id": _identity(actual),
                "value_id": str(actual.get("value_id", "")),
                "object_id": object_id,
                "target_parameter_slot": slot,
            }
        )
    edge_suffix = "" if target_count == 1 else f":{target_id}"
    return {
        "edge_id": f"call:{site_id}{edge_suffix}",
        "src_node_id": caller_id,
        "dst_node_id": target_id,
        "function_id": caller_id,
        "site_id": site_id,
        "edge_kind": "CALLIND",
        "resolution": (
            "EXACT_INDIRECT_TARGET"
            if target_count == 1
            else "RUNTIME_CALLBACK_MAY_TARGET"
        ),
        "resolution_kind": "BODY_PROVED_RUNTIME_CALLBACK_REGION",
        "recognition": recognition,
        "analysis_precision": precision,
        "candidate_count": target_count,
        "argument_bindings": bindings,
        "argument_atom_ids": [row["atom_id"] for row in bindings],
        "argument_value_ids": [row["value_id"] for row in bindings],
        "argument_object_ids": [
            str(actual.get("object_id", "")) for actual in actuals
        ],
        "resolved_argument_object_ids": resolved_ids,
        "argument_access_paths": access_paths,
        "resolution_evidence": [evidence],
        "bound_output_effects": [],
    }


def resolve_runtime_callback_relations(
    program_facts: dict[str, Any],
    call_edges: list[dict[str, Any]],
    *,
    runtime: dataflow_objects.RuntimeObjectIndex,
    access_index: memory_access_facts.MemoryAccessFactIndex,
    literal_words: dict[int, int] | None = None,
    output_effects: list[dict[str, Any]] | None = None,
    max_wrapper_depth: int = 8,
    max_targets: int = 16,
) -> dict[str, Any]:
    """Recover Callgraph relations for writable runtime callback fields."""

    literal_words = dict(literal_words or {})
    output_effects = list(output_effects or [])
    functions = {
        str(function.get("function_id", "")): function
        for function in list(program_facts.get("functions", []) or [])
        if str(function.get("function_id", ""))
    }
    function_by_entry: dict[int, str] = {}
    for function_id, function in functions.items():
        raw = function.get("entry")
        try:
            entry = int(str(raw), 0)
        except (TypeError, ValueError):
            try:
                entry = int(str(raw), 16)
            except (TypeError, ValueError):
                continue
        function_by_entry[entry & ~1] = function_id
    by_atom, by_site = _definitions(functions)

    registrations_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    registrations: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for fact in access_index.write_facts:
        store_entry = by_site.get(fact.site_id)
        if not store_entry:
            continue
        function_id, op = store_entry
        inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
        if len(inputs) < 2:
            continue
        stored = inputs[-1]
        concrete, formal_slots, transparent_sites = _trace_function_values(
            function_id,
            stored,
            function_by_entry=function_by_entry,
            literal_words=literal_words,
            by_atom=by_atom,
            by_site=by_site,
        )
        target_evidence: list[dict[str, Any]] = []
        over_budget = False
        for slot in sorted(formal_slots):
            resolved, evidence, exceeded = _resolve_formal_targets(
                function_id,
                slot,
                functions=functions,
                function_by_entry=function_by_entry,
                literal_words=literal_words,
                call_edges=call_edges,
                by_atom=by_atom,
                by_site=by_site,
                max_depth=max_wrapper_depth,
                max_targets=max_targets,
            )
            concrete.update(resolved)
            target_evidence.extend(evidence)
            over_budget = over_budget or exceeded
        if over_budget or len(concrete) > max_targets:
            blockers.append(
                {
                    "reason": "runtime_callback_target_budget_exhausted",
                    "site_id": fact.site_id,
                    "candidate_target_count": len(concrete),
                    "max_targets": max_targets,
                }
            )
            continue
        if not concrete:
            continue
        registration = {
            "write_fact": fact,
            "targets": sorted(concrete),
            "transparent_site_ids": transparent_sites,
            "target_evidence": target_evidence,
        }
        registrations_by_object[fact.aggregate_object_id].append(registration)
        registrations.append(registration)

    recovered_edges: list[dict[str, Any]] = []
    resolved_rows: list[dict[str, Any]] = []
    for caller_id, function in functions.items():
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "CALLIND":
                continue
            inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
            if not inputs:
                continue
            load = _target_load(
                caller_id,
                inputs[0],
                by_atom=by_atom,
                by_site=by_site,
            )
            if not load:
                continue
            load_site_id = str(load.get("site_id", ""))
            load_fact = access_index.fact_by_site.get(load_site_id)
            matching: list[tuple[dict[str, Any], str]] = []
            load_object_id = ""
            if isinstance(load_fact, memory_access_facts.ReadFact):
                load_object_id = load_fact.aggregate_object_id
                for registration in registrations_by_object.get(
                    load_fact.aggregate_object_id, []
                ):
                    relation = memory_access_facts.region_relation(
                        registration["write_fact"], load_fact
                    )
                    if relation != memory_access_facts.RegionRelation.DISJOINT:
                        matching.append((registration, relation.value))
            else:
                load_inputs = [
                    dict(item or {}) for item in list(load.get("inputs", []) or [])
                ]
                address_node = load_inputs[-1] if load_inputs else {}
                resolved_load = runtime.resolve(address_node, caller_id) or {}
                local_object_id = str(resolved_load.get("object_id", ""))
                local_offset = _access_path_offset(
                    list(resolved_load.get("access_path", []) or [])
                )
                load_address = _site_address(load_site_id)
                alias_objects: set[str] = set()
                for effect in output_effects:
                    if str(effect.get("caller_function_id", "")) != caller_id:
                        continue
                    destination = dict(effect.get("destination", {}) or {})
                    if not _same_base_object(
                        str(destination.get("object_id", "")), local_object_id
                    ):
                        continue
                    if int(destination.get("offset", 0) or 0) != 0:
                        continue
                    effect_address = _site_address(str(effect.get("call_site_id", "")))
                    if (
                        effect_address is not None
                        and load_address is not None
                        and effect_address > load_address
                    ):
                        continue
                    stored_value = dict(effect.get("stored_value", {}) or {})
                    alias_object = str(stored_value.get("object_id", ""))
                    if alias_object:
                        alias_objects.add(alias_object)
                if local_offset is not None:
                    for registration in registrations:
                        write_fact = registration["write_fact"]
                        if any(
                            _same_base_object(alias_object, candidate)
                            for alias_object in alias_objects
                            for candidate in (
                                write_fact.object_id,
                                write_fact.aggregate_object_id,
                                write_fact.base_object_id,
                            )
                        ):
                            matching.append(
                                (
                                    registration,
                                    memory_access_facts.RegionRelation.MAY_OVERLAP.value,
                                )
                            )
                    if alias_objects:
                        load_object_id = sorted(alias_objects)[0]
            targets = sorted(
                {
                    target
                    for registration, _relation in matching
                    for target in registration["targets"]
                }
            )
            if not targets:
                continue
            if len(targets) > max_targets:
                blockers.append(
                    {
                        "reason": "runtime_callback_target_budget_exhausted",
                        "site_id": str(op.get("site_id", "")),
                        "candidate_target_count": len(targets),
                        "max_targets": max_targets,
                    }
                )
                continue
            exact_region = all(
                relation == memory_access_facts.RegionRelation.EXACT_OVERLAP.value
                for _registration, relation in matching
            )
            singleton = len(targets) == 1
            recognition = "deterministic" if singleton and exact_region else "heuristic"
            precision = "EXACT" if singleton and exact_region else "MAY"
            candidate_set_id = hashlib.sha256(
                (str(op.get("site_id", "")) + "|" + "|".join(targets)).encode()
            ).hexdigest()[:20]
            for target_id in targets:
                evidence = {
                    "candidate_set_id": f"runtime-callback:{candidate_set_id}",
                    "target_function_id": target_id,
                    "load_site_id": load_site_id,
                    "aggregate_object_id": load_object_id,
                    "region_relations": sorted({relation for _, relation in matching}),
                    "registration_store_site_ids": sorted(
                        {
                            registration["write_fact"].site_id
                            for registration, _relation in matching
                            if target_id in registration["targets"]
                        }
                    ),
                    "target_binding_evidence": [
                        item
                        for registration, _relation in matching
                        if target_id in registration["targets"]
                        for item in registration["target_evidence"]
                    ],
                }
                recovered_edges.append(
                    _make_call_edge(
                        caller_id,
                        op,
                        target_id,
                        runtime=runtime,
                        recognition=recognition,
                        precision=precision,
                        target_count=len(targets),
                        evidence=evidence,
                    )
                )
                resolved_rows.append(
                    {
                        "site_id": str(op.get("site_id", "")),
                        "caller_function_id": caller_id,
                        "target_function_id": target_id,
                        "recognition": recognition,
                        "analysis_precision": precision,
                        "evidence": evidence,
                    }
                )

    return {
        "call_edges": sorted(
            recovered_edges,
            key=lambda row: (str(row.get("site_id", "")), str(row.get("dst_node_id", ""))),
        ),
        "resolved": sorted(
            resolved_rows,
            key=lambda row: (str(row.get("site_id", "")), str(row.get("target_function_id", ""))),
        ),
        "blockers": blockers,
        "counts": {
            "registration_regions": len(registrations_by_object),
            "resolved_relations": len(resolved_rows),
            "resolved_callsites": len(
                {str(row.get("site_id", "")) for row in resolved_rows}
            ),
            "blockers": len(blockers),
        },
    }
