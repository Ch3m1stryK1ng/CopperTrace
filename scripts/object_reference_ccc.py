#!/usr/bin/env python3
"""Recover source-associated object-reference CCC effects from High P-code.

The analysis is deliberately framework agnostic.  It recognizes two body
effects only:

* insert: a formal payload reaches a STORE into a constant-offset Region
  rooted at a different formal container;
* remove: a LOAD from such a Region reaches RETURN through transparent ops.

Body summaries are instantiated at resolved High P-code callsites.  A writer
is emitted only when its payload actual is already associated with an admitted
Source as ``OBJECT_REFERENCE`` or ``VALUE`` and its container actual resolves
to an object.  Readers require the same object resolution.  No Sink, function
name, framework contract, queue layout, or CVE metadata is consulted.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

import dataflow_objects


TRANSPARENT_OPS = {
    "COPY",
    "CAST",
    "INT_ZEXT",
    "INT_SEXT",
    "SUBPIECE",
}
CONSTANT_ADDRESS_OPS = {"PTRADD", "PTRSUB", "INT_ADD"}
SUPPORTED_SOURCE_STATES = {"OBJECT_REFERENCE", "VALUE"}


def _stable_id(prefix: str, *parts: Any) -> str:
    token = hashlib.sha256(
        "|".join(str(part) for part in parts).encode()
    ).hexdigest()[:20]
    return f"{prefix}:{token}"


def _node(raw: Any) -> dict[str, Any]:
    return dict(raw or {}) if isinstance(raw, dict) else {}


def _identity(raw: Any) -> str:
    return dataflow_objects.identity(_node(raw))


def _site(op: dict[str, Any]) -> str:
    return str(op.get("site_id", ""))


def _parameter_slot(node: dict[str, Any]) -> int | None:
    for key in ("parameter_slot", "index"):
        value = node.get(key)
        if isinstance(value, int) and (
            bool(node.get("is_parameter"))
            or bool(node.get("is_input"))
            or str(node.get("object_id", "")).startswith("param:")
        ):
            return value
    match = re.fullmatch(r"param:[^:]+:(\d+)", str(node.get("object_id", "")))
    return int(match.group(1)) if match else None


def _signed_constant(node: dict[str, Any]) -> int | None:
    return dataflow_objects.signed_constant(node)


def _definition_index(function: dict[str, Any]) -> dict[str, dict[str, Any]]:
    definitions: dict[str, dict[str, Any]] = {}
    for op in list(function.get("pcode_ops", []) or []):
        output = _node(op.get("output"))
        atom = _identity(output)
        if atom:
            definitions[atom] = op
        site_id = _site(op)
        if site_id:
            definitions[f"site:{site_id}"] = op
    return definitions


def _definition(
    node: dict[str, Any], definitions: dict[str, dict[str, Any]]
) -> dict[str, Any] | None:
    atom = _identity(node)
    if atom and atom in definitions:
        return definitions[atom]
    site_id = str(node.get("def_site_id", ""))
    return definitions.get(f"site:{site_id}") if site_id else None


@dataclass(frozen=True)
class FormalTrace:
    slot: int
    constant_offset: int
    atom_ids: tuple[str, ...]
    operation_site_ids: tuple[str, ...]


@dataclass(frozen=True)
class LoadTrace:
    container: FormalTrace
    load_site_id: str
    load_atom_id: str
    load_extent: int
    return_adjustment: int
    operation_site_ids: tuple[str, ...]


@dataclass(frozen=True)
class WrappedRemoveTrace:
    container: FormalTrace
    wrapped_summary_id: str
    wrapped_target_function_id: str
    wrapper_call_site_id: str
    region_extent: int
    container_relative_offset: int
    return_adjustment: int
    returned_atom_id: str
    operation_site_ids: tuple[str, ...]
    summary_depth: int
    recognition: str
    analysis_precision: str


def _constant_delta(mnemonic: str, inputs: list[dict[str, Any]]) -> int | None:
    constants = [_signed_constant(item) for item in inputs if item.get("is_constant")]
    if any(value is None for value in constants):
        return None
    values = [int(value) for value in constants if value is not None]
    if mnemonic == "PTRADD":
        if len(values) == 2:
            return values[0] * values[1]
        if len(values) == 1:
            return values[0]
        return None
    if mnemonic in {"PTRSUB", "INT_ADD"}:
        return sum(values) if values else None
    return None


def _trace_formal(
    node: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
    *,
    max_depth: int,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> FormalTrace | None:
    """Trace one value to exactly one formal through the admitted operations."""

    slot = _parameter_slot(node)
    atom = _identity(node)
    if slot is not None:
        return FormalTrace(slot, 0, (atom,) if atom else (), ())
    if depth >= max_depth or not atom or atom in seen:
        return None
    op = _definition(node, definitions)
    if op is None:
        return None
    mnemonic = str(op.get("mnemonic", ""))
    inputs = [_node(item) for item in list(op.get("inputs", []) or [])]
    dynamic = [item for item in inputs if not bool(item.get("is_constant"))]
    if mnemonic in TRANSPARENT_OPS:
        if len(dynamic) != 1:
            return None
        nested = _trace_formal(
            dynamic[0],
            definitions,
            max_depth=max_depth,
            depth=depth + 1,
            seen=seen | {atom},
        )
        delta = 0
    elif mnemonic in CONSTANT_ADDRESS_OPS:
        if len(dynamic) != 1:
            return None
        delta = _constant_delta(mnemonic, inputs)
        if delta is None:
            return None
        nested = _trace_formal(
            dynamic[0],
            definitions,
            max_depth=max_depth,
            depth=depth + 1,
            seen=seen | {atom},
        )
    else:
        return None
    if nested is None:
        return None
    return FormalTrace(
        slot=nested.slot,
        constant_offset=nested.constant_offset + delta,
        atom_ids=tuple(dict.fromkeys((atom,) + nested.atom_ids)),
        operation_site_ids=tuple(
            dict.fromkeys((_site(op),) + nested.operation_site_ids)
        ),
    )


def _trace_returned_load(
    node: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
    *,
    max_depth: int,
    depth: int = 0,
    adjustment: int = 0,
    seen: frozenset[str] = frozenset(),
) -> LoadTrace | None:
    atom = _identity(node)
    if depth >= max_depth or not atom or atom in seen:
        return None
    op = _definition(node, definitions)
    if op is None:
        return None
    mnemonic = str(op.get("mnemonic", ""))
    inputs = [_node(item) for item in list(op.get("inputs", []) or [])]
    dynamic = [item for item in inputs if not bool(item.get("is_constant"))]
    if mnemonic == "LOAD":
        if not dynamic:
            return None
        container = _trace_formal(
            dynamic[-1], definitions, max_depth=max_depth
        )
        output = _node(op.get("output"))
        if container is None or not _identity(output):
            return None
        return LoadTrace(
            container=container,
            load_site_id=_site(op),
            load_atom_id=_identity(output),
            load_extent=int(output.get("size", 0) or node.get("size", 0) or 0),
            return_adjustment=adjustment,
            operation_site_ids=(),
        )
    if mnemonic in TRANSPARENT_OPS:
        if len(dynamic) != 1:
            return None
        delta = 0
    elif mnemonic in CONSTANT_ADDRESS_OPS:
        if len(dynamic) != 1:
            return None
        parsed = _constant_delta(mnemonic, inputs)
        if parsed is None:
            return None
        delta = parsed
    else:
        return None
    nested = _trace_returned_load(
        dynamic[0],
        definitions,
        max_depth=max_depth,
        depth=depth + 1,
        adjustment=adjustment + delta,
        seen=seen | {atom},
    )
    if nested is None:
        return None
    return LoadTrace(
        container=nested.container,
        load_site_id=nested.load_site_id,
        load_atom_id=nested.load_atom_id,
        load_extent=nested.load_extent,
        return_adjustment=nested.return_adjustment,
        operation_site_ids=tuple(
            dict.fromkeys((_site(op),) + nested.operation_site_ids)
        ),
    )


def recover_body_effect_summaries(
    program_facts: dict[str, Any],
    *,
    max_trace_depth: int = 16,
    max_wrapper_depth: int = 4,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Recover name-independent insert/remove summaries from function bodies."""

    summaries: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for function in list(program_facts.get("functions", []) or []):
        function = _node(function)
        function_id = str(function.get("function_id", ""))
        if not function_id:
            continue
        definitions = _definition_index(function)
        for op in list(function.get("pcode_ops", []) or []):
            mnemonic = str(op.get("mnemonic", ""))
            inputs = [_node(item) for item in list(op.get("inputs", []) or [])]
            if mnemonic == "STORE" and len(inputs) >= 2:
                address, stored = inputs[-2], inputs[-1]
                payload = _trace_formal(
                    stored, definitions, max_depth=max_trace_depth
                )
                if payload is None:
                    continue
                container = _trace_formal(
                    address, definitions, max_depth=max_trace_depth
                )
                if container is None:
                    blockers.append(
                        {
                            "reason": "object_reference_insert_container_region_unresolved",
                            "function_id": function_id,
                            "site_id": _site(op),
                            "payload_parameter_slot": payload.slot,
                        }
                    )
                    continue
                if container.slot == payload.slot:
                    blockers.append(
                        {
                            "reason": "object_reference_insert_container_payload_alias",
                            "function_id": function_id,
                            "site_id": _site(op),
                            "parameter_slot": container.slot,
                        }
                    )
                    continue
                extent = int(stored.get("size", 0) or 0)
                if extent <= 0:
                    blockers.append(
                        {
                            "reason": "object_reference_insert_extent_unknown",
                            "function_id": function_id,
                            "site_id": _site(op),
                        }
                    )
                    continue
                summary_id = _stable_id(
                    "object-reference-effect",
                    "INSERT",
                    function_id,
                    _site(op),
                    container.slot,
                    container.constant_offset,
                    payload.slot,
                    payload.constant_offset,
                    extent,
                )
                summaries.append(
                    {
                        "summary_id": summary_id,
                        "effect_kind": "INSERT",
                        "function_id": function_id,
                        "function": str(function.get("name", "")),
                        "site_id": _site(op),
                        "container_parameter_slot": container.slot,
                        "payload_parameter_slot": payload.slot,
                        "container_relative_offset": container.constant_offset,
                        "payload_relative_offset": payload.constant_offset,
                        "region_extent": extent,
                        "stored_atom_id": _identity(stored),
                        "address_trace_site_ids": list(
                            container.operation_site_ids
                        ),
                        "payload_trace_site_ids": list(payload.operation_site_ids),
                        "recognition": "deterministic",
                        "analysis_precision": "EXACT",
                        "proof": "FORMAL_PAYLOAD_TO_CONSTANT_FORMAL_REGION_STORE",
                    }
                )
            elif mnemonic == "RETURN":
                returned = [item for item in inputs if not item.get("is_constant")]
                if len(returned) != 1:
                    continue
                loaded = _trace_returned_load(
                    returned[0], definitions, max_depth=max_trace_depth
                )
                if loaded is None or loaded.load_extent <= 0:
                    continue
                summary_id = _stable_id(
                    "object-reference-effect",
                    "REMOVE",
                    function_id,
                    loaded.load_site_id,
                    _site(op),
                    loaded.container.slot,
                    loaded.container.constant_offset,
                    loaded.load_extent,
                    loaded.return_adjustment,
                )
                summaries.append(
                    {
                        "summary_id": summary_id,
                        "effect_kind": "REMOVE",
                        "function_id": function_id,
                        "function": str(function.get("name", "")),
                        "site_id": loaded.load_site_id,
                        "return_site_id": _site(op),
                        "container_parameter_slot": loaded.container.slot,
                        "container_relative_offset": (
                            loaded.container.constant_offset
                        ),
                        "region_extent": loaded.load_extent,
                        "loaded_atom_id": loaded.load_atom_id,
                        "returned_atom_id": _identity(returned[0]),
                        "return_adjustment": loaded.return_adjustment,
                        "address_trace_site_ids": list(
                            loaded.container.operation_site_ids
                        ),
                        "return_trace_site_ids": list(
                            loaded.operation_site_ids
                        ),
                        "recognition": "deterministic",
                        "analysis_precision": "EXACT",
                        "proof": "CONSTANT_FORMAL_REGION_LOAD_TO_RETURN",
                    }
                )
    unique = {str(row["summary_id"]): row for row in summaries}
    derived, wrapper_blockers = _derive_wrapper_effect_summaries(
        program_facts,
        list(unique.values()),
        max_trace_depth=max_trace_depth,
        max_wrapper_depth=max_wrapper_depth,
    )
    unique.update({str(row["summary_id"]): row for row in derived})
    blockers.extend(wrapper_blockers)
    unique_blockers = {
        (str(row.get("reason", "")), str(row.get("function_id", "")), str(row.get("site_id", ""))): row
        for row in blockers
    }
    return (
        [unique[key] for key in sorted(unique)],
        [unique_blockers[key] for key in sorted(unique_blockers)],
    )


def _call_actuals(op: dict[str, Any]) -> list[dict[str, Any]]:
    inputs = [_node(item) for item in list(op.get("inputs", []) or [])]
    argument_ids = [
        str(item)
        for item in list(_node(op.get("call")).get("argument_value_ids", []) or [])
        if str(item)
    ]
    if argument_ids:
        by_atom = {_identity(item): item for item in inputs if _identity(item)}
        resolved = [by_atom[atom] for atom in argument_ids if atom in by_atom]
        if len(resolved) == len(argument_ids):
            return resolved
    return inputs[1:] if inputs else []


def _trace_returned_remove_calls(
    node: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
    summaries_by_target: dict[str, list[dict[str, Any]]],
    *,
    max_depth: int,
    depth: int = 0,
    adjustment: int = 0,
    seen: frozenset[str] = frozenset(),
) -> list[WrappedRemoveTrace]:
    """Trace a wrapper return to a resolved callee REMOVE effect."""

    atom = _identity(node)
    if depth >= max_depth or not atom or atom in seen:
        return []
    op = _definition(node, definitions)
    if op is None:
        return []
    mnemonic = str(op.get("mnemonic", ""))
    inputs = [_node(item) for item in list(op.get("inputs", []) or [])]
    dynamic = [item for item in inputs if not bool(item.get("is_constant"))]

    if mnemonic in {"CALL", "CALLIND"}:
        target_id = str(_node(op.get("call")).get("target_function_id", ""))
        actuals = _call_actuals(op)
        traces: list[WrappedRemoveTrace] = []
        for summary in summaries_by_target.get(target_id, []):
            if str(summary.get("effect_kind", "")) != "REMOVE":
                continue
            container_slot = int(summary.get("container_parameter_slot", -1))
            if container_slot < 0 or container_slot >= len(actuals):
                continue
            container = _trace_formal(
                actuals[container_slot], definitions, max_depth=max_depth
            )
            if container is None:
                continue
            traces.append(
                WrappedRemoveTrace(
                    container=container,
                    wrapped_summary_id=str(summary.get("summary_id", "")),
                    wrapped_target_function_id=target_id,
                    wrapper_call_site_id=_site(op),
                    region_extent=int(summary.get("region_extent", 0) or 0),
                    container_relative_offset=(
                        container.constant_offset
                        + int(summary.get("container_relative_offset", 0) or 0)
                    ),
                    return_adjustment=(
                        adjustment
                        + int(summary.get("return_adjustment", 0) or 0)
                    ),
                    returned_atom_id=atom,
                    operation_site_ids=(),
                    summary_depth=int(summary.get("summary_depth", 0) or 0) + 1,
                    recognition=str(summary.get("recognition", "deterministic")),
                    analysis_precision=str(
                        summary.get("analysis_precision", "EXACT")
                    ),
                )
            )
        return traces

    if mnemonic in TRANSPARENT_OPS:
        if len(dynamic) != 1:
            return []
        delta = 0
        branches = dynamic
    elif mnemonic in CONSTANT_ADDRESS_OPS:
        if len(dynamic) != 1:
            return []
        parsed = _constant_delta(mnemonic, inputs)
        if parsed is None:
            return []
        delta = parsed
        branches = dynamic
    elif mnemonic == "MULTIEQUAL":
        # Each SSA predecessor is retained.  Different constant adjustments are
        # separate may-effects rather than being guessed into one return value.
        delta = 0
        branches = dynamic
    else:
        return []

    traces: list[WrappedRemoveTrace] = []
    for branch in branches:
        nested = _trace_returned_remove_calls(
            branch,
            definitions,
            summaries_by_target,
            max_depth=max_depth,
            depth=depth + 1,
            adjustment=adjustment + delta,
            seen=seen | {atom},
        )
        for trace in nested:
            precision = trace.analysis_precision
            recognition = trace.recognition
            if mnemonic == "MULTIEQUAL" and len(branches) > 1:
                precision = "MAY"
                recognition = "heuristic"
            traces.append(
                WrappedRemoveTrace(
                    container=trace.container,
                    wrapped_summary_id=trace.wrapped_summary_id,
                    wrapped_target_function_id=trace.wrapped_target_function_id,
                    wrapper_call_site_id=trace.wrapper_call_site_id,
                    region_extent=trace.region_extent,
                    container_relative_offset=trace.container_relative_offset,
                    return_adjustment=trace.return_adjustment,
                    returned_atom_id=atom,
                    operation_site_ids=tuple(
                        dict.fromkeys((_site(op),) + trace.operation_site_ids)
                    ),
                    summary_depth=trace.summary_depth,
                    recognition=recognition,
                    analysis_precision=precision,
                )
            )
    unique = {
        (
            trace.wrapped_summary_id,
            trace.container.slot,
            trace.container_relative_offset,
            trace.return_adjustment,
        ): trace
        for trace in traces
    }
    return [unique[key] for key in sorted(unique)]


def _derive_wrapper_effect_summaries(
    program_facts: dict[str, Any],
    direct_summaries: list[dict[str, Any]],
    *,
    max_trace_depth: int,
    max_wrapper_depth: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Propagate proven effects through resolved, role-preserving wrappers."""

    functions = [
        _node(function)
        for function in list(program_facts.get("functions", []) or [])
        if str(_node(function).get("function_id", ""))
    ]
    known = {str(row.get("summary_id", "")): row for row in direct_summaries}
    derived: dict[str, dict[str, Any]] = {}
    blockers: list[dict[str, Any]] = []

    for _round in range(max(0, int(max_wrapper_depth))):
        summaries_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for summary in known.values():
            summaries_by_target[str(summary.get("function_id", ""))].append(summary)
        added = 0

        for function in functions:
            function_id = str(function.get("function_id", ""))
            definitions = _definition_index(function)
            pcode_ops = list(function.get("pcode_ops", []) or [])

            for op in pcode_ops:
                if str(op.get("mnemonic", "")) not in {"CALL", "CALLIND"}:
                    continue
                target_id = str(_node(op.get("call")).get("target_function_id", ""))
                if not target_id or target_id == function_id:
                    continue
                actuals = _call_actuals(op)
                for wrapped in summaries_by_target.get(target_id, []):
                    if str(wrapped.get("effect_kind", "")) != "INSERT":
                        continue
                    container_slot = int(wrapped.get("container_parameter_slot", -1))
                    payload_slot = int(wrapped.get("payload_parameter_slot", -1))
                    if not (
                        0 <= container_slot < len(actuals)
                        and 0 <= payload_slot < len(actuals)
                    ):
                        continue
                    container = _trace_formal(
                        actuals[container_slot],
                        definitions,
                        max_depth=max_trace_depth,
                    )
                    payload = _trace_formal(
                        actuals[payload_slot],
                        definitions,
                        max_depth=max_trace_depth,
                    )
                    if container is None or payload is None:
                        continue
                    if container.slot == payload.slot:
                        continue
                    summary_depth = int(wrapped.get("summary_depth", 0) or 0) + 1
                    if summary_depth > max_wrapper_depth:
                        continue
                    container_offset = (
                        container.constant_offset
                        + int(wrapped.get("container_relative_offset", 0) or 0)
                    )
                    payload_offset = (
                        payload.constant_offset
                        + int(wrapped.get("payload_relative_offset", 0) or 0)
                    )
                    summary_id = _stable_id(
                        "object-reference-effect",
                        "INSERT_WRAPPER",
                        function_id,
                        _site(op),
                        wrapped.get("summary_id", ""),
                        container.slot,
                        container_offset,
                        payload.slot,
                        payload_offset,
                    )
                    if summary_id in known:
                        continue
                    row = {
                        "summary_id": summary_id,
                        "effect_kind": "INSERT",
                        "function_id": function_id,
                        "function": str(function.get("name", "")),
                        "site_id": _site(op),
                        "container_parameter_slot": container.slot,
                        "payload_parameter_slot": payload.slot,
                        "container_relative_offset": container_offset,
                        "payload_relative_offset": payload_offset,
                        "region_extent": int(wrapped.get("region_extent", 0) or 0),
                        "stored_atom_id": _identity(actuals[payload_slot]),
                        "address_trace_site_ids": list(container.operation_site_ids),
                        "payload_trace_site_ids": list(payload.operation_site_ids),
                        "wrapped_summary_id": str(wrapped.get("summary_id", "")),
                        "wrapped_target_function_id": target_id,
                        "wrapper_call_site_id": _site(op),
                        "summary_depth": summary_depth,
                        "recognition": str(
                            wrapped.get("recognition", "deterministic")
                        ),
                        "analysis_precision": str(
                            wrapped.get("analysis_precision", "EXACT")
                        ),
                        "proof": "RESOLVED_CALL_FORMAL_BINDING_TO_INSERT_EFFECT",
                    }
                    known[summary_id] = row
                    derived[summary_id] = row
                    added += 1

            summaries_by_target = defaultdict(list)
            for summary in known.values():
                summaries_by_target[str(summary.get("function_id", ""))].append(summary)
            for op in pcode_ops:
                if str(op.get("mnemonic", "")) != "RETURN":
                    continue
                returned = [
                    item
                    for item in [_node(raw) for raw in list(op.get("inputs", []) or [])]
                    if not bool(item.get("is_constant"))
                ]
                if len(returned) != 1:
                    continue
                traces = _trace_returned_remove_calls(
                    returned[0],
                    definitions,
                    summaries_by_target,
                    max_depth=max_trace_depth,
                )
                for trace in traces:
                    if trace.summary_depth > max_wrapper_depth:
                        continue
                    summary_id = _stable_id(
                        "object-reference-effect",
                        "REMOVE_WRAPPER",
                        function_id,
                        _site(op),
                        trace.wrapped_summary_id,
                        trace.container.slot,
                        trace.container_relative_offset,
                        trace.return_adjustment,
                    )
                    if summary_id in known:
                        continue
                    row = {
                        "summary_id": summary_id,
                        "effect_kind": "REMOVE",
                        "function_id": function_id,
                        "function": str(function.get("name", "")),
                        "site_id": trace.wrapper_call_site_id,
                        "return_site_id": _site(op),
                        "container_parameter_slot": trace.container.slot,
                        "container_relative_offset": trace.container_relative_offset,
                        "region_extent": trace.region_extent,
                        "loaded_atom_id": "",
                        "returned_atom_id": _identity(returned[0]),
                        "return_adjustment": trace.return_adjustment,
                        "address_trace_site_ids": list(
                            trace.container.operation_site_ids
                        ),
                        "return_trace_site_ids": list(trace.operation_site_ids),
                        "wrapped_summary_id": trace.wrapped_summary_id,
                        "wrapped_target_function_id": (
                            trace.wrapped_target_function_id
                        ),
                        "wrapper_call_site_id": trace.wrapper_call_site_id,
                        "summary_depth": trace.summary_depth,
                        "recognition": trace.recognition,
                        "analysis_precision": trace.analysis_precision,
                        "proof": "RESOLVED_CALL_RETURN_BINDING_TO_REMOVE_EFFECT",
                    }
                    known[summary_id] = row
                    derived[summary_id] = row
                    added += 1

        if added == 0:
            break
    else:
        blockers.append(
            {
                "reason": "object_reference_wrapper_summary_depth_budget_exhausted",
                "max_wrapper_depth": int(max_wrapper_depth),
            }
        )

    return [derived[key] for key in sorted(derived)], blockers


def _lineage_atoms(
    node: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
    *,
    max_depth: int,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> set[str]:
    atom = _identity(node)
    if not atom or atom in seen or depth >= max_depth:
        return set()
    result = {atom}
    op = _definition(node, definitions)
    if op is None:
        return result
    mnemonic = str(op.get("mnemonic", ""))
    inputs = [_node(item) for item in list(op.get("inputs", []) or [])]
    dynamic = [item for item in inputs if not item.get("is_constant")]
    if mnemonic in TRANSPARENT_OPS and len(dynamic) == 1:
        result.update(
            _lineage_atoms(
                dynamic[0],
                definitions,
                max_depth=max_depth,
                depth=depth + 1,
                seen=seen | {atom},
            )
        )
    elif mnemonic in CONSTANT_ADDRESS_OPS and len(dynamic) == 1:
        if _constant_delta(mnemonic, inputs) is not None:
            result.update(
                _lineage_atoms(
                    dynamic[0],
                    definitions,
                    max_depth=max_depth,
                    depth=depth + 1,
                    seen=seen | {atom},
                )
            )
    return result


def _association_rows(source_associations: Any) -> list[dict[str, Any]]:
    if isinstance(source_associations, dict):
        source_associations = source_associations.get("source_associations", [])
    return [
        _node(row)
        for row in list(source_associations or [])
        if str(_node(row).get("state_kind", "")) in SUPPORTED_SOURCE_STATES
    ]


def _binding_object_ids(binding: dict[str, Any] | None) -> set[str]:
    binding = _node(binding)
    return {
        str(binding.get("object_id", "")),
        str(binding.get("root_object_id", "")),
        str(binding.get("base_object_id", "")),
    } - {""}


def _matching_source_associations(
    *,
    caller_id: str,
    actual: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
    associations: list[dict[str, Any]],
    runtime: Any,
    max_trace_depth: int,
) -> list[dict[str, Any]]:
    atoms = _lineage_atoms(
        actual, definitions, max_depth=max_trace_depth
    )
    actual_binding = runtime.resolve(actual, caller_id)
    actual_objects = _binding_object_ids(actual_binding)
    matches: list[dict[str, Any]] = []
    for association in associations:
        if str(association.get("function_id", "")) != caller_id:
            continue
        state_kind = str(association.get("state_kind", ""))
        association_atom = str(association.get("atom_id", ""))
        if association_atom and association_atom in atoms:
            matches.append(association)
            continue
        if state_kind != "OBJECT_REFERENCE":
            continue
        association_objects = {
            str(association.get("object_id", "")),
            str(association.get("pointee_object_id", "")),
            str(association.get("base_object_id", "")),
        } - {""}
        if actual_objects.intersection(association_objects):
            matches.append(association)
    unique = {
        str(row.get("association_id", "")) or _stable_id(
            "anonymous-source-association",
            caller_id,
            row.get("source_definition_id", ""),
            row.get("atom_id", ""),
        ): row
        for row in matches
    }
    return [unique[key] for key in sorted(unique)]


def _offsets_after_last_deref(access_path: Iterable[Any]) -> tuple[int, str | None]:
    path = [str(item) for item in access_path]
    start = len(path) - 1 - path[::-1].index("deref") if "deref" in path else -1
    total = 0
    for item in path[start + 1 :]:
        if not item.startswith("byte_offset:"):
            return 0, "container_actual_access_path_not_constant"
        try:
            total += int(item.split(":", 1)[1], 0)
        except ValueError:
            return 0, "container_actual_access_path_not_constant"
    return total, None


def _instantiate_region(
    *,
    runtime: Any,
    actual: dict[str, Any],
    caller_id: str,
    relative_offset: int,
    extent: int,
) -> tuple[dict[str, Any] | None, str | None, str]:
    binding = runtime.resolve(actual, caller_id)
    if not binding:
        return None, "object_reference_container_actual_unresolved", "MAY"
    binding = _node(binding)
    object_id = str(binding.get("object_id", ""))
    root_object_id = str(binding.get("root_object_id", "") or object_id)
    if not object_id:
        return None, "object_reference_container_actual_has_no_object", "MAY"
    path = list(binding.get("access_path", []) or [])
    actual_offset, error = _offsets_after_last_deref(path)
    if error:
        return None, error, "MAY"
    # A LOAD-derived pointer denotes a separate pointee object.  Offsets before
    # its final dereference belong to the parent field, not the pointee Region.
    base_object_id = object_id if "deref" in path else root_object_id
    precision = str(binding.get("precision", "MAY") or "MAY").upper()
    precision = "EXACT" if precision == "EXACT" else "MAY"
    return (
        {
            "object_id": base_object_id,
            "base_object_id": base_object_id,
            "offset": actual_offset + int(relative_offset),
            "extent": int(extent),
            "actual_object_id": object_id,
            "actual_root_object_id": root_object_id,
            "actual_access_path": path,
        },
        None,
        precision,
    )


def _fact_precision(
    binding_precision: str, associations: Iterable[dict[str, Any]] = ()
) -> tuple[str, str]:
    heuristic = binding_precision != "EXACT"
    for association in associations:
        if str(association.get("recognition", "deterministic")).lower() == "heuristic":
            heuristic = True
        if str(association.get("analysis_precision", "EXACT")).upper() != "EXACT":
            heuristic = True
    return ("MAY", "heuristic") if heuristic else ("EXACT", "deterministic")


def instantiate_callsites(
    program_facts: dict[str, Any],
    body_effect_summaries: Iterable[dict[str, Any]],
    *,
    source_associations: Any,
    runtime: Any,
    max_trace_depth: int = 16,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Bind body summaries to resolved callsites and concrete object Regions."""

    functions = {
        str(function.get("function_id", "")): _node(function)
        for function in list(program_facts.get("functions", []) or [])
        if str(function.get("function_id", ""))
    }
    summaries_by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for summary in body_effect_summaries:
        summary = _node(summary)
        summaries_by_target[str(summary.get("function_id", ""))].append(summary)
    associations = _association_rows(source_associations)
    writers: list[dict[str, Any]] = []
    readers: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []

    for caller_id, caller in functions.items():
        definitions = _definition_index(caller)
        for op in list(caller.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) not in {"CALL", "CALLIND"}:
                continue
            target_id = str(_node(op.get("call")).get("target_function_id", ""))
            if not target_id or target_id not in summaries_by_target:
                continue
            actuals = _call_actuals(op)
            for summary in summaries_by_target[target_id]:
                container_slot = int(summary.get("container_parameter_slot", -1))
                if container_slot < 0 or container_slot >= len(actuals):
                    blockers.append(
                        {
                            "reason": "object_reference_container_actual_missing",
                            "summary_id": str(summary.get("summary_id", "")),
                            "function_id": caller_id,
                            "site_id": _site(op),
                            "parameter_slot": container_slot,
                        }
                    )
                    continue
                region, region_error, binding_precision = _instantiate_region(
                    runtime=runtime,
                    actual=actuals[container_slot],
                    caller_id=caller_id,
                    relative_offset=int(
                        summary.get("container_relative_offset", 0) or 0
                    ),
                    extent=int(summary.get("region_extent", 0) or 0),
                )
                if region is None:
                    blockers.append(
                        {
                            "reason": str(region_error),
                            "summary_id": str(summary.get("summary_id", "")),
                            "function_id": caller_id,
                            "site_id": _site(op),
                            "parameter_slot": container_slot,
                        }
                    )
                    continue
                if str(summary.get("effect_kind", "")) == "INSERT":
                    payload_slot = int(summary.get("payload_parameter_slot", -1))
                    if payload_slot < 0 or payload_slot >= len(actuals):
                        blockers.append(
                            {
                                "reason": "object_reference_payload_actual_missing",
                                "summary_id": str(summary.get("summary_id", "")),
                                "function_id": caller_id,
                                "site_id": _site(op),
                                "parameter_slot": payload_slot,
                            }
                        )
                        continue
                    payload = actuals[payload_slot]
                    matched = _matching_source_associations(
                        caller_id=caller_id,
                        actual=payload,
                        definitions=definitions,
                        associations=associations,
                        runtime=runtime,
                        max_trace_depth=max_trace_depth,
                    )
                    if not matched:
                        blockers.append(
                            {
                                "reason": "object_reference_payload_not_source_associated",
                                "summary_id": str(summary.get("summary_id", "")),
                                "function_id": caller_id,
                                "site_id": _site(op),
                                "payload_atom_id": _identity(payload),
                            }
                        )
                        continue
                    precision, recognition = _fact_precision(
                        binding_precision, matched
                    )
                    fact_id = _stable_id(
                        "object-reference-write",
                        summary.get("summary_id", ""),
                        caller_id,
                        _site(op),
                        region["base_object_id"],
                        region["offset"],
                        region["extent"],
                    )
                    writers.append(
                        {
                            "fact_id": fact_id,
                            "effect_kind": "OBJECT_REFERENCE_WRITE",
                            "summary_id": str(summary.get("summary_id", "")),
                            "function_id": caller_id,
                            "function": str(caller.get("name", "")),
                            "target_function_id": target_id,
                            "callsite_id": _site(op),
                            "physical_store_site_id": str(summary.get("site_id", "")),
                            "container_actual_atom_id": _identity(
                                actuals[container_slot]
                            ),
                            "payload_actual_atom_id": _identity(payload),
                            "payload_relative_offset": int(
                                summary.get("payload_relative_offset", 0) or 0
                            ),
                            "region": region,
                            "source_association_ids": sorted(
                                {
                                    str(row.get("association_id", ""))
                                    for row in matched
                                    if str(row.get("association_id", ""))
                                }
                            ),
                            "source_definition_ids": sorted(
                                {
                                    str(row.get("source_definition_id", ""))
                                    for row in matched
                                    if str(row.get("source_definition_id", ""))
                                }
                            ),
                            "source_ids": sorted(
                                {
                                    str(row.get("source_id", ""))
                                    for row in matched
                                    if str(row.get("source_id", ""))
                                }
                            ),
                            "source_state_kinds": sorted(
                                {str(row.get("state_kind", "")) for row in matched}
                            ),
                            "recognition": recognition,
                            "analysis_precision": precision,
                            "ccc_eligible": False,
                            "paired_fact_ids": [],
                        }
                    )
                else:
                    output = _node(op.get("output"))
                    output_atom = _identity(output)
                    if not output_atom:
                        blockers.append(
                            {
                                "reason": "object_reference_remove_call_has_no_result",
                                "summary_id": str(summary.get("summary_id", "")),
                                "function_id": caller_id,
                                "site_id": _site(op),
                            }
                        )
                        continue
                    precision, recognition = _fact_precision(binding_precision)
                    fact_id = _stable_id(
                        "object-reference-read",
                        summary.get("summary_id", ""),
                        caller_id,
                        _site(op),
                        region["base_object_id"],
                        region["offset"],
                        region["extent"],
                    )
                    readers.append(
                        {
                            "fact_id": fact_id,
                            "effect_kind": "OBJECT_REFERENCE_READ",
                            "summary_id": str(summary.get("summary_id", "")),
                            "function_id": caller_id,
                            "function": str(caller.get("name", "")),
                            "target_function_id": target_id,
                            "callsite_id": _site(op),
                            "physical_load_site_id": str(summary.get("site_id", "")),
                            "physical_return_site_id": str(
                                summary.get("return_site_id", "")
                            ),
                            "container_actual_atom_id": _identity(
                                actuals[container_slot]
                            ),
                            "loaded_result_atom_id": output_atom,
                            "loaded_result_object_id": str(
                                output.get("object_id", "")
                            ),
                            "return_adjustment": int(
                                summary.get("return_adjustment", 0) or 0
                            ),
                            "region": region,
                            "source_association_ids": [],
                            "source_definition_ids": [],
                            "source_ids": [],
                            "recognition": recognition,
                            "analysis_precision": precision,
                            "ccc_eligible": False,
                            "paired_fact_ids": [],
                        }
                    )

    def region_key(fact: dict[str, Any]) -> tuple[str, int, int]:
        region = _node(fact.get("region"))
        return (
            str(region.get("base_object_id", "")),
            int(region.get("offset", 0) or 0),
            int(region.get("extent", 0) or 0),
        )

    writers_by_region: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    readers_by_region: dict[tuple[str, int, int], list[dict[str, Any]]] = defaultdict(list)
    for fact in writers:
        writers_by_region[region_key(fact)].append(fact)
    for fact in readers:
        readers_by_region[region_key(fact)].append(fact)
    for key, region_writers in writers_by_region.items():
        region_readers = readers_by_region.get(key, [])
        if not region_readers:
            blockers.append(
                {
                    "reason": "object_reference_written_region_has_no_reader",
                    "base_object_id": key[0],
                    "region_offset": key[1],
                    "region_extent": key[2],
                    "writer_fact_ids": [row["fact_id"] for row in region_writers],
                }
            )
            continue
        writer_ids = sorted(row["fact_id"] for row in region_writers)
        reader_ids = sorted(row["fact_id"] for row in region_readers)
        lineage_ids = sorted(
            {
                lineage
                for row in region_writers
                for lineage in list(row.get("source_definition_ids", []) or [])
            }
        )
        source_ids = sorted(
            {
                source_id
                for row in region_writers
                for source_id in list(row.get("source_ids", []) or [])
            }
        )
        pair_is_may = any(
            str(row.get("analysis_precision", "")) != "EXACT"
            for row in region_writers + region_readers
        )
        for row in region_writers:
            row["ccc_eligible"] = True
            row["paired_fact_ids"] = reader_ids
            if pair_is_may:
                row["analysis_precision"] = "MAY"
                row["recognition"] = "heuristic"
        for row in region_readers:
            row["ccc_eligible"] = True
            row["paired_fact_ids"] = writer_ids
            row["source_definition_ids"] = lineage_ids
            row["source_ids"] = source_ids
            if pair_is_may:
                row["analysis_precision"] = "MAY"
                row["recognition"] = "heuristic"
    for key, region_readers in readers_by_region.items():
        if key not in writers_by_region:
            blockers.append(
                {
                    "reason": "object_reference_read_region_has_no_source_writer",
                    "base_object_id": key[0],
                    "region_offset": key[1],
                    "region_extent": key[2],
                    "reader_fact_ids": [row["fact_id"] for row in region_readers],
                }
            )

    writer_unique = {str(row["fact_id"]): row for row in writers}
    reader_unique = {str(row["fact_id"]): row for row in readers}
    blocker_unique = {
        (
            str(row.get("reason", "")),
            str(row.get("function_id", "")),
            str(row.get("site_id", "")),
            str(row.get("summary_id", "")),
            str(row.get("base_object_id", "")),
            str(row.get("region_offset", "")),
        ): row
        for row in blockers
    }
    return (
        [writer_unique[key] for key in sorted(writer_unique)],
        [reader_unique[key] for key in sorted(reader_unique)],
        [blocker_unique[key] for key in sorted(blocker_unique)],
    )


def recover_object_reference_ccc(
    program_facts: dict[str, Any],
    *,
    source_associations: Any,
    runtime: Any,
    max_trace_depth: int = 16,
) -> dict[str, Any]:
    """Run body recovery and callsite instantiation without pipeline coupling."""

    summaries, body_blockers = recover_body_effect_summaries(
        program_facts, max_trace_depth=max_trace_depth
    )
    writers, readers, binding_blockers = instantiate_callsites(
        program_facts,
        summaries,
        source_associations=source_associations,
        runtime=runtime,
        max_trace_depth=max_trace_depth,
    )
    blockers = body_blockers + binding_blockers
    return {
        "schema_version": "ct-mini-object-reference-ccc-v1",
        "body_effect_summaries": summaries,
        "writer_facts": writers,
        "reader_facts": readers,
        "blockers": blockers,
        "metrics": {
            "body_effect_summaries": len(summaries),
            "insert_summaries": sum(
                row.get("effect_kind") == "INSERT" for row in summaries
            ),
            "remove_summaries": sum(
                row.get("effect_kind") == "REMOVE" for row in summaries
            ),
            "writer_facts": len(writers),
            "reader_facts": len(readers),
            "ccc_eligible_writer_facts": sum(
                bool(row.get("ccc_eligible")) for row in writers
            ),
            "ccc_eligible_reader_facts": sum(
                bool(row.get("ccc_eligible")) for row in readers
            ),
            "blockers": len(blockers),
        },
    }
