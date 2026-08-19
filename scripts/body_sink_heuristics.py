#!/usr/bin/env python3
"""Generalized body-derived Sink heuristics over High P-code and CFG facts.

The recognizers are deliberately bounded:

* Counted Range COPY/FILL;
* Sentinel Copy; and
* Stateful Loop Write;
* Paired Buffer-State Consume/Reserve; and
* In-place Swap Operation; and
* Parser Out-of-Bounds Read.

Every recognizer uses two stages.  A structural scan first records candidates;
pattern-specific High P-code and CFG checks then either emit a heuristic Sink
or retain an explicit rejection reason.  Function, framework, sample, and CVE
names never participate in a decision.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from high_pcode_loop_analysis import (
    AddressProgression,
    AnalysisBlocker,
    FunctionCFG,
    NaturalLoop,
    Recurrence,
    comparison_for_branch,
    node_constant,
    node_object_id,
    node_text,
    node_value_id,
    parse_int,
)
from software_source_engine import ProgramIndex, formal_access_path
from parser_oob_read_heuristic import SourceAssociationIndex as ParserSourceIndex
from parser_oob_read_heuristic import discover_parser_oob_reads
from variable_store_heuristic import discover_variable_address_stores


def stable_id(prefix: str, *parts: Any) -> str:
    payload = "\x1f".join(str(part or "") for part in parts).encode("utf-8", "replace")
    return f"{prefix}:{hashlib.sha256(payload).hexdigest()[:20]}"


def operation_inputs(op: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(item) for item in list(op.get("inputs", []) or [])]


def operation_output(op: dict[str, Any]) -> dict[str, Any]:
    return dict(op.get("output", {}) or {})


def op_site(op: dict[str, Any]) -> str:
    return str(op.get("site_id", ""))


def expression(node: dict[str, Any], fallback: str = "") -> str:
    return str(fallback or "").strip() or node_text(node)


def parameter_slot(node: dict[str, Any]) -> int | None:
    slot = node.get("parameter_slot")
    if isinstance(slot, int):
        return slot
    object_id = node_object_id(node)
    if object_id.startswith("param:"):
        try:
            return int(object_id.rsplit(":", 1)[1])
        except ValueError:
            return None
    return None


def memory_block_for_address(
    program_facts: dict[str, Any], address: int
) -> dict[str, Any] | None:
    for raw in list(program_facts.get("memory_blocks", []) or []):
        row = dict(raw)
        start = parse_int(row.get("start"))
        end = parse_int(row.get("end"))
        if start is not None and end is not None and start <= address <= end:
            return row
    return None


def immutable_memory_pointer(
    program_facts: dict[str, Any], node: dict[str, Any]
) -> bool:
    value = node_constant(node)
    if value is None and bool(node.get("is_address")):
        value = parse_int(node.get("offset"))
    if value is None:
        return False
    block = memory_block_for_address(program_facts, value)
    return bool(
        block
        and block.get("read")
        and not block.get("write")
        and block.get("initialized")
    )


@dataclass(frozen=True)
class CandidateDecision:
    pattern: str
    function_id: str
    function: str
    site_id: str
    loop_id: str
    status: str
    reason_code: str
    evidence: dict[str, Any]

    def as_json(self) -> dict[str, Any]:
        return {
            "candidate_id": stable_id(
                "sink-candidate",
                self.pattern,
                self.function_id,
                self.site_id,
                self.loop_id,
            ),
            "pattern": self.pattern,
            "function_id": self.function_id,
            "function": self.function,
            "site_id": self.site_id,
            "loop_id": self.loop_id,
            "status": self.status,
            "reason_code": self.reason_code,
            "evidence": self.evidence,
        }


class SourceEvidenceIndex:
    """Index only supplied, positive external-input MMIO evidence.

    The recognizer does not infer register roles from names or addresses.  It
    excludes a loop only when a Source/register artifact explicitly identifies
    the relevant LOAD site, output ValueId, or register address as an
    external-input-capable data register.
    """

    def __init__(self, *packs: dict[str, Any] | None) -> None:
        self.load_sites: set[str] = set()
        self.value_ids: set[str] = set()
        self.register_addresses: set[int] = set()
        for pack in packs:
            if pack:
                self._consume(pack)

    @staticmethod
    def _positive(row: dict[str, Any]) -> bool:
        role = str(
            row.get("register_role", "")
            or row.get("role", "")
            or row.get("resolved_role", "")
            or row.get("source_kind", "")
        ).lower()
        label = str(row.get("label", "") or row.get("source_label", "")).upper()
        confirmed = (
            row.get("external_input_capable") is True
            or row.get("confirmed_source") is True
            or str(row.get("status", "")).lower() in {"confirmed", "accepted"}
            or str(row.get("decision", "")).upper().startswith("ACCEPT")
        )
        data_role = any(
            token in role
            for token in ("data", "receive", "rx", "fifo", "payload", "ingress")
        )
        status_role = any(
            token in role for token in ("status", "control", "config", "enable")
        )
        explicit_data = data_role or row.get("is_data_register") is True
        return bool(
            confirmed
            and explicit_data
            and not status_role
            and ("MMIO" in label or row.get("external_input_capable") is True)
        )

    def _consume(self, value: Any) -> None:
        if isinstance(value, list):
            for item in value:
                self._consume(item)
            return
        if not isinstance(value, dict):
            return
        row = dict(value)
        if self._positive(row):
            for key in ("load_site_id", "mmio_load_site_id", "site_id"):
                if row.get(key):
                    self.load_sites.add(str(row[key]))
            for key in ("load_value_id", "value_id", "output_value_id"):
                if row.get(key):
                    self.value_ids.add(str(row[key]))
            for key in ("register_address", "address", "mmio_address"):
                address = parse_int(row.get(key))
                if address is not None:
                    self.register_addresses.add(address)
        for child in row.values():
            if isinstance(child, (dict, list)):
                self._consume(child)

    def is_external_load(self, load: dict[str, Any]) -> bool:
        if op_site(load) in self.load_sites:
            return True
        output_id = node_value_id(operation_output(load))
        if output_id and output_id in self.value_ids:
            return True
        inputs = operation_inputs(load)
        address = node_constant(inputs[-1]) if inputs else None
        return address is not None and address in self.register_addresses


def vulnerable_parameter(
    role: str,
    node: dict[str, Any],
    *,
    origin_kind: str,
    expression_text: str = "",
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "role": role,
        "expr": expression(node, expression_text),
        "constant": node_constant(node) is not None,
        "origin_kind": origin_kind,
    }
    if node_value_id(node):
        row["value_id"] = node_value_id(node)
    if node_object_id(node):
        row["object_id"] = node_object_id(node)
    slot = parameter_slot(node)
    if slot is not None:
        row["parameter_slot"] = slot
    return row


def base_parameter(
    role: str, progression: AddressProgression, cfg: FunctionCFG
) -> dict[str, Any]:
    row = vulnerable_parameter(
        role,
        progression.base_node,
        origin_kind="memory_content",
    )
    formal = cfg.formal_access(progression.base_node)
    if formal is not None:
        row["parameter_slot"] = formal[0]
        row["access_path"] = list(formal[1])
        if not row.get("expr") or row.get("expr") == "UNNAMED":
            row["expr"] = f"arg{formal[0]}"
    return row


def scalar_parameter(
    role: str, node: dict[str, Any], cfg: FunctionCFG
) -> dict[str, Any]:
    row = vulnerable_parameter(role, node, origin_kind="scalar")
    formal = cfg.formal_access(node)
    if formal is not None:
        row["parameter_slot"] = formal[0]
        row["access_path"] = list(formal[1])
        if not row.get("expr") or row.get("expr") == "UNNAMED":
            row["expr"] = f"arg{formal[0]}"
    return row


def bounded_sink_row(
    *,
    program_facts: dict[str, Any],
    function: dict[str, Any],
    site: dict[str, Any],
    sink_type: str,
    method: str,
    roles: dict[str, str],
    vulnerable_parameters: list[dict[str, Any]],
    object_roles: dict[str, dict[str, Any]],
    proof: dict[str, Any],
) -> dict[str, Any]:
    site_id = op_site(site)
    function_id = str(function.get("function_id", ""))
    binary_sha256 = str(program_facts.get("binary_sha256", ""))
    return {
        "id": stable_id("sink", binary_sha256, function_id, site_id, method),
        "sink_id": stable_id("sink", binary_sha256, function_id, site_id, method),
        "label": sink_type,
        "sink_type": sink_type,
        "recognition": "heuristic",
        "recognition_method": method,
        "detection_kind": f"high_pcode_cfg_{method}",
        "function_id": function_id,
        "function": str(function.get("name", "")),
        "site_id": site_id,
        "effect_site_id": site_id,
        "instruction_address": str(site.get("instruction_address", "")),
        "expr": f"{method}@{site_id}",
        "roles": roles,
        "vulnerable_parameter_roles": [
            str(row.get("role", "")) for row in vulnerable_parameters
        ],
        "vulnerable_parameters": vulnerable_parameters,
        "object_roles": object_roles,
        "binding_status": "verified_high_pcode_cfg_pattern",
        "decision": "ACCEPT_HEURISTIC",
        "evidence_level": "HEURISTIC_HIGH_PCODE_CFG_PATTERN",
        "taint_status": "not_evaluated",
        "check_status": "unknown",
        "vulnerability_status": "not_evaluated",
        "proof": proof,
        "boundary_callsites": [],
    }


def compatible_progressions(
    first: AddressProgression, second: AddressProgression, loop: NaturalLoop
) -> bool:
    return bool(
        first.recurrence.update_block_id in loop.blocks
        and second.recurrence.update_block_id in loop.blocks
        and first.stride != 0
        and second.stride != 0
        and abs(first.stride) == abs(second.stride)
    )


def select_loop_bound(
    bounds: Iterable[Any],
    recurrences: Iterable[Recurrence],
) -> Any | None:
    recurrence_ids = {row.phi_value_id for row in recurrences}
    candidates = [
        row for row in bounds if row.recurrence.phi_value_id in recurrence_ids
    ]
    return candidates[0] if candidates else None


def iteration_extent_node(bound: Any, cfg: FunctionCFG) -> dict[str, Any]:
    """Return the value that controls the number of loop iterations.

    For ``i < count`` this is the comparison bound.  For the common countdown
    form ``remaining != 0; remaining--`` the comparison bound is the constant
    zero, while the initial recurrence value is the externally supplied
    extent.
    """

    if (
        node_constant(bound.bound_node) is not None
        and node_constant(bound.recurrence.initial_node) is None
    ):
        return dict(bound.recurrence.initial_node)
    initial = cfg.formal_access(bound.recurrence.initial_node)
    terminal = cfg.formal_access(bound.bound_node)
    if initial is not None and terminal is not None and initial[0] == terminal[0]:
        initial_offset = sum(initial[1])
        terminal_offset = sum(terminal[1])
        step = int(bound.recurrence.step)
        distance = terminal_offset - initial_offset
        if step and distance and distance % step == 0 and distance // step > 0:
            extent = distance // step
            return {
                "object_id": f"const:{extent:x}:4",
                "value_id": f"const:{extent:x}:4",
                "space": "const",
                "offset": hex(extent),
                "size": 4,
                "high_name": "",
                "high_data_type": "size_t",
                "is_parameter": False,
                "parameter_slot": None,
                "is_constant": True,
            }
    return dict(bound.bound_node)


def counted_range_candidates(
    program_facts: dict[str, Any],
    function: dict[str, Any],
    cfg: FunctionCFG,
    source_index: SourceEvidenceIndex,
) -> tuple[list[dict[str, Any]], list[CandidateDecision]]:
    sinks: list[dict[str, Any]] = []
    decisions: list[CandidateDecision] = []
    for loop in cfg.loops:
        stores = [
            op
            for op in cfg.loop_ops(loop)
            if str(op.get("mnemonic", "")) == "STORE"
        ]
        if not stores:
            continue
        recurrences = cfg.recurrences(loop)
        bounds = cfg.loop_bounds(loop, recurrences)
        for store in stores:
            evidence: dict[str, Any] = {
                "candidate_stage": {
                    "loop": loop.as_json(),
                    "store_site_id": op_site(store),
                }
            }

            def reject(code: str, extra: dict[str, Any] | None = None) -> None:
                if extra:
                    evidence.update(extra)
                decisions.append(
                    CandidateDecision(
                        "counted_range",
                        cfg.function_id,
                        str(function.get("name", "")),
                        op_site(store),
                        loop.loop_id,
                        "rejected",
                        code,
                        evidence,
                    )
                )

            if not recurrences:
                reject("counted_range_no_fixed_stride_recurrence")
                continue
            if not bounds:
                reject("counted_range_no_recurrence_bound_exit")
                continue
            store_inputs = operation_inputs(store)
            if len(store_inputs) < 3:
                reject("malformed_store_operands")
                continue
            destination = cfg.address_progression(
                store_inputs[-2], loop, recurrences
            )
            if destination is None:
                reject("counted_range_destination_not_fixed_stride")
                continue
            bound = select_loop_bound(bounds, recurrences)
            if bound is None:
                reject("counted_range_bound_not_recovered")
                continue
            extent = iteration_extent_node(bound, cfg)

            stored_value = store_inputs[-1]
            load = cfg.unique_load_origin(stored_value)
            if load is not None:
                if source_index.is_external_load(load):
                    reject(
                        "excluded_external_input_mmio_to_buffer_source",
                        {
                            "source_exclusion": {
                                "load_site_id": op_site(load),
                                "load_value_id": node_value_id(operation_output(load)),
                            }
                        },
                    )
                    continue
                load_inputs = operation_inputs(load)
                source = (
                    cfg.address_progression(load_inputs[-1], loop, recurrences)
                    if len(load_inputs) >= 2
                    else None
                )
                if source is None:
                    reject("counted_range_copy_source_not_fixed_stride")
                    continue
                if not compatible_progressions(destination, source, loop):
                    reject(
                        "counted_range_source_destination_stride_mismatch",
                        {
                            "destination": destination.as_json(),
                            "source": source.as_json(),
                        },
                    )
                    continue
                parameters = [
                    base_parameter("src", source, cfg),
                ]
                if node_constant(extent) is None:
                    parameters.append(scalar_parameter("len", extent, cfg))
                if immutable_memory_pointer(program_facts, source.base_node):
                    parameters = [
                        row for row in parameters if row.get("role") != "src"
                    ]
                if not parameters:
                    reject("no_trackable_vulnerable_parameter")
                    continue
                proof = {
                    "pattern": "counted_range_copy_v1",
                    "loop": loop.as_json(),
                    "store_site_id": op_site(store),
                    "load_site_id": op_site(load),
                    "destination_progression": destination.as_json(),
                    "source_progression": source.as_json(),
                    "loop_bound": bound.as_json(),
                    "stored_value_lineage": "unchanged_from_load",
                }
                sink = bounded_sink_row(
                    program_facts=program_facts,
                    function=function,
                    site=store,
                    sink_type="COPY_SINK",
                    method="counted_range_copy",
                    roles={
                        "dst": expression(destination.base_node),
                        "src": expression(source.base_node),
                        "len": expression(extent),
                    },
                    vulnerable_parameters=parameters,
                    object_roles={
                        "dst": {
                            "expr": expression(destination.base_node),
                            "object_id": node_object_id(destination.base_node),
                            "value_id": node_value_id(destination.base_node),
                        }
                    },
                    proof=proof,
                )
                sinks.append(sink)
                decisions.append(
                    CandidateDecision(
                        "counted_range",
                        cfg.function_id,
                        str(function.get("name", "")),
                        op_site(store),
                        loop.loop_id,
                        "confirmed",
                        "confirmed_counted_range_copy",
                        proof,
                    )
                )
                continue

            if not cfg.loop_invariant(stored_value, loop):
                reject("counted_range_stored_value_not_copy_or_invariant_fill")
                continue
            parameters = []
            if node_constant(extent) is None:
                parameters.append(scalar_parameter("len", extent, cfg))
            if not parameters:
                reject("no_trackable_vulnerable_parameter")
                continue
            proof = {
                "pattern": "counted_range_fill_v1",
                "loop": loop.as_json(),
                "store_site_id": op_site(store),
                "destination_progression": destination.as_json(),
                "loop_bound": bound.as_json(),
                "fill_value": expression(stored_value),
                "fill_value_loop_invariant": True,
            }
            sinks.append(
                bounded_sink_row(
                    program_facts=program_facts,
                    function=function,
                    site=store,
                    sink_type="MEMSET_SINK",
                    method="counted_range_fill",
                    roles={
                        "dst": expression(destination.base_node),
                        "value": expression(stored_value),
                        "len": expression(extent),
                    },
                    vulnerable_parameters=parameters,
                    object_roles={
                        "dst": {
                            "expr": expression(destination.base_node),
                            "object_id": node_object_id(destination.base_node),
                            "value_id": node_value_id(destination.base_node),
                        }
                    },
                    proof=proof,
                )
            )
            decisions.append(
                CandidateDecision(
                    "counted_range",
                    cfg.function_id,
                    str(function.get("name", "")),
                    op_site(store),
                    loop.loop_id,
                    "confirmed",
                    "confirmed_counted_range_fill",
                    proof,
                )
            )
    return sinks, decisions


def sentinel_copy_candidates(
    program_facts: dict[str, Any],
    function: dict[str, Any],
    cfg: FunctionCFG,
    source_index: SourceEvidenceIndex,
) -> tuple[list[dict[str, Any]], list[CandidateDecision]]:
    sinks: list[dict[str, Any]] = []
    decisions: list[CandidateDecision] = []
    for loop in cfg.loops:
        ops = cfg.loop_ops(loop)
        stores = [op for op in ops if str(op.get("mnemonic", "")) == "STORE"]
        loads = [op for op in ops if str(op.get("mnemonic", "")) == "LOAD"]
        branches = cfg.controlling_branches(loop)
        if not stores or not loads or not branches:
            continue
        recurrences = cfg.recurrences(loop)
        for store in stores:
            evidence: dict[str, Any] = {
                "candidate_stage": {
                    "loop": loop.as_json(),
                    "store_site_id": op_site(store),
                    "load_sites": [op_site(load) for load in loads],
                    "branch_sites": [op_site(branch) for branch in branches],
                }
            }

            def reject(code: str, extra: dict[str, Any] | None = None) -> None:
                if extra:
                    evidence.update(extra)
                decisions.append(
                    CandidateDecision(
                        "sentinel_copy",
                        cfg.function_id,
                        str(function.get("name", "")),
                        op_site(store),
                        loop.loop_id,
                        "rejected",
                        code,
                        evidence,
                    )
                )

            store_inputs = operation_inputs(store)
            if len(store_inputs) < 3:
                reject("malformed_store_operands")
                continue
            load = cfg.unique_load_origin(store_inputs[-1])
            if load is None:
                reject("sentinel_store_value_not_unchanged_load")
                continue
            if source_index.is_external_load(load):
                reject(
                    "excluded_external_input_mmio_to_buffer_source",
                    {"source_exclusion": {"load_site_id": op_site(load)}},
                )
                continue
            load_inputs = operation_inputs(load)
            if len(load_inputs) < 2:
                reject("malformed_load_operands")
                continue
            destination = cfg.address_progression(
                store_inputs[-2], loop, recurrences
            )
            source = cfg.address_progression(load_inputs[-1], loop, recurrences)
            if destination is None or source is None:
                reject("sentinel_source_or_destination_not_fixed_stride")
                continue
            if not compatible_progressions(destination, source, loop):
                reject(
                    "sentinel_source_destination_stride_mismatch",
                    {
                        "destination": destination.as_json(),
                        "source": source.as_json(),
                    },
                )
                continue

            load_value_id = node_value_id(operation_output(load))
            sentinel_match: tuple[dict[str, Any], dict[str, Any], int] | None = None
            for branch in branches:
                comparison_row = comparison_for_branch(cfg, branch)
                if comparison_row is None:
                    continue
                comparison, parts = comparison_row
                if str(comparison.get("mnemonic", "")) not in {
                    "INT_EQUAL",
                    "INT_NOTEQUAL",
                }:
                    continue
                left_flow = cfg.flows_unchanged(parts[0], load_value_id)
                right_flow = cfg.flows_unchanged(parts[1], load_value_id)
                if left_flow == right_flow:
                    continue
                sentinel_node = parts[1] if left_flow else parts[0]
                sentinel = node_constant(sentinel_node)
                if sentinel is None:
                    continue
                sentinel_match = comparison, branch, sentinel
                break
            if sentinel_match is None:
                reject("sentinel_branch_does_not_test_stored_load_value")
                continue

            comparison, branch, sentinel = sentinel_match
            parameters = [base_parameter("src", source, cfg)]
            if immutable_memory_pointer(program_facts, source.base_node):
                parameters = []
            if not parameters:
                reject("no_trackable_vulnerable_parameter")
                continue
            proof = {
                "pattern": "sentinel_copy_v1",
                "loop": loop.as_json(),
                "store_site_id": op_site(store),
                "load_site_id": op_site(load),
                "comparison_site_id": op_site(comparison),
                "branch_site_id": op_site(branch),
                "sentinel": sentinel,
                "destination_progression": destination.as_json(),
                "source_progression": source.as_json(),
                "stored_value_lineage": "unchanged_from_load",
            }
            sinks.append(
                bounded_sink_row(
                    program_facts=program_facts,
                    function=function,
                    site=store,
                    sink_type="COPY_SINK",
                    method="sentinel_copy",
                    roles={
                        "dst": expression(destination.base_node),
                        "src": expression(source.base_node),
                        "sentinel": hex(sentinel),
                    },
                    vulnerable_parameters=parameters,
                    object_roles={
                        "dst": {
                            "expr": expression(destination.base_node),
                            "object_id": node_object_id(destination.base_node),
                            "value_id": node_value_id(destination.base_node),
                        }
                    },
                    proof=proof,
                )
            )
            decisions.append(
                CandidateDecision(
                    "sentinel_copy",
                    cfg.function_id,
                    str(function.get("name", "")),
                    op_site(store),
                    loop.loop_id,
                    "confirmed",
                    "confirmed_sentinel_copy",
                    proof,
                )
            )
    return sinks, decisions


@dataclass(frozen=True)
class FieldUpdate:
    effect_kind: str
    direction: str
    base_slot: int
    base_path: tuple[int, ...]
    field_offset: int
    delta_node: dict[str, Any]
    delta_key: tuple[Any, ...]
    load_site_id: str
    arithmetic_site_id: str
    store_site_id: str
    store_block_id: str

    def as_json(self) -> dict[str, Any]:
        return {
            "effect_kind": self.effect_kind,
            "direction": self.direction,
            "base_parameter_slot": self.base_slot,
            "base_access_path": list(self.base_path),
            "field_offset": self.field_offset,
            "delta": expression(self.delta_node),
            "delta_value_id": node_value_id(self.delta_node),
            "load_site_id": self.load_site_id,
            "arithmetic_site_id": self.arithmetic_site_id,
            "store_site_id": self.store_site_id,
            "store_block_id": self.store_block_id,
        }


@dataclass(frozen=True)
class MemoryStateRecurrence:
    load: dict[str, Any]
    update_store: dict[str, Any]
    location_key: tuple[Any, ...]
    step: int

    def as_json(self) -> dict[str, Any]:
        return {
            "load_site_id": op_site(self.load),
            "load_value_id": node_value_id(operation_output(self.load)),
            "update_store_site_id": op_site(self.update_store),
            "location_key": list(self.location_key),
            "step": self.step,
        }


def stable_memory_location(
    cfg: FunctionCFG, node: dict[str, Any]
) -> tuple[Any, ...] | None:
    """Identify a concrete memory slot without guessing pointer targets."""

    current = cfg.strip_transparent(node)
    formal = cfg.formal_access(current)
    if formal is not None:
        return ("formal", formal[0], tuple(formal[1]))
    object_id = node_object_id(current)
    if object_id.startswith(("global:", "symbol:", "stack:")):
        return ("object", object_id)
    if bool(current.get("is_address")) and str(current.get("space", "")) == "ram":
        address = parse_int(current.get("offset"))
        if address is not None:
            return ("ram", address, int(current.get("size", 0) or 0))
    return None


def lineage_loads(
    cfg: FunctionCFG, node: dict[str, Any], *, limit: int = 128
) -> list[dict[str, Any]]:
    queue = [dict(node)]
    seen: set[str] = set()
    loads: dict[str, dict[str, Any]] = {}
    steps = 0
    while queue and steps < limit:
        current = queue.pop()
        steps += 1
        value_id = node_value_id(current)
        if not value_id or value_id in seen:
            continue
        seen.add(value_id)
        definition = cfg.definitions.get(value_id)
        if not definition:
            continue
        mnemonic = str(definition.get("mnemonic", ""))
        if mnemonic == "LOAD":
            loads[op_site(definition)] = definition
            continue
        if mnemonic in {"CALL", "CALLIND", "STORE", "CALLOTHER"}:
            continue
        queue.extend(operation_inputs(definition))
    return list(loads.values())


def linear_state_step(
    cfg: FunctionCFG, value: dict[str, Any], old_value_id: str
) -> int | None:
    current = cfg.strip_transparent(value)
    definition = cfg.definitions.get(node_value_id(current))
    if not definition:
        return None
    mnemonic = str(definition.get("mnemonic", ""))
    parts = operation_inputs(definition)
    if mnemonic == "PTRADD" and len(parts) >= 3:
        scale = node_constant(cfg.strip_transparent(parts[2]))
        delta = node_constant(cfg.strip_transparent(parts[1]))
        if scale is None or delta is None:
            return None
        if not cfg.depends_on(parts[0], old_value_id):
            return None
        step = int(delta) * int(scale)
        return step if step else None
    if mnemonic not in {"INT_ADD", "INT_SUB"} or len(parts) != 2:
        return None
    old_positions = [
        position
        for position, part in enumerate(parts)
        if cfg.depends_on(part, old_value_id)
    ]
    if len(old_positions) != 1:
        return None
    old_position = old_positions[0]
    delta = node_constant(cfg.strip_transparent(parts[1 - old_position]))
    if delta is None or int(delta) == 0:
        return None
    if mnemonic == "INT_SUB" and old_position != 0:
        return None
    return -int(delta) if mnemonic == "INT_SUB" else int(delta)


def memory_state_recurrences(
    cfg: FunctionCFG,
    loop: NaturalLoop,
    destination: dict[str, Any],
) -> list[MemoryStateRecurrence]:
    recurrences: list[MemoryStateRecurrence] = []
    loop_stores = [
        op
        for op in cfg.loop_ops(loop)
        if str(op.get("mnemonic", "")) == "STORE"
    ]
    for load in lineage_loads(cfg, destination):
        load_inputs = operation_inputs(load)
        if len(load_inputs) < 2:
            continue
        location_key = stable_memory_location(cfg, load_inputs[-1])
        old_value_id = node_value_id(operation_output(load))
        if location_key is None or not old_value_id:
            continue
        for update_store in loop_stores:
            update_inputs = operation_inputs(update_store)
            if len(update_inputs) < 3:
                continue
            if stable_memory_location(cfg, update_inputs[-2]) != location_key:
                continue
            step = linear_state_step(cfg, update_inputs[-1], old_value_id)
            if step is None:
                continue
            recurrences.append(
                MemoryStateRecurrence(
                    load=load,
                    update_store=update_store,
                    location_key=location_key,
                    step=step,
                )
            )
    return recurrences


def delta_lineage_key(
    cfg: FunctionCFG, node: dict[str, Any]
) -> tuple[Any, ...] | None:
    current = cfg.strip_transparent(node)
    if node_constant(current) is not None:
        return None
    formal = cfg.formal_access(current)
    if formal is not None:
        return ("formal", formal[0], formal[1])
    value_id = node_value_id(current)
    return ("value", value_id) if value_id else None


def recover_field_update(
    cfg: FunctionCFG, store: dict[str, Any]
) -> FieldUpdate | None:
    inputs = operation_inputs(store)
    if len(inputs) < 3:
        return None
    destination = cfg.formal_access(inputs[-2])
    if destination is None or not destination[1]:
        return None
    base_slot, access_path = destination
    base_path = access_path[:-1]
    field_offset = access_path[-1]
    arithmetic = cfg.definitions.get(node_value_id(cfg.strip_transparent(inputs[-1])))
    if not arithmetic:
        return None
    mnemonic = str(arithmetic.get("mnemonic", ""))
    parts = operation_inputs(arithmetic)
    if mnemonic not in {"INT_ADD", "INT_SUB", "PTRADD"}:
        return None

    old_node: dict[str, Any] | None = None
    delta_node: dict[str, Any] | None = None
    direction = ""
    if mnemonic == "PTRADD" and len(parts) >= 3:
        if node_constant(parts[2]) != 1:
            return None
        old_node, delta_node, direction = parts[0], parts[1], "add"
    elif mnemonic == "INT_SUB" and len(parts) == 2:
        old_node, delta_node, direction = parts[0], parts[1], "sub"
    elif mnemonic == "INT_ADD" and len(parts) == 2:
        origins = [cfg.unique_load_origin(part) for part in parts]
        matches = []
        for position, load in enumerate(origins):
            load_inputs = operation_inputs(load or {})
            if len(load_inputs) >= 2 and cfg.formal_access(load_inputs[-1]) == destination:
                matches.append(position)
        if len(matches) != 1:
            return None
        old_position = matches[0]
        old_node = parts[old_position]
        delta_node = parts[1 - old_position]
        direction = "add"
    if old_node is None or delta_node is None:
        return None

    old_load = cfg.unique_load_origin(old_node)
    old_inputs = operation_inputs(old_load or {})
    if len(old_inputs) < 2 or cfg.formal_access(old_inputs[-1]) != destination:
        return None
    delta_key = delta_lineage_key(cfg, delta_node)
    if delta_key is None:
        return None
    old_type = str(operation_output(old_load or {}).get("high_data_type", "") or "")
    result_type = str(operation_output(arithmetic).get("high_data_type", "") or "")
    effect_kind = "cursor" if mnemonic == "PTRADD" or "*" in f"{old_type} {result_type}" else "scalar"
    return FieldUpdate(
        effect_kind=effect_kind,
        direction=direction,
        base_slot=base_slot,
        base_path=base_path,
        field_offset=field_offset,
        delta_node=delta_node,
        delta_key=delta_key,
        load_site_id=op_site(old_load or {}),
        arithmetic_site_id=op_site(arithmetic),
        store_site_id=op_site(store),
        store_block_id=str(store.get("block_id", "")),
    )


def definitely_mutually_exclusive(
    cfg: FunctionCFG, first_block: str, second_block: str
) -> bool:
    """Recognize only explicit sibling branch arms as mutually exclusive."""

    if first_block == second_block:
        return False
    if cfg.block_reaches(first_block, second_block) or cfg.block_reaches(
        second_block, first_block
    ):
        return False
    for branch_block, successors in cfg.successors.items():
        if len(successors) < 2:
            continue
        if branch_block not in cfg.dominators.get(first_block, set()):
            continue
        if branch_block not in cfg.dominators.get(second_block, set()):
            continue
        first_arms = {
            successor
            for successor in successors
            if cfg.block_reaches(successor, first_block)
        }
        second_arms = {
            successor
            for successor in successors
            if cfg.block_reaches(successor, second_block)
        }
        if first_arms and second_arms and first_arms.isdisjoint(second_arms):
            return True
    return False


def paired_buffer_state_candidates(
    program_facts: dict[str, Any],
    function: dict[str, Any],
    cfg: FunctionCFG,
) -> tuple[list[dict[str, Any]], list[CandidateDecision]]:
    sinks: list[dict[str, Any]] = []
    decisions: list[CandidateDecision] = []
    stores = [
        op for op in cfg.ops if str(op.get("mnemonic", "")) == "STORE"
    ]
    updates: list[tuple[dict[str, Any], FieldUpdate]] = []
    for store in stores:
        update = recover_field_update(cfg, store)
        if update is not None:
            updates.append((store, update))
    if len(updates) < 2:
        if stores:
            decisions.append(
                CandidateDecision(
                    "paired_buffer_state",
                    cfg.function_id,
                    str(function.get("name", "")),
                    op_site(stores[0]),
                    "",
                    "rejected",
                    "paired_state_fewer_than_two_recoverable_field_updates",
                    {"store_sites": [op_site(store) for store in stores]},
                )
            )
        return sinks, decisions

    seen_pairs: set[tuple[str, str]] = set()
    compatible_found = False
    for first_index, (first_store, first) in enumerate(updates):
        for second_store, second in updates[first_index + 1 :]:
            pair_sites = tuple(sorted((first.store_site_id, second.store_site_id)))
            if pair_sites in seen_pairs:
                continue
            seen_pairs.add(pair_sites)
            evidence = {
                "first_update": first.as_json(),
                "second_update": second.as_json(),
            }
            if (first.base_slot, first.base_path) != (second.base_slot, second.base_path):
                reason = "paired_state_different_base_objects"
            elif first.field_offset == second.field_offset:
                reason = "paired_state_same_field"
            elif first.delta_key != second.delta_key:
                reason = "paired_state_different_amount_lineage"
            elif first.direction == second.direction:
                reason = "paired_state_updates_not_opposite"
            elif definitely_mutually_exclusive(
                cfg, first.store_block_id, second.store_block_id
            ):
                reason = "paired_state_updates_not_cfg_compatible"
            else:
                reason = ""
            if reason:
                decisions.append(
                    CandidateDecision(
                        "paired_buffer_state",
                        cfg.function_id,
                        str(function.get("name", "")),
                        pair_sites[0],
                        "",
                        "rejected",
                        reason,
                        evidence,
                    )
                )
                continue

            compatible_found = True
            amount = first.delta_node
            buffer_node = parameter_node_for_slot(
                function, cfg, first.base_slot
            )
            buffer_parameter = vulnerable_parameter(
                "buffer",
                buffer_node,
                origin_kind="memory_object",
                expression_text=f"arg{first.base_slot}",
            )
            buffer_parameter["parameter_slot"] = first.base_slot
            buffer_parameter["access_path"] = list(first.base_path)
            parameter = vulnerable_parameter("amount", amount, origin_kind="scalar")
            if first.delta_key and first.delta_key[0] == "formal":
                parameter["parameter_slot"] = int(first.delta_key[1])
                parameter["access_path"] = list(first.delta_key[2])
                if (
                    not parameter.get("expr")
                    or parameter.get("expr") == "UNNAMED"
                ):
                    parameter["expr"] = f"arg{first.delta_key[1]}"
            effect_site = first_store if op_site(first_store) == pair_sites[0] else second_store
            proof = {
                "pattern": "paired_buffer_state_v2",
                "state_effects": [first.as_json(), second.as_json()],
                "same_base_object": True,
                "same_amount_lineage": True,
                "opposite_state_updates": True,
                "cfg_relation": (
                    "dominance_supported"
                    if cfg.can_coexecute(
                        first.store_block_id, second.store_block_id
                    )
                    else "not_proved_mutually_exclusive"
                ),
                "effect_kind_evidence": sorted(
                    {first.effect_kind, second.effect_kind}
                ),
            }
            sinks.append(
                bounded_sink_row(
                    program_facts=program_facts,
                    function=function,
                    site=effect_site,
                    sink_type="BUFFER_STATE_SINK",
                    method="paired_buffer_state",
                    roles={
                        "buffer": f"arg{first.base_slot}",
                        "amount": expression(amount),
                    },
                    vulnerable_parameters=[buffer_parameter, parameter],
                    object_roles={
                        "buffer": {
                            "parameter_slot": first.base_slot,
                            "access_path": list(first.base_path),
                        }
                    },
                    proof=proof,
                )
            )
            decisions.append(
                CandidateDecision(
                    "paired_buffer_state",
                    cfg.function_id,
                    str(function.get("name", "")),
                    op_site(effect_site),
                    "",
                    "confirmed",
                    "confirmed_paired_buffer_state",
                    proof,
                )
            )
    if not compatible_found and not decisions:
        decisions.append(
            CandidateDecision(
                "paired_buffer_state",
                cfg.function_id,
                str(function.get("name", "")),
                op_site(stores[0]),
                "",
                "rejected",
                "paired_state_no_compatible_update_pair",
                {"store_sites": [op_site(store) for store in stores]},
            )
        )
    return sinks, decisions


def stateful_loop_write_candidates(
    program_facts: dict[str, Any],
    function: dict[str, Any],
    cfg: FunctionCFG,
    source_index: SourceEvidenceIndex,
) -> tuple[list[dict[str, Any]], list[CandidateDecision]]:
    """Recognize loop writes whose destination is advanced through RAM state."""

    sinks: list[dict[str, Any]] = []
    decisions: list[CandidateDecision] = []
    for loop in cfg.loops:
        stores = [
            op
            for op in cfg.loop_ops(loop)
            if str(op.get("mnemonic", "")) == "STORE"
        ]
        for store in stores:
            inputs = operation_inputs(store)
            if len(inputs) < 3:
                continue
            destination, stored_value = inputs[-2], inputs[-1]
            copied_load = cfg.unique_load_origin(stored_value)
            if copied_load is None:
                continue
            if source_index.is_external_load(copied_load):
                decisions.append(
                    CandidateDecision(
                        "stateful_loop_write",
                        cfg.function_id,
                        str(function.get("name", "")),
                        op_site(store),
                        loop.loop_id,
                        "rejected",
                        "excluded_external_input_mmio_to_buffer_source",
                        {"load_site_id": op_site(copied_load)},
                    )
                )
                continue
            recurrences = memory_state_recurrences(cfg, loop, destination)
            if not recurrences:
                continue

            load_inputs = operation_inputs(copied_load)
            source_address = load_inputs[-1] if len(load_inputs) >= 2 else {}
            source_slots = formal_slots_in_lineage(cfg, source_address)
            if len(source_slots) != 1:
                decisions.append(
                    CandidateDecision(
                        "stateful_loop_write",
                        cfg.function_id,
                        str(function.get("name", "")),
                        op_site(store),
                        loop.loop_id,
                        "rejected",
                        "stateful_loop_source_not_uniquely_formal_bound",
                        {
                            "load_site_id": op_site(copied_load),
                            "source_parameter_slots": sorted(source_slots),
                        },
                    )
                )
                continue

            source_slot = next(iter(source_slots))
            source_node = parameter_node_for_slot(function, cfg, source_slot)
            source_parameter = vulnerable_parameter(
                "src",
                source_node,
                origin_kind="memory_content",
                expression_text=f"arg{source_slot}",
            )
            source_parameter["parameter_slot"] = source_slot
            source_parameter["access_path"] = []
            vulnerable_parameters = [source_parameter]
            roles = {"src": expression(source_node, f"arg{source_slot}")}
            object_roles: dict[str, dict[str, Any]] = {}

            destination_slots = formal_slots_in_lineage(cfg, destination)
            if len(destination_slots) == 1:
                destination_slot = next(iter(destination_slots))
                destination_node = parameter_node_for_slot(
                    function, cfg, destination_slot
                )
                destination_parameter = vulnerable_parameter(
                    "dst",
                    destination_node,
                    origin_kind="memory_object",
                    expression_text=f"arg{destination_slot}",
                )
                destination_parameter["parameter_slot"] = destination_slot
                destination_parameter["access_path"] = []
                vulnerable_parameters.insert(0, destination_parameter)
                roles["dst"] = expression(
                    destination_node, f"arg{destination_slot}"
                )
                object_roles["dst"] = {
                    "parameter_slot": destination_slot,
                    "access_path": [],
                }

            recurrence = sorted(
                recurrences,
                key=lambda row: (
                    op_site(row.update_store),
                    op_site(row.load),
                ),
            )[0]
            state_node = operation_output(recurrence.load)
            state_parameter = vulnerable_parameter(
                "index",
                state_node,
                origin_kind="scalar",
            )
            vulnerable_parameters.append(state_parameter)
            roles["index"] = expression(state_node)
            proof = {
                "pattern": "stateful_loop_write_v1",
                "loop": loop.as_json(),
                "transfer": {
                    "load_site_id": op_site(copied_load),
                    "store_site_id": op_site(store),
                    "stored_value_lineage": "unchanged_load",
                },
                "destination_state_recurrence": recurrence.as_json(),
                "source_parameter_slot": source_slot,
                "destination_parameter_slots": sorted(destination_slots),
                "mmio_source_excluded": True,
            }
            sinks.append(
                bounded_sink_row(
                    program_facts=program_facts,
                    function=function,
                    site=store,
                    sink_type="LOOP_WRITE_SINK",
                    method="stateful_loop_write",
                    roles=roles,
                    vulnerable_parameters=vulnerable_parameters,
                    object_roles=object_roles,
                    proof=proof,
                )
            )
            decisions.append(
                CandidateDecision(
                    "stateful_loop_write",
                    cfg.function_id,
                    str(function.get("name", "")),
                    op_site(store),
                    loop.loop_id,
                    "confirmed",
                    "confirmed_stateful_loop_write",
                    proof,
                )
            )
    return sinks, decisions


def buffer_state_reservation_candidates(
    program_facts: dict[str, Any],
    function: dict[str, Any],
    cfg: FunctionCFG,
) -> tuple[list[dict[str, Any]], list[CandidateDecision]]:
    """Recognize reserve-at-old-tail effects under BUFFER_STATE_SINK."""

    sinks: list[dict[str, Any]] = []
    decisions: list[CandidateDecision] = []
    stores = [
        op for op in cfg.ops if str(op.get("mnemonic", "")) == "STORE"
    ]
    returns = [
        op for op in cfg.ops if str(op.get("mnemonic", "")) == "RETURN"
    ]
    for store in stores:
        update = recover_field_update(cfg, store)
        if update is None or update.direction != "add":
            continue
        update_load = cfg.definitions.get(
            node_value_id(cfg.strip_transparent(operation_inputs(store)[-1]))
        )
        if update_load is None:
            continue
        old_value_id = ""
        for part in operation_inputs(update_load):
            load = cfg.unique_load_origin(part)
            load_inputs = operation_inputs(load or {})
            if (
                len(load_inputs) >= 2
                and cfg.formal_access(load_inputs[-1])
                == (update.base_slot, update.base_path + (update.field_offset,))
            ):
                old_value_id = node_value_id(operation_output(load or {}))
                break
        if not old_value_id:
            continue

        matched_return: dict[str, Any] | None = None
        pointer_field: tuple[int, ...] | None = None
        for return_op in returns:
            return_inputs = operation_inputs(return_op)
            if not return_inputs:
                continue
            returned = return_inputs[-1]
            expression_op = cfg.definitions.get(
                node_value_id(cfg.strip_transparent(returned))
            )
            if not expression_op or str(expression_op.get("mnemonic", "")) not in {
                "PTRADD",
                "INT_ADD",
            }:
                continue
            parts = operation_inputs(expression_op)
            if not any(cfg.depends_on(part, old_value_id) for part in parts):
                continue
            for part in parts:
                pointer_load = cfg.unique_load_origin(part)
                pointer_inputs = operation_inputs(pointer_load or {})
                if len(pointer_inputs) < 2:
                    continue
                access = cfg.formal_access(pointer_inputs[-1])
                if (
                    access is None
                    or access[0] != update.base_slot
                    or tuple(access[1]) == update.base_path + (update.field_offset,)
                ):
                    continue
                pointer_field = tuple(access[1])
                matched_return = return_op
                break
            if matched_return is not None:
                break
        if matched_return is None or pointer_field is None:
            continue

        buffer_node = parameter_node_for_slot(function, cfg, update.base_slot)
        buffer_parameter = vulnerable_parameter(
            "buffer",
            buffer_node,
            origin_kind="memory_object",
            expression_text=f"arg{update.base_slot}",
        )
        buffer_parameter["parameter_slot"] = update.base_slot
        buffer_parameter["access_path"] = list(update.base_path)
        amount_parameter = vulnerable_parameter(
            "amount", update.delta_node, origin_kind="scalar"
        )
        if update.delta_key and update.delta_key[0] == "formal":
            amount_parameter["parameter_slot"] = int(update.delta_key[1])
            amount_parameter["access_path"] = list(update.delta_key[2])
            amount_parameter["expr"] = f"arg{update.delta_key[1]}"
        proof = {
            "pattern": "buffer_state_reserve_v1",
            "length_update": update.as_json(),
            "returned_pointer_site_id": op_site(matched_return),
            "pointer_field_access_path": list(pointer_field),
            "same_base_object": True,
            "old_state_used_in_return_pointer": True,
        }
        sinks.append(
            bounded_sink_row(
                program_facts=program_facts,
                function=function,
                site=store,
                sink_type="BUFFER_STATE_SINK",
                method="buffer_state_reserve",
                roles={
                    "buffer": f"arg{update.base_slot}",
                    "amount": expression(update.delta_node),
                },
                vulnerable_parameters=[buffer_parameter, amount_parameter],
                object_roles={
                    "buffer": {
                        "parameter_slot": update.base_slot,
                        "access_path": list(update.base_path),
                    }
                },
                proof=proof,
            )
        )
        decisions.append(
            CandidateDecision(
                "buffer_state_reserve",
                cfg.function_id,
                str(function.get("name", "")),
                op_site(store),
                "",
                "confirmed",
                "confirmed_buffer_state_reservation",
                proof,
            )
        )
    return sinks, decisions


@dataclass(frozen=True)
class SwapTransfer:
    store: dict[str, Any]
    load: dict[str, Any]
    destination: AddressProgression
    source: AddressProgression

    def as_json(self) -> dict[str, Any]:
        return {
            "store_site_id": op_site(self.store),
            "load_site_id": op_site(self.load),
            "destination": self.destination.as_json(),
            "source": self.source.as_json(),
        }


def pointer_like_type(type_name: str) -> bool:
    text = type_name.replace(" ", "")
    return "*" in text or text.endswith("[]")


def formal_slots_in_lineage(
    cfg: FunctionCFG,
    node: dict[str, Any],
    *,
    limit: int = 128,
) -> set[int]:
    queue = [dict(node)]
    seen: set[str] = set()
    slots: set[int] = set()
    steps = 0
    while queue and steps < limit:
        current = queue.pop()
        steps += 1
        slot = parameter_slot(current)
        if slot is not None:
            slots.add(slot)
            continue
        value_id = node_value_id(current)
        if not value_id or value_id in seen:
            continue
        seen.add(value_id)
        definition = cfg.definitions.get(value_id)
        if not definition:
            continue
        if str(definition.get("mnemonic", "")) in {
            "CALL",
            "CALLIND",
            "LOAD",
            "STORE",
        }:
            continue
        queue.extend(operation_inputs(definition))
    return slots


def object_ids_in_lineage(
    cfg: FunctionCFG,
    node: dict[str, Any],
    *,
    limit: int = 128,
) -> set[str]:
    queue = [dict(node)]
    seen: set[str] = set()
    objects: set[str] = set()
    steps = 0
    while queue and steps < limit:
        current = queue.pop()
        steps += 1
        object_id = node_object_id(current)
        if object_id.startswith(("global:", "stack:", "symbol:")):
            objects.add(object_id)
        value_id = node_value_id(current)
        if not value_id or value_id in seen:
            continue
        seen.add(value_id)
        definition = cfg.definitions.get(value_id)
        if not definition:
            continue
        if str(definition.get("mnemonic", "")) in {
            "CALL",
            "CALLIND",
            "LOAD",
            "STORE",
        }:
            continue
        queue.extend(operation_inputs(definition))
    return objects


def progression_base_identity(
    cfg: FunctionCFG,
    function: dict[str, Any],
    progression: AddressProgression,
) -> tuple[str, Any] | None:
    slots = formal_slots_in_lineage(cfg, progression.base_node)
    parameter_types = {
        int(row.get("index", -1)): str(row.get("data_type", ""))
        for row in list(function.get("parameters", []) or [])
        if isinstance(row.get("index"), int)
    }
    pointer_slots = {
        slot for slot in slots if pointer_like_type(parameter_types.get(slot, ""))
    }
    if len(pointer_slots) == 1:
        return ("formal", next(iter(pointer_slots)))
    formal = cfg.formal_access(progression.base_node)
    if formal is not None:
        return ("formal", formal[0])
    objects = object_ids_in_lineage(cfg, progression.base_node)
    if len(objects) == 1:
        return ("object", next(iter(objects)))
    return None


def progression_location_key(
    cfg: FunctionCFG,
    function: dict[str, Any],
    progression: AddressProgression,
) -> tuple[Any, ...] | None:
    base = progression_base_identity(cfg, function, progression)
    if base is None:
        return None
    return (
        base,
        progression.recurrence.phi_value_id,
        progression.stride,
    )


def parameter_node_for_slot(
    function: dict[str, Any], cfg: FunctionCFG, slot: int
) -> dict[str, Any]:
    for op in cfg.ops:
        for node in [*operation_inputs(op), operation_output(op)]:
            if parameter_slot(node) == slot:
                return dict(node)
    for row in list(function.get("parameters", []) or []):
        if row.get("index") != slot:
            continue
        return {
            "object_id": str(
                row.get("object_id", "")
                or f"param:{str(function.get('entry', '')).removeprefix('0x')}:{slot}"
            ),
            "value_id": "",
            "space": "register",
            "offset": "",
            "size": 0,
            "high_name": str(row.get("name", "") or f"arg{slot}"),
            "high_data_type": str(row.get("data_type", "")),
            "is_parameter": True,
            "parameter_slot": slot,
            "is_constant": False,
        }
    return {}


def in_place_swap_candidates(
    program_facts: dict[str, Any],
    function: dict[str, Any],
    cfg: FunctionCFG,
) -> tuple[list[dict[str, Any]], list[CandidateDecision]]:
    sinks: list[dict[str, Any]] = []
    decisions: list[CandidateDecision] = []
    for loop in cfg.loops:
        recurrences = cfg.recurrences(loop)
        transfers: list[SwapTransfer] = []
        stores = [
            op
            for op in cfg.loop_ops(loop)
            if str(op.get("mnemonic", "")) == "STORE"
        ]
        for store in stores:
            inputs = operation_inputs(store)
            if len(inputs) < 3:
                continue
            destination = cfg.address_progression(
                inputs[-2], loop, recurrences
            )
            load = cfg.unique_load_origin(inputs[-1])
            load_inputs = operation_inputs(load or {})
            source = (
                cfg.address_progression(load_inputs[-1], loop, recurrences)
                if len(load_inputs) >= 2
                else None
            )
            if destination is None or load is None or source is None:
                continue
            transfers.append(
                SwapTransfer(
                    store=store,
                    load=load,
                    destination=destination,
                    source=source,
                )
            )

        emitted = False
        for first_index, first in enumerate(transfers):
            for second in transfers[first_index + 1 :]:
                first_dst = progression_location_key(
                    cfg, function, first.destination
                )
                first_src = progression_location_key(cfg, function, first.source)
                second_dst = progression_location_key(
                    cfg, function, second.destination
                )
                second_src = progression_location_key(
                    cfg, function, second.source
                )
                if None in {first_dst, first_src, second_dst, second_src}:
                    continue
                if first_dst != second_src or second_dst != first_src:
                    continue
                base = progression_base_identity(
                    cfg, function, first.destination
                )
                if base is None or base != progression_base_identity(
                    cfg, function, first.source
                ):
                    continue
                if base != progression_base_identity(
                    cfg, function, second.destination
                ) or base != progression_base_identity(
                    cfg, function, second.source
                ):
                    continue

                vulnerable_parameters: list[dict[str, Any]] = []
                object_roles: dict[str, dict[str, Any]] = {}
                roles: dict[str, str] = {}
                buffer_slot: int | None = None
                if base[0] == "formal":
                    buffer_slot = int(base[1])
                    buffer_node = parameter_node_for_slot(
                        function, cfg, buffer_slot
                    )
                    buffer_parameter = vulnerable_parameter(
                        "buffer",
                        buffer_node,
                        origin_kind="memory_content",
                        expression_text=f"arg{buffer_slot}",
                    )
                    buffer_parameter["parameter_slot"] = buffer_slot
                    buffer_parameter["access_path"] = []
                    vulnerable_parameters.append(buffer_parameter)
                    roles["buffer"] = expression(
                        buffer_node, f"arg{buffer_slot}"
                    )
                    object_roles["buffer"] = {
                        "parameter_slot": buffer_slot,
                        "access_path": [],
                    }
                else:
                    roles["buffer"] = str(base[1])
                    object_roles["buffer"] = {"object_id": str(base[1])}

                bound_slots: set[int] = set()
                for bound in cfg.loop_bounds(loop, recurrences):
                    bound_slots.update(
                        formal_slots_in_lineage(cfg, bound.bound_node)
                    )
                    bound_slots.update(
                        formal_slots_in_lineage(
                            cfg, bound.recurrence.initial_node
                        )
                    )
                if buffer_slot is not None:
                    bound_slots.discard(buffer_slot)
                if len(bound_slots) == 1:
                    extent_slot = next(iter(bound_slots))
                    extent_node = parameter_node_for_slot(
                        function, cfg, extent_slot
                    )
                    extent_parameter = vulnerable_parameter(
                        "len",
                        extent_node,
                        origin_kind="scalar",
                        expression_text=f"arg{extent_slot}",
                    )
                    extent_parameter["parameter_slot"] = extent_slot
                    extent_parameter["access_path"] = []
                    if not extent_parameter["constant"]:
                        vulnerable_parameters.append(extent_parameter)
                        roles["len"] = expression(
                            extent_node, f"arg{extent_slot}"
                        )

                if not vulnerable_parameters:
                    continue
                proof = {
                    "pattern": "in_place_swap_v1",
                    "loop": loop.as_json(),
                    "cross_write_transfers": [
                        first.as_json(),
                        second.as_json(),
                    ],
                    "same_buffer_base": True,
                    "stored_value_lineage": "unchanged_cross_write",
                    "range_parameter_slots": sorted(bound_slots),
                    "progression_evidence": {
                        "first_stride": first.destination.stride,
                        "second_stride": second.destination.stride,
                    },
                }
                sinks.append(
                    bounded_sink_row(
                        program_facts=program_facts,
                        function=function,
                        site=first.store,
                        sink_type="LOOP_WRITE_SINK",
                        method="in_place_swap",
                        roles=roles,
                        vulnerable_parameters=vulnerable_parameters,
                        object_roles=object_roles,
                        proof=proof,
                    )
                )
                decisions.append(
                    CandidateDecision(
                        "in_place_swap",
                        cfg.function_id,
                        str(function.get("name", "")),
                        op_site(first.store),
                        loop.loop_id,
                        "confirmed",
                        "confirmed_in_place_swap",
                        proof,
                    )
                )
                emitted = True
                break
            if emitted:
                break
        if stores and not emitted:
            decisions.append(
                CandidateDecision(
                    "in_place_swap",
                    cfg.function_id,
                    str(function.get("name", "")),
                    op_site(stores[0]),
                    loop.loop_id,
                    "rejected",
                    "in_place_swap_no_cross_write_pair",
                    {"store_sites": [op_site(store) for store in stores]},
                )
            )
    return sinks, decisions


def dedupe_sinks(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        key = (
            str(row.get("function_id", "")),
            str(row.get("site_id", "")),
            str(row.get("recognition_method", "")),
            str(row.get("read_effect_id", "")),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result


def actual_expression(node: dict[str, Any]) -> str:
    return (
        str(node.get("high_name", "") or "").strip()
        or str(node.get("address", "") or "").strip()
        or node_value_id(node)
        or node_object_id(node)
    )


def normalized_function_body_hash(function: dict[str, Any]) -> str:
    """Hash address-independent High P-code shape for audit deduplication."""

    blocks = list(function.get("basic_blocks", []) or [])
    block_index = {
        str(block.get("block_id", "")): int(block.get("index", position) or position)
        for position, block in enumerate(blocks)
    }
    normalized_blocks = []
    for position, block in enumerate(blocks):
        successors = list(
            block.get("successor_block_ids", block.get("successors", [])) or []
        )
        normalized_blocks.append(
            {
                "index": int(block.get("index", position) or position),
                "successors": sorted(
                    block_index.get(str(target), -1) for target in successors
                ),
            }
        )
    normalized_ops = []
    for op in list(function.get("pcode_ops", []) or []):
        inputs = []
        for node in list(op.get("inputs", []) or []):
            row = dict(node)
            inputs.append(
                {
                    "constant": (
                        node_constant(row) if bool(row.get("is_constant")) else None
                    ),
                    "parameter_slot": row.get("parameter_slot"),
                    "size": int(row.get("size", 0) or 0),
                    "type": str(row.get("high_data_type", "") or ""),
                }
            )
        output = dict(op.get("output", {}) or {})
        normalized_ops.append(
            {
                "block": block_index.get(str(op.get("block_id", "")), -1),
                "mnemonic": str(op.get("mnemonic", "")),
                "inputs": inputs,
                "output_size": int(output.get("size", 0) or 0),
                "output_type": str(output.get("high_data_type", "") or ""),
            }
        )
    payload = json.dumps(
        {
            "blocks": sorted(normalized_blocks, key=lambda row: row["index"]),
            "ops": normalized_ops,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class BodyRoleBinding:
    role: str
    kind: str
    origin_kind: str
    parameter_slot: int | None = None
    access_path: tuple[int, ...] = ()
    constant: int | None = None

    def key(self) -> tuple[Any, ...]:
        return (
            self.role,
            self.kind,
            self.origin_kind,
            self.parameter_slot,
            self.access_path,
            self.constant,
        )


@dataclass(frozen=True)
class BodyEffectSummary:
    summary_id: str
    function_id: str
    method: str
    label: str
    bindings: tuple[BodyRoleBinding, ...]
    implementation_function_id: str
    implementation_function: str
    implementation_body_hash: str
    effect_site_ids: tuple[str, ...]
    depth: int
    proof_path: tuple[str, ...]

    def key(self) -> tuple[Any, ...]:
        return (
            self.function_id,
            self.method,
            self.label,
            tuple(binding.key() for binding in self.bindings),
            self.implementation_function_id,
            self.effect_site_ids,
        )


def body_actual_binding(
    index: ProgramIndex,
    function_id: str,
    node: dict[str, Any],
    *,
    role: str,
    origin_kind: str,
    inherited_path: tuple[int, ...] = (),
) -> BodyRoleBinding | None:
    formal = formal_access_path(
        node, index.definitions_by_function.get(function_id, {})
    )
    if formal is not None:
        return BodyRoleBinding(
            role=role,
            kind="formal",
            origin_kind=origin_kind,
            parameter_slot=formal[0],
            access_path=tuple(formal[1]) + inherited_path,
        )
    constant = node_constant(node)
    if constant is None:
        constant = index.resolve_constant(function_id, node)
    if constant is not None:
        return BodyRoleBinding(
            role=role,
            kind="constant",
            origin_kind=origin_kind,
            constant=int(constant),
        )
    return None


def thin_wrapper_call(function: dict[str, Any], op: dict[str, Any]) -> bool:
    calls = [
        candidate
        for candidate in list(function.get("pcode_ops", []) or [])
        if str(candidate.get("mnemonic", "")) in {"CALL", "CALLIND"}
    ]
    if len(calls) != 1 or op_site(calls[0]) != op_site(op):
        return False
    return not any(
        str(candidate.get("mnemonic", ""))
        in {"CBRANCH", "BRANCHIND", "CALLOTHER"}
        for candidate in list(function.get("pcode_ops", []) or [])
    )


def prune_body_parameters(
    program_facts: dict[str, Any],
    parameters: Iterable[dict[str, Any]],
    nodes_by_role: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    kept: list[dict[str, Any]] = []
    pruned: list[dict[str, Any]] = []
    nodes = nodes_by_role or {}
    for raw in parameters:
        row = dict(raw)
        role = str(row.get("role", ""))
        origin_kind = str(row.get("origin_kind", "scalar"))
        node = dict(nodes.get(role, {}) or {})
        is_constant = bool(row.get("constant"))
        if origin_kind == "scalar" and is_constant:
            row["prune_reason"] = "constant_scalar"
            pruned.append(row)
            continue
        if origin_kind in {"memory_content", "memory_object"} and is_constant:
            if node and immutable_memory_pointer(program_facts, node):
                row["prune_reason"] = "immutable_memory_object"
                pruned.append(row)
                continue
        kept.append(row)
    return kept, pruned


def body_effect_evidence(
    effect: dict[str, Any], function: dict[str, Any]
) -> dict[str, Any]:
    return {
        "function": str(effect.get("function", "")),
        "function_id": str(effect.get("function_id", "")),
        "site_id": str(effect.get("site_id", "")),
        "effect_site_id": str(effect.get("effect_site_id", "")),
        "instruction_address": str(effect.get("instruction_address", "")),
        "expr": str(effect.get("expr", "")),
        "binding_status": str(effect.get("binding_status", "")),
        "vulnerable_parameters": list(
            effect.get("vulnerable_parameters", []) or []
        ),
        "evidence_kind": "body_effect",
        "implementation_body_hash": normalized_function_body_hash(function),
    }


def materialize_body_sink_calls(
    program_facts: dict[str, Any],
    implementations: Iterable[dict[str, Any]],
    *,
    excluded_function_names: set[str] | None = None,
    max_wrapper_depth: int = 5,
) -> dict[str, Any]:
    """Materialize body effects at the outermost proved wrapper boundary.

    Implementations that have no resolvable caller remain concrete body-site
    startpoints. This preserves callback and top-level effects while avoiding
    duplicate inner/outer startpoints for a proved wrapper lineage.
    """

    excluded = set(excluded_function_names or ())
    index = ProgramIndex(program_facts)
    functions_by_id = {
        str(function.get("function_id", "")): dict(function)
        for function in list(program_facts.get("functions", []) or [])
    }
    implementation_rows = [
        dict(row)
        for row in implementations
        if str(row.get("function", "")) not in excluded
    ]
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    blockers: list[dict[str, Any]] = []
    for row in implementation_rows:
        bindings: list[BodyRoleBinding] = []
        for parameter in list(row.get("vulnerable_parameters", []) or []):
            slot = parameter.get("parameter_slot")
            if not isinstance(slot, int):
                bindings = []
                break
            bindings.append(
                BodyRoleBinding(
                    role=str(parameter.get("role", "")),
                    kind="formal",
                    origin_kind=str(parameter.get("origin_kind", "scalar")),
                    parameter_slot=slot,
                    access_path=tuple(parameter.get("access_path", []) or []),
                )
            )
        if not bindings:
            continue
        key = (
            str(row.get("function_id", "")),
            str(row.get("recognition_method", "")),
            str(row.get("label", "")),
            tuple(binding.key() for binding in bindings),
        )
        grouped.setdefault(key, []).append(row)

    summaries: list[BodyEffectSummary] = []
    for key, effects in grouped.items():
        function_id, method, label, _binding_key = key
        function = functions_by_id.get(function_id, {})
        bindings = tuple(
            BodyRoleBinding(
                role=str(parameter.get("role", "")),
                kind="formal",
                origin_kind=str(parameter.get("origin_kind", "scalar")),
                parameter_slot=int(parameter["parameter_slot"]),
                access_path=tuple(parameter.get("access_path", []) or []),
            )
            for parameter in list(effects[0].get("vulnerable_parameters", []) or [])
        )
        effect_sites = tuple(
            sorted(
                {
                    str(effect.get("effect_site_id", ""))
                    for effect in effects
                    if effect.get("effect_site_id")
                }
            )
        )
        summaries.append(
            BodyEffectSummary(
                summary_id=stable_id(
                    "body-summary", function_id, method, label, *effect_sites
                ),
                function_id=function_id,
                method=method,
                label=label,
                bindings=bindings,
                implementation_function_id=function_id,
                implementation_function=str(function.get("name", "")),
                implementation_body_hash=normalized_function_body_hash(function),
                effect_site_ids=effect_sites,
                depth=1,
                proof_path=effect_sites,
            )
        )

    known = {summary.key() for summary in summaries}
    for _depth in range(max(0, max_wrapper_depth - 1)):
        by_function: dict[str, list[BodyEffectSummary]] = {}
        for summary in summaries:
            by_function.setdefault(summary.function_id, []).append(summary)
        additions: list[BodyEffectSummary] = []
        for caller, op in index.calls:
            target = index.resolve_call_target(caller, op)
            if target is None:
                continue
            target_id = str(target.get("function_id", ""))
            for callee_summary in by_function.get(target_id, []):
                if not thin_wrapper_call(caller, op):
                    continue
                actuals = index.call_actuals(caller, op)
                composed: list[BodyRoleBinding] = []
                failed = False
                for binding in callee_summary.bindings:
                    if binding.kind == "constant":
                        composed.append(binding)
                        continue
                    slot = binding.parameter_slot
                    if slot is None or slot >= len(actuals):
                        failed = True
                        break
                    mapped = body_actual_binding(
                        index,
                        str(caller.get("function_id", "")),
                        dict(actuals[slot]),
                        role=binding.role,
                        origin_kind=binding.origin_kind,
                        inherited_path=binding.access_path,
                    )
                    if mapped is None:
                        failed = True
                        break
                    composed.append(mapped)
                if failed:
                    blockers.append(
                        {
                            "code": "body_sink_wrapper_role_not_exactly_bound",
                            "site_id": op_site(op),
                            "callee_function_id": target_id,
                            "summary_id": callee_summary.summary_id,
                        }
                    )
                    continue
                call_site = op_site(op)
                summary = BodyEffectSummary(
                    summary_id=stable_id(
                        "body-summary",
                        str(caller.get("function_id", "")),
                        call_site,
                        callee_summary.summary_id,
                    ),
                    function_id=str(caller.get("function_id", "")),
                    method=callee_summary.method,
                    label=callee_summary.label,
                    bindings=tuple(composed),
                    implementation_function_id=callee_summary.implementation_function_id,
                    implementation_function=callee_summary.implementation_function,
                    implementation_body_hash=callee_summary.implementation_body_hash,
                    effect_site_ids=callee_summary.effect_site_ids,
                    depth=callee_summary.depth + 1,
                    proof_path=(call_site,) + callee_summary.proof_path,
                )
                if summary.key() not in known:
                    known.add(summary.key())
                    additions.append(summary)
        if not additions:
            break
        summaries.extend(additions)

    summaries_by_function: dict[str, list[BodyEffectSummary]] = {}
    for summary in summaries:
        summaries_by_function.setdefault(summary.function_id, []).append(summary)
    boundaries: list[dict[str, Any]] = []
    for caller, op in index.calls:
        target = index.resolve_call_target(caller, op)
        if target is None:
            continue
        target_id = str(target.get("function_id", ""))
        actuals = index.call_actuals(caller, op)
        for summary in summaries_by_function.get(target_id, []):
            parameters: list[dict[str, Any]] = []
            nodes_by_role: dict[str, dict[str, Any]] = {}
            roles: dict[str, str] = {}
            role_bindings: dict[str, dict[str, Any]] = {}
            failed = False
            for binding in summary.bindings:
                if binding.kind == "constant":
                    parameter = {
                        "role": binding.role,
                        "expr": str(binding.constant),
                        "constant": True,
                        "constant_value": binding.constant,
                        "origin_kind": binding.origin_kind,
                    }
                    parameters.append(parameter)
                    roles[binding.role] = str(binding.constant)
                    role_bindings[binding.role] = {
                        "constant": binding.constant,
                        "access_path": list(binding.access_path),
                    }
                    continue
                slot = binding.parameter_slot
                if slot is None or slot >= len(actuals):
                    failed = True
                    break
                actual = dict(actuals[slot])
                constant = node_constant(actual)
                if constant is None:
                    constant = index.resolve_constant(
                        str(caller.get("function_id", "")), actual
                    )
                expr = actual_expression(actual)
                if binding.access_path:
                    expr += "".join(
                        f"[+0x{offset:x}]" for offset in binding.access_path
                    )
                parameter = {
                    "role": binding.role,
                    "index": slot,
                    "expr": expr,
                    "constant": constant is not None,
                    "constant_value": constant,
                    "origin_kind": binding.origin_kind,
                    "value_id": node_value_id(actual),
                    "object_id": node_object_id(actual),
                    "access_path": list(binding.access_path),
                }
                parameters.append(parameter)
                nodes_by_role[binding.role] = actual
                roles[binding.role] = expr
                role_bindings[binding.role] = {
                    "index": slot,
                    "value_id": node_value_id(actual),
                    "object_id": node_object_id(actual),
                    "constant": constant,
                    "access_path": list(binding.access_path),
                }
            if failed:
                continue
            kept, pruned = prune_body_parameters(
                program_facts, parameters, nodes_by_role
            )
            if not kept:
                continue
            site_id = op_site(op)
            boundaries.append(
                {
                    "id": stable_id(
                        "sink",
                        program_facts.get("binary_sha256", ""),
                        site_id,
                        summary.method,
                        summary.implementation_function_id,
                    ),
                    "sink_id": stable_id(
                        "sink",
                        program_facts.get("binary_sha256", ""),
                        site_id,
                        summary.method,
                        summary.implementation_function_id,
                    ),
                    "recognition": "heuristic",
                    "recognition_method": summary.method,
                    "recognition_class": "BODY_DERIVED_PATTERN_CALLSITE",
                    "detection_kind": f"high_pcode_cfg_{summary.method}_callsite",
                    "confirmation_source": "body_pattern_recursive_formal_actual_binding",
                    "label": summary.label,
                    "sink_type": summary.label,
                    "callee": str(target.get("name", "")),
                    "callee_function_id": target_id,
                    "implementation_function": summary.implementation_function,
                    "implementation_function_id": summary.implementation_function_id,
                    "implementation_body_hash": summary.implementation_body_hash,
                    "function": str(caller.get("name", "")),
                    "function_id": str(caller.get("function_id", "")),
                    "site_id": site_id,
                    "effect_site_id": summary.effect_site_ids[0]
                    if summary.effect_site_ids
                    else "",
                    "effect_site_ids": list(summary.effect_site_ids),
                    "instruction_address": str(op.get("instruction_address", "")),
                    "expr": f"{target.get('name', '')}(...)",
                    "roles": roles,
                    "role_bindings": role_bindings,
                    "vulnerable_parameter_roles": [
                        str(parameter.get("role", "")) for parameter in kept
                    ],
                    "vulnerable_parameters": kept,
                    "pruned_vulnerable_parameters": pruned,
                    "binding_status": "verified_high_pcode_body_pattern_callsite",
                    "decision": "ACCEPT_HEURISTIC",
                    "evidence_level": "HEURISTIC_HIGH_PCODE_CFG_PATTERN",
                    "taint_status": "not_evaluated",
                    "check_status": "unknown",
                    "vulnerability_status": "not_evaluated",
                    "summary_id": summary.summary_id,
                    "summary_depth": summary.depth,
                    "proof_path": [site_id, *summary.proof_path],
                    "proof": {
                        "proof_kind": "body_derived_pattern",
                        "body_function_id": summary.implementation_function_id,
                        "body_function": summary.implementation_function,
                        "effect_site_ids": list(summary.effect_site_ids),
                        "proof_path": [site_id, *summary.proof_path],
                    },
                    "boundary_callsites": [],
                }
            )

    unique_boundaries: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in boundaries:
        key = (
            str(row.get("site_id", "")),
            str(row.get("implementation_function_id", "")),
            str(row.get("recognition_method", "")),
        )
        previous = unique_boundaries.get(key)
        if previous is None or int(row.get("summary_depth", 0) or 0) > int(
            previous.get("summary_depth", 0) or 0
        ):
            unique_boundaries[key] = row
    boundaries = list(unique_boundaries.values())
    canonical: list[dict[str, Any]] = []
    for row in boundaries:
        site_id = str(row.get("site_id", ""))
        implementation_id = str(row.get("implementation_function_id", ""))
        nested = any(
            str(other.get("implementation_function_id", "")) == implementation_id
            and str(other.get("site_id", "")) != site_id
            and site_id in {
                str(item)
                for item in list(other.get("proof_path", []) or [])[1:]
            }
            for other in boundaries
        )
        if not nested:
            canonical.append(row)

    effects_by_site = {
        str(row.get("effect_site_id", "")): row for row in implementation_rows
    }
    covered_effects: set[str] = set()
    for row in canonical:
        effect_ids = set(str(item) for item in row.get("effect_site_ids", []) or [])
        covered_effects.update(effect_ids)
        evidence = [
            body_effect_evidence(
                effects_by_site[effect_id],
                functions_by_id.get(
                    str(effects_by_site[effect_id].get("function_id", "")), {}
                ),
            )
            for effect_id in sorted(effect_ids)
            if effect_id in effects_by_site
        ]
        evidence.extend(
            {
                "function": str(boundary.get("function", "")),
                "function_id": str(boundary.get("function_id", "")),
                "site_id": str(boundary.get("site_id", "")),
                "effect_site_id": str(boundary.get("effect_site_id", "")),
                "callee": str(boundary.get("callee", "")),
                "expr": str(boundary.get("expr", "")),
                "binding_status": str(boundary.get("binding_status", "")),
                "vulnerable_parameters": list(
                    boundary.get("vulnerable_parameters", []) or []
                ),
                "evidence_kind": "wrapper_boundary",
            }
            for boundary in boundaries
            if str(boundary.get("implementation_function_id", ""))
            == str(row.get("implementation_function_id", ""))
            and str(boundary.get("site_id", ""))
            in {str(item) for item in list(row.get("proof_path", []) or [])}
        )
        row["boundary_callsites"] = evidence

    fallback: list[dict[str, Any]] = []
    for raw in implementation_rows:
        effect_site = str(raw.get("effect_site_id", ""))
        if effect_site in covered_effects:
            continue
        row = dict(raw)
        function = functions_by_id.get(str(row.get("function_id", "")), {})
        kept, pruned = prune_body_parameters(
            program_facts, list(row.get("vulnerable_parameters", []) or [])
        )
        if not kept:
            continue
        row["recognition_class"] = "BODY_DERIVED_PATTERN_IMPLEMENTATION"
        row["implementation_function"] = str(row.get("function", ""))
        row["implementation_function_id"] = str(row.get("function_id", ""))
        row["implementation_body_hash"] = normalized_function_body_hash(function)
        row["vulnerable_parameters"] = kept
        row["vulnerable_parameter_roles"] = [
            str(parameter.get("role", "")) for parameter in kept
        ]
        row["pruned_vulnerable_parameters"] = pruned
        row["boundary_callsites"] = []
        fallback.append(row)

    calls = dedupe_sinks([*canonical, *fallback])
    return {
        "heuristic_sink_calls": calls,
        "blockers": blockers,
        "implementation_groups": len(grouped),
        "body_effect_fallbacks": len(fallback),
        "recursive_summaries": len(summaries),
        "canonical_wrapper_callsites": len(canonical),
    }


def analyze_program_facts(
    program_facts: dict[str, Any],
    *,
    source_evidence: dict[str, Any] | None = None,
    register_evidence: dict[str, Any] | None = None,
    source_associations: list[dict[str, Any]] | None = None,
    enabled_methods: set[str] | None = None,
    method_specs: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Recognize supported body-derived Sink patterns.

    The return value includes confirmed heuristic Sink rows, every structural
    candidate decision, and function-level blockers.  A blocker is not a
    negative Sink decision; it means required CFG/P-code evidence was absent.
    """

    active_methods = set(enabled_methods) if enabled_methods is not None else {
        "counted_range_copy",
        "counted_range_fill",
        "sentinel_copy",
        "paired_buffer_state",
        "buffer_state_reserve",
        "stateful_loop_write",
        "in_place_swap",
        "parser_oob_read",
    }
    specifications = dict(method_specs or {})
    program_index = ProgramIndex(program_facts)
    parser_source_index = ParserSourceIndex(source_associations or [])
    source_index = SourceEvidenceIndex(
        source_evidence,
        register_evidence,
        dict(program_facts.get("source_evidence", {}) or {}),
        {"register_profiles": list(program_facts.get("register_profiles", []) or [])},
    )
    sinks: list[dict[str, Any]] = []
    decisions: list[CandidateDecision] = []
    blockers: list[AnalysisBlocker] = []
    functions_seen = 0
    functions_analyzed = 0
    for raw_function in list(program_facts.get("functions", []) or []):
        function = dict(raw_function)
        functions_seen += 1
        cfg, cfg_blockers = FunctionCFG.build(function)
        if cfg is None:
            blockers.extend(cfg_blockers)
            continue
        functions_analyzed += 1
        if active_methods & {"counted_range_copy", "counted_range_fill"}:
            counted_sinks, counted_decisions = counted_range_candidates(
                program_facts, function, cfg, source_index
            )
            counted_sinks = [
                row for row in counted_sinks
                if str(row.get("recognition_method", "")) in active_methods
            ]
            counted_decisions = [
                row for row in counted_decisions
                if (
                    row.pattern == "counted_range"
                    and active_methods & {"counted_range_copy", "counted_range_fill"}
                )
            ]
            sinks.extend(counted_sinks)
            decisions.extend(counted_decisions)
        if "sentinel_copy" in active_methods:
            sentinel_sinks, sentinel_decisions = sentinel_copy_candidates(
                program_facts, function, cfg, source_index
            )
            sinks.extend(sentinel_sinks)
            decisions.extend(sentinel_decisions)
        if "paired_buffer_state" in active_methods:
            state_sinks, state_decisions = paired_buffer_state_candidates(
                program_facts, function, cfg
            )
            sinks.extend(state_sinks)
            decisions.extend(state_decisions)
        if "buffer_state_reserve" in active_methods:
            reserve_sinks, reserve_decisions = buffer_state_reservation_candidates(
                program_facts, function, cfg
            )
            sinks.extend(reserve_sinks)
            decisions.extend(reserve_decisions)
        if "stateful_loop_write" in active_methods:
            loop_sinks, loop_decisions = stateful_loop_write_candidates(
                program_facts, function, cfg, source_index
            )
            sinks.extend(loop_sinks)
            decisions.extend(loop_decisions)
        if "in_place_swap" in active_methods:
            swap_sinks, swap_decisions = in_place_swap_candidates(
                program_facts, function, cfg
            )
            sinks.extend(swap_sinks)
            decisions.extend(swap_decisions)
        if "parser_oob_read" in active_methods:
            parser_sinks, parser_decisions = discover_parser_oob_reads(
                program_facts,
                function,
                cfg,
                source_associations=parser_source_index,
                rule=dict(specifications.get("parser_oob_read", {}) or {}),
                program_index=program_index,
            )
            for descriptor in parser_sinks:
                row = bounded_sink_row(
                    program_facts=program_facts,
                    function=function,
                    site=dict(descriptor["site"]),
                    sink_type="PARSER_OOB_READ_SINK",
                    method="parser_oob_read",
                    roles=dict(descriptor.get("roles", {}) or {}),
                    vulnerable_parameters=list(
                        descriptor.get("vulnerable_parameters", []) or []
                    ),
                    object_roles=dict(descriptor.get("object_roles", {}) or {}),
                    proof=dict(descriptor.get("proof", {}) or {}),
                )
                row["read_effect_id"] = str(descriptor.get("read_effect_id", ""))
                sinks.append(row)
            decisions.extend(
                CandidateDecision(
                    pattern=str(decision.get("pattern", "parser_oob_read")),
                    function_id=str(decision.get("function_id", "")),
                    function=str(decision.get("function", "")),
                    site_id=str(decision.get("site_id", "")),
                    loop_id="",
                    status=str(decision.get("status", "rejected")),
                    reason_code=str(decision.get("reason_code", "")),
                    evidence=dict(decision.get("evidence", {}) or {}),
                )
                for decision in parser_decisions
            )
        if "variable_address_store" in active_methods:
            store_sinks, store_decisions = discover_variable_address_stores(
                program_facts,
                function,
                cfg,
                source_associations=parser_source_index,
            )
            for descriptor in store_sinks:
                row = bounded_sink_row(
                    program_facts=program_facts,
                    function=function,
                    site=dict(descriptor["site"]),
                    sink_type="STORE_SINK",
                    method="variable_address_store",
                    roles=dict(descriptor.get("roles", {}) or {}),
                    vulnerable_parameters=list(
                        descriptor.get("vulnerable_parameters", []) or []
                    ),
                    object_roles=dict(descriptor.get("object_roles", {}) or {}),
                    proof=dict(descriptor.get("proof", {}) or {}),
                )
                row["audit_only"] = True
                sinks.append(row)
            decisions.extend(
                CandidateDecision(
                    pattern=str(decision.get("pattern", "variable_address_store")),
                    function_id=str(decision.get("function_id", "")),
                    function=str(decision.get("function", "")),
                    site_id=str(decision.get("site_id", "")),
                    loop_id="",
                    status=str(decision.get("status", "rejected")),
                    reason_code=str(decision.get("reason_code", "")),
                    evidence=dict(decision.get("evidence", {}) or {}),
                )
                for decision in store_decisions
            )

    deduped = dedupe_sinks(sinks)
    candidate_rows = [row.as_json() for row in decisions]
    return {
        "schema_version": "ct-mini-body-sink-heuristics-v1",
        "binary": str(program_facts.get("binary", "")),
        "binary_sha256": str(program_facts.get("binary_sha256", "")),
        "recognition": "heuristic",
        "enabled_methods": sorted(active_methods),
        "heuristic_sink_implementations": deduped,
        "heuristic_sink_calls": deduped,
        "sink_startpoints": deduped,
        "candidates": candidate_rows,
        "blockers": [row.as_json() for row in blockers],
        "stats": {
            "functions_seen": functions_seen,
            "functions_analyzed": functions_analyzed,
            "heuristic_sink_calls": len(deduped),
            "candidates_confirmed": sum(
                1 for row in candidate_rows if row["status"] == "confirmed"
            ),
            "candidates_rejected": sum(
                1 for row in candidate_rows if row["status"] == "rejected"
            ),
            "functions_blocked": len(
                {row.function_id for row in blockers if row.function_id}
            ),
        },
    }


# Kept as the concise interface named in the v2 planning document.
recognize_body_derived_sinks = analyze_program_facts
