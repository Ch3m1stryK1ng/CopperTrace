#!/usr/bin/env python3
"""Bind local range Checks as evidence for post-A2 semantic review."""

from __future__ import annotations

from collections import deque
from typing import Any


SCALAR_BOUND_ROLES = frozenset(
    {
        "len",
        "length",
        "size",
        "count",
        "amount",
        "index",
        "offset",
        "cursor",
        "width",
        "available_length",
        "bound",
    }
)
VALUE_LINEAGE_OPS = frozenset(
    {
        "COPY",
        "CAST",
        "INT_ZEXT",
        "INT_SEXT",
        "INT_ADD",
        "INT_SUB",
        "INT_MULT",
        "INT_DIV",
        "INT_SDIV",
        "INT_AND",
        "INT_OR",
        "INT_XOR",
        "INT_LEFT",
        "INT_RIGHT",
        "INT_SRIGHT",
        "PTRADD",
        "PTRSUB",
        "MULTIEQUAL",
        "PIECE",
        "SUBPIECE",
    }
)
VALUE_EQUIVALENT_OPS = frozenset({"COPY", "CAST", "INT_ZEXT"})
BOOLEAN_TRANSPARENT_OPS = frozenset({"COPY", "CAST", "BOOL_NEGATE"})
ORDERED_COMPARISONS = frozenset(
    {"INT_LESS", "INT_LESSEQUAL", "INT_SLESS", "INT_SLESSEQUAL"}
)
CAPACITY_SINK_LABELS = frozenset({"COPY_SINK", "MEMSET_SINK"})
CAPACITY_EXTENT_EVIDENCE = frozenset(
    {
        "elf_symbol_st_size_and_writable_memory_block",
        "ghidra_defined_array_datatype",
        "ghidra_high_symbol_array_datatype",
    }
)


def _value_id(varnode: Any) -> str:
    return str(varnode.get("value_id", "")) if isinstance(varnode, dict) else ""


def _is_constant(varnode: Any) -> bool:
    return bool(varnode.get("is_constant", False)) if isinstance(varnode, dict) else False


def _constant_value(varnode: Any) -> int | None:
    if not _is_constant(varnode):
        return None
    raw = str(varnode.get("offset", "") or "")
    try:
        return int(raw, 0)
    except (TypeError, ValueError):
        return None


def _integer(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    raw = str(value or "").strip().lower()
    if raw.startswith("0x-"):
        raw = "-0x" + raw[3:]
    try:
        return int(raw, 0)
    except (TypeError, ValueError):
        return None


def _signed_constant(varnode: Any) -> int | None:
    value = _constant_value(varnode)
    if value is None:
        return None
    size = _integer(varnode.get("size")) if isinstance(varnode, dict) else None
    if not size or size <= 0:
        return value
    bits = size * 8
    mask = (1 << bits) - 1
    value &= mask
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _node_size(varnode: Any) -> int:
    return int(_integer(varnode.get("size")) or 0) if isinstance(varnode, dict) else 0


def _function_id_from_site(site_id: str) -> str:
    parts = str(site_id or "").split(":")
    return f"fn:{parts[1]}" if len(parts) >= 2 and parts[0] == "site" else ""


class ProgramCheckIndex:
    """Lazy per-function High P-code/CFG index for one firmware image."""

    def __init__(self, program_facts: dict[str, Any]):
        self._functions = {
            str(row.get("function_id", "")): row
            for row in list(program_facts.get("functions", []) or [])
            if str(row.get("function_id", ""))
        }
        self._static_objects = [
            dict(row)
            for row in list(program_facts.get("static_objects", []) or [])
            if int(_integer(row.get("extent")) or 0) > 0
            and bool(row.get("writable", False))
            and str(row.get("extent_evidence", "")) in CAPACITY_EXTENT_EVIDENCE
        ]
        stack_pointer = dict(
            dict(program_facts.get("architecture", {}) or {}).get(
                "stack_pointer", {}
            )
            or {}
        )
        self._stack_pointer_offset = _integer(stack_pointer.get("offset"))
        self._cache: dict[str, dict[str, Any]] = {}

    def _function_index(self, function_id: str) -> dict[str, Any] | None:
        if function_id in self._cache:
            return self._cache[function_id]
        function = self._functions.get(function_id)
        if function is None:
            return None

        ops = list(function.get("pcode_ops", []) or [])
        ops_by_site = {
            str(row.get("site_id", "")): row
            for row in ops
            if str(row.get("site_id", ""))
        }
        defs: dict[str, dict[str, Any]] = {}
        nodes_by_value: dict[str, dict[str, Any]] = {}
        for op in ops:
            output_id = _value_id(op.get("output"))
            if output_id:
                defs[output_id] = op
                nodes_by_value[output_id] = dict(op.get("output") or {})
            for node in list(op.get("inputs", []) or []):
                input_id = _value_id(node)
                if input_id:
                    nodes_by_value.setdefault(input_id, dict(node))

        blocks = {
            str(row.get("block_id", "")): row
            for row in list(function.get("basic_blocks", []) or [])
            if str(row.get("block_id", ""))
        }
        successors = {
            block_id: tuple(
                str(value)
                for value in list(block.get("successor_block_ids", []) or [])
                if str(value)
            )
            for block_id, block in blocks.items()
        }
        predecessors = {
            block_id: tuple(
                str(value)
                for value in list(block.get("predecessor_block_ids", []) or [])
                if str(value)
            )
            for block_id, block in blocks.items()
        }
        dominators = _compute_dominators(blocks, predecessors)
        index = {
            "function": function,
            "ops_by_site": ops_by_site,
            "defs": defs,
            "nodes_by_value": nodes_by_value,
            "blocks": blocks,
            "successors": successors,
            "dominators": dominators,
        }
        self._cache[function_id] = index
        return index

    def bind_sink(self, sink: dict[str, Any]) -> dict[str, Any]:
        site_id = str(sink.get("site_id", "") or "")
        function_id = str(sink.get("function_id", "") or "") or _function_id_from_site(
            site_id
        )
        index = self._function_index(function_id)
        if index is None:
            return _unknown_result("sink_function_not_in_program_facts")

        sink_op = index["ops_by_site"].get(site_id)
        if sink_op is None:
            return _unknown_result("sink_site_not_bound_to_high_pcode")
        sink_block_id = str(sink_op.get("block_id", "") or "")
        if not sink_block_id or sink_block_id not in index["blocks"]:
            return _unknown_result("sink_block_not_bound_to_cfg")

        if str(sink.get("label", "")) == "PARSER_OOB_READ_SINK":
            return _bind_parser_read(sink, sink_op, sink_block_id, index)

        results: list[dict[str, Any]] = []
        for parameter in list(sink.get("vulnerable_parameters", []) or []):
            role = str(parameter.get("role", "") or "").lower()
            if role not in SCALAR_BOUND_ROLES:
                continue
            start_value_id = str(parameter.get("value_id", "") or "")
            if not start_value_id:
                results.append(
                    {
                        "role": role,
                        "status": "UNKNOWN",
                        "reason": "vulnerable_parameter_value_id_missing",
                    }
                )
                continue
            results.append(
                _bind_parameter(
                    role,
                    start_value_id,
                    sink_block_id,
                    index,
                )
            )

        capacity, capacity_blocker = _prove_capacity_safe(
            sink,
            sink_op,
            results,
            index,
            self._static_objects,
            self._stack_pointer_offset,
        )
        if capacity is not None:
            status = "CAPACITY_SAFE"
        elif any(row.get("status") == "PARAMETER_BOUNDED" for row in results):
            status = "PARAMETER_BOUNDED"
        elif any(row.get("status") == "OBSERVED_NOT_BOUND" for row in results):
            status = "OBSERVED_NOT_BOUND"
        else:
            status = "UNKNOWN"
        return {
            "status": status,
            "proof_boundary": "local_high_pcode_cfg_and_static_object_extent",
            "hard_drop": False,
            "offline_filter_eligible": False,
            "parameter_checks": results,
            "capacity_proof": capacity or {},
            "capacity_blocker": "" if capacity is not None else capacity_blocker,
        }


def _op_position(op: dict[str, Any]) -> tuple[int, int]:
    return (
        int(_integer(op.get("instruction_address")) or -1),
        int(_integer(op.get("op_order")) or -1),
    )


def _equivalent_to(
    node: dict[str, Any], target_value_id: str, defs: dict[str, dict[str, Any]]
) -> bool:
    value_id = _value_id(node)
    return bool(
        target_value_id
        and value_id
        and (
            target_value_id in _value_equivalent_lineage(value_id, defs)
            or value_id in _value_equivalent_lineage(target_value_id, defs)
        )
    )


def _exact_sum_matches(
    node: dict[str, Any],
    terms: list[tuple[str, int | None]],
    defs: dict[str, dict[str, Any]],
) -> bool:
    """Prove a two-term SSA sum used as a required read endpoint."""

    definition = defs.get(_value_id(node))
    if not definition or str(definition.get("mnemonic", "")) not in {
        "INT_ADD",
        "PTRADD",
    }:
        return False
    parts = list(definition.get("inputs", []) or [])
    if str(definition.get("mnemonic", "")) == "PTRADD" and len(parts) >= 3:
        scale = _signed_constant(parts[2])
        if scale != 1:
            return False
        parts = parts[:2]
    if len(parts) != 2 or len(terms) != 2:
        return False

    def matches(part: dict[str, Any], term: tuple[str, int | None]) -> bool:
        value_id, constant = term
        if value_id:
            return _equivalent_to(part, value_id, defs)
        return constant is not None and _constant_value(part) == constant

    return bool(
        (matches(parts[0], terms[0]) and matches(parts[1], terms[1]))
        or (matches(parts[0], terms[1]) and matches(parts[1], terms[0]))
    )


def _required_read_operand(
    node: dict[str, Any], read: dict[str, Any], defs: dict[str, dict[str, Any]]
) -> str:
    """Return ``last_index`` or ``end`` when the operand exactly bounds a read."""

    dynamic_ids = [
        str(value)
        for value in list(read.get("dynamic_value_ids", []) or [])
        if str(value)
    ]
    width_value_id = str(read.get("width_value_id", ""))
    width_constant = _integer(read.get("width_constant"))
    fixed_offset = int(_integer(read.get("fixed_offset")) or 0)

    if len(dynamic_ids) == 1 and width_constant == 1 and fixed_offset == 0:
        if _equivalent_to(node, dynamic_ids[0], defs):
            return "last_index"
    if not dynamic_ids and width_value_id and fixed_offset == 0:
        if _equivalent_to(node, width_value_id, defs):
            return "end"
    if not dynamic_ids and width_constant is not None:
        required = fixed_offset + width_constant
        if _constant_value(node) == required:
            return "end"
    if len(dynamic_ids) == 1 and fixed_offset == 0:
        if width_value_id and _exact_sum_matches(
            node, [(dynamic_ids[0], None), (width_value_id, None)], defs
        ):
            return "end"
        if width_constant not in (None, 0, 1) and _exact_sum_matches(
            node, [(dynamic_ids[0], None), ("", width_constant)], defs
        ):
            return "end"
    return ""


def _comparison_is_safe(
    comparison: dict[str, Any],
    *,
    comparison_true_on_sink_path: bool,
    available_value_id: str,
    read: dict[str, Any],
    defs: dict[str, dict[str, Any]],
) -> tuple[bool, dict[str, Any]]:
    mnemonic = str(comparison.get("mnemonic", ""))
    if mnemonic not in {"INT_LESS", "INT_LESSEQUAL"}:
        return False, {}
    parts = [dict(item or {}) for item in list(comparison.get("inputs", []) or [])[:2]]
    if len(parts) != 2:
        return False, {}
    available_positions = [
        index
        for index, part in enumerate(parts)
        if _equivalent_to(part, available_value_id, defs)
    ]
    if len(available_positions) != 1:
        return False, {}
    available_position = available_positions[0]
    required_position = 1 - available_position
    requirement = _required_read_operand(parts[required_position], read, defs)
    if not requirement:
        return False, {}

    safe = False
    if required_position == 0 and comparison_true_on_sink_path:
        # required < available is safe for a last index or an end.  The
        # non-strict form is safe only for an exclusive end.
        safe = mnemonic == "INT_LESS" or requirement == "end"
    elif available_position == 0 and not comparison_true_on_sink_path:
        # !(available < required) proves available >= required; for a last
        # index equality remains unsafe. !(available <= required) proves >.
        safe = requirement == "end" or mnemonic == "INT_LESSEQUAL"
    return safe, {
        "comparison_site_id": str(comparison.get("site_id", "")),
        "comparison_mnemonic": mnemonic,
        "available_input_index": available_position,
        "required_input_index": required_position,
        "required_operand_kind": requirement,
        "comparison_true_on_sink_path": comparison_true_on_sink_path,
    }


def _path_mutates_between(
    branch: dict[str, Any],
    sink_op: dict[str, Any],
    sink_successor: str,
    index: dict[str, Any],
) -> list[str]:
    """Conservatively identify STORE/CALL effects after a candidate Check."""

    branch_block = str(branch.get("block_id", ""))
    sink_block = str(sink_op.get("block_id", ""))
    branch_position = _op_position(branch)
    sink_position = _op_position(sink_op)
    sites: list[str] = []
    for op in index["ops_by_site"].values():
        if str(op.get("mnemonic", "")) not in {"STORE", "CALL", "CALLIND"}:
            continue
        if str(op.get("site_id", "")) == str(sink_op.get("site_id", "")):
            continue
        block_id = str(op.get("block_id", ""))
        position = _op_position(op)
        on_path = False
        if branch_block == sink_block == block_id:
            on_path = branch_position < position < sink_position
        elif block_id == branch_block:
            on_path = position > branch_position and _can_reach(
                sink_successor, sink_block, index["successors"]
            )
        elif block_id == sink_block:
            on_path = position < sink_position and _can_reach(
                sink_successor, sink_block, index["successors"]
            )
        else:
            on_path = _can_reach(
                sink_successor, block_id, index["successors"]
            ) and _can_reach(block_id, sink_block, index["successors"])
        if on_path:
            sites.append(str(op.get("site_id", "")))
    return sorted(set(sites))


def _bind_parser_read(
    sink: dict[str, Any],
    sink_op: dict[str, Any],
    sink_block_id: str,
    index: dict[str, Any],
) -> dict[str, Any]:
    proof = dict(sink.get("proof", {}) or {})
    read = dict(proof.get("read_effect", {}) or {})
    admission = dict(proof.get("admission", {}) or {})
    available_value_id = str(admission.get("available_length_value_id", ""))
    if not available_value_id:
        available_value_id = next(
            (
                str(row.get("value_id", ""))
                for row in list(sink.get("vulnerable_parameters", []) or [])
                if str(row.get("role", "")) == "available_length"
                and str(row.get("value_id", ""))
            ),
            "",
        )

    control_ids = {
        str(value)
        for value in list(read.get("dynamic_value_ids", []) or [])
        if str(value)
    }
    width_value_id = str(read.get("width_value_id", ""))
    if width_value_id and _integer(read.get("width_constant")) is None:
        control_ids.add(width_value_id)
    if available_value_id:
        control_ids.add(available_value_id)

    observed: list[dict[str, Any]] = []
    safe_rows: list[dict[str, Any]] = []
    for branch in index["ops_by_site"].values():
        if str(branch.get("mnemonic", "")) != "CBRANCH":
            continue
        branch_block = str(branch.get("block_id", ""))
        if branch_block not in index["dominators"].get(sink_block_id, frozenset()):
            continue
        block = dict(index["blocks"].get(branch_block, {}) or {})
        true_successor = str(
            block.get("true_successor_block_id", block.get("true_successor", ""))
            or ""
        )
        false_successor = str(
            block.get("false_successor_block_id", block.get("false_successor", ""))
            or ""
        )
        if not true_successor or not false_successor:
            continue
        true_reaches = _can_reach(true_successor, sink_block_id, index["successors"])
        false_reaches = _can_reach(false_successor, sink_block_id, index["successors"])
        if true_reaches == false_reaches:
            continue
        comparison, inverted = _comparison_for_branch(branch, index["defs"])
        if comparison is None:
            continue
        comparison_inputs = [
            dict(item or {})
            for item in list(comparison.get("inputs", []) or [])[:2]
        ]
        comparison_lineage = set()
        for item in comparison_inputs:
            comparison_lineage.update(
                _backward_lineage(_value_id(item), index["defs"])
            )
        if control_ids and not (comparison_lineage & control_ids):
            continue
        comparison_true_on_sink_path = bool(true_reaches) ^ bool(inverted)
        sink_successor = true_successor if true_reaches else false_successor
        safe, relation = _comparison_is_safe(
            comparison,
            comparison_true_on_sink_path=comparison_true_on_sink_path,
            available_value_id=available_value_id,
            read=read,
            defs=index["defs"],
        )
        mutation_sites = _path_mutates_between(
            branch, sink_op, sink_successor, index
        )
        row = {
            **relation,
            "branch_site_id": str(branch.get("site_id", "")),
            "branch_block_id": branch_block,
            "sink_block_id": sink_block_id,
            "dominates_sink": True,
            "mutation_sites_between_check_and_read": mutation_sites,
            "status": (
                "CAPACITY_SAFE" if safe and not mutation_sites else "UNKNOWN"
            ),
            "reason": (
                "dominating_same_ssa_range_check_proves_read_within_available_length"
                if safe and not mutation_sites
                else "related_check_does_not_prove_current_read_range"
            ),
        }
        if safe and mutation_sites:
            row["reason"] = "range_check_precedes_unresolved_memory_mutation"
        observed.append(row)
        if safe and not mutation_sites:
            safe_rows.append(row)

    if safe_rows:
        selected = min(safe_rows, key=lambda row: str(row.get("branch_site_id", "")))
        return {
            "status": "CAPACITY_SAFE",
            "proof_boundary": "local_high_pcode_cfg_parser_read_range",
            "hard_drop": False,
            "offline_filter_eligible": False,
            "parameter_checks": observed,
            "capacity_proof": selected,
            "capacity_blocker": "",
        }
    if observed:
        return {
            "status": "UNKNOWN",
            "proof_boundary": "local_high_pcode_cfg_parser_read_range",
            "hard_drop": False,
            "offline_filter_eligible": False,
            "parameter_checks": observed,
            "capacity_proof": {},
            "capacity_blocker": "related_check_not_sufficient_for_capacity_proof",
        }
    return {
        "status": "MISSING",
        "proof_boundary": "local_high_pcode_cfg_parser_read_range",
        "hard_drop": False,
        "offline_filter_eligible": False,
        "parameter_checks": [],
        "capacity_proof": {},
        "capacity_blocker": "no_dominating_related_range_check",
    }


def _unknown_result(reason: str) -> dict[str, Any]:
    return {
        "status": "UNKNOWN",
        "proof_boundary": "local_high_pcode_cfg_and_static_object_extent",
        "hard_drop": False,
        "offline_filter_eligible": False,
        "parameter_checks": [],
        "capacity_proof": {},
        "capacity_blocker": reason,
        "reason": reason,
    }


def _compute_dominators(
    blocks: dict[str, dict[str, Any]],
    predecessors: dict[str, tuple[str, ...]],
) -> dict[str, frozenset[str]]:
    block_ids = set(blocks)
    if not block_ids:
        return {}
    entries = sorted(
        block_id for block_id in block_ids if not predecessors.get(block_id)
    )
    entry = entries[0] if entries else min(
        block_ids, key=lambda value: int(blocks[value].get("index", 0) or 0)
    )
    dominators: dict[str, set[str]] = {
        block_id: ({block_id} if block_id == entry else set(block_ids))
        for block_id in block_ids
    }
    changed = True
    while changed:
        changed = False
        for block_id in block_ids:
            if block_id == entry:
                continue
            preds = [value for value in predecessors.get(block_id, ()) if value in block_ids]
            incoming = (
                set.intersection(*(dominators[value] for value in preds))
                if preds
                else set()
            )
            updated = {block_id} | incoming
            if updated != dominators[block_id]:
                dominators[block_id] = updated
                changed = True
    return {key: frozenset(value) for key, value in dominators.items()}


def _backward_lineage(
    start_value_id: str,
    defs: dict[str, dict[str, Any]],
    *,
    max_values: int = 256,
) -> frozenset[str]:
    seen: set[str] = set()
    queue: deque[str] = deque([start_value_id])
    while queue and len(seen) < max_values:
        value_id = queue.popleft()
        if not value_id or value_id in seen:
            continue
        seen.add(value_id)
        defining_op = defs.get(value_id)
        if defining_op is None:
            continue
        if str(defining_op.get("mnemonic", "")) not in VALUE_LINEAGE_OPS:
            continue
        for input_node in list(defining_op.get("inputs", []) or []):
            if _is_constant(input_node):
                continue
            input_id = _value_id(input_node)
            if input_id and input_id not in seen:
                queue.append(input_id)
    return frozenset(seen)


def _value_equivalent_lineage(
    start_value_id: str,
    defs: dict[str, dict[str, Any]],
    *,
    max_values: int = 64,
) -> frozenset[str]:
    """Follow only operations that preserve the scalar runtime value."""

    seen: set[str] = set()
    queue: deque[str] = deque([start_value_id])
    while queue and len(seen) < max_values:
        value_id = queue.popleft()
        if not value_id or value_id in seen:
            continue
        seen.add(value_id)
        defining_op = defs.get(value_id)
        if defining_op is None:
            continue
        mnemonic = str(defining_op.get("mnemonic", ""))
        if mnemonic not in VALUE_EQUIVALENT_OPS:
            continue
        inputs = list(defining_op.get("inputs", []) or [])
        output = dict(defining_op.get("output") or {})
        if not inputs:
            continue
        source = inputs[0]
        if mnemonic == "CAST" and _node_size(source) != _node_size(output):
            continue
        if mnemonic == "INT_ZEXT" and _node_size(source) > _node_size(output):
            continue
        input_id = _value_id(source)
        if input_id and input_id not in seen:
            queue.append(input_id)
    return frozenset(seen)


def _static_object_matches(
    static_objects: list[dict[str, Any]],
    *,
    storage_space: str,
    function_id: str,
    base_offset: int,
) -> list[dict[str, Any]]:
    matches = [
        row
        for row in static_objects
        if str(row.get("storage_space", "")) == storage_space
        and (storage_space != "stack" or str(row.get("function_id", "")) == function_id)
        and _integer(row.get("base_offset")) == base_offset
    ]
    by_extent: dict[int, dict[str, Any]] = {}
    evidence: dict[int, set[str]] = {}
    for row in matches:
        extent = int(_integer(row.get("extent")) or 0)
        if extent <= 0:
            continue
        by_extent.setdefault(extent, dict(row))
        evidence.setdefault(extent, set()).add(str(row.get("extent_evidence", "")))
    result = []
    for extent in sorted(by_extent):
        row = by_extent[extent]
        row["corroborating_extent_evidence"] = sorted(evidence[extent])
        result.append(row)
    return result


def _resolve_static_destination(
    value_id: str,
    index: dict[str, Any],
    static_objects: list[dict[str, Any]],
    stack_pointer_offset: int | None,
    *,
    added_offset: int = 0,
    seen: frozenset[str] = frozenset(),
) -> dict[str, Any] | None:
    if not value_id or value_id in seen or len(seen) >= 64:
        return None
    seen = seen | {value_id}
    node = dict(index["nodes_by_value"].get(value_id, {}) or {})
    function_id = str(index["function"].get("function_id", ""))

    direct_matches = [
        row for row in static_objects if str(row.get("object_id", "")) == str(node.get("object_id", ""))
    ]
    if len({_integer(row.get("extent")) for row in direct_matches}) == 1 and direct_matches:
        return {
            "static_object": dict(direct_matches[0]),
            "destination_offset": added_offset,
            "resolution": "exact_static_object_id",
        }

    space = str(node.get("space", "") or "").lower()
    node_offset = _integer(node.get("offset"))
    if space == "stack" and node_offset is not None:
        matches = _static_object_matches(
            static_objects,
            storage_space="stack",
            function_id=function_id,
            base_offset=node_offset,
        )
        if len(matches) == 1:
            return {
                "static_object": matches[0],
                "destination_offset": added_offset,
                "resolution": "stack_varnode_base",
            }
    if space in {"ram", "mem", "memory"} and bool(node.get("is_address", False)) and node_offset is not None:
        matches = _static_object_matches(
            static_objects,
            storage_space="ram",
            function_id="",
            base_offset=node_offset,
        )
        if len(matches) == 1:
            return {
                "static_object": matches[0],
                "destination_offset": added_offset,
                "resolution": "global_address_base",
            }

    defining_op = index["defs"].get(value_id)
    if defining_op is None:
        return None
    mnemonic = str(defining_op.get("mnemonic", ""))
    inputs = list(defining_op.get("inputs", []) or [])
    if mnemonic in VALUE_EQUIVALENT_OPS and inputs:
        return _resolve_static_destination(
            _value_id(inputs[0]),
            index,
            static_objects,
            stack_pointer_offset,
            added_offset=added_offset,
            seen=seen,
        )
    if mnemonic == "PTRSUB" and len(inputs) >= 2:
        first = inputs[0]
        field_offset = _signed_constant(inputs[1])
        first_register_offset = _integer(first.get("offset"))
        if (
            field_offset is not None
            and stack_pointer_offset is not None
            and str(first.get("space", "")).lower() == "register"
            and first_register_offset == stack_pointer_offset
        ):
            matches = _static_object_matches(
                static_objects,
                storage_space="stack",
                function_id=function_id,
                base_offset=field_offset,
            )
            if len(matches) == 1:
                return {
                    "static_object": matches[0],
                    "destination_offset": added_offset,
                    "resolution": "stack_pointer_ptrsub",
                    "pointer_site_id": str(defining_op.get("site_id", "")),
                }
        if field_offset is not None:
            return _resolve_static_destination(
                _value_id(first),
                index,
                static_objects,
                stack_pointer_offset,
                added_offset=added_offset + field_offset,
                seen=seen,
            )
    if mnemonic == "PTRADD" and len(inputs) >= 2:
        item_offset = _signed_constant(inputs[1])
        scale = _signed_constant(inputs[2]) if len(inputs) >= 3 else 1
        if item_offset is not None and scale is not None:
            return _resolve_static_destination(
                _value_id(inputs[0]),
                index,
                static_objects,
                stack_pointer_offset,
                added_offset=added_offset + item_offset * scale,
                seen=seen,
            )
    return None


def _sink_argument_value_id(
    sink: dict[str, Any], sink_op: dict[str, Any], argument_index: int
) -> str:
    proof_ids = list(dict(sink.get("proof", {}) or {}).get("argument_value_ids", []) or [])
    if argument_index < len(proof_ids) and str(proof_ids[argument_index]):
        return str(proof_ids[argument_index])
    inputs = list(sink_op.get("inputs", []) or [])[1:]
    return _value_id(inputs[argument_index]) if argument_index < len(inputs) else ""


def _prove_capacity_safe(
    sink: dict[str, Any],
    sink_op: dict[str, Any],
    parameter_checks: list[dict[str, Any]],
    index: dict[str, Any],
    static_objects: list[dict[str, Any]],
    stack_pointer_offset: int | None,
) -> tuple[dict[str, Any] | None, str]:
    if str(sink.get("label", "")) not in CAPACITY_SINK_LABELS:
        return None, "sink_label_not_supported_by_capacity_proof"
    length_parameters = [
        row
        for row in list(sink.get("vulnerable_parameters", []) or [])
        if str(row.get("role", "")).lower() in {"len", "length", "size", "count", "amount"}
        and not bool(row.get("constant", False))
    ]
    if len(length_parameters) != 1:
        return None, "non_unique_nonconstant_length_parameter"
    length_parameter = length_parameters[0]
    length_index = _integer(length_parameter.get("index"))
    if length_index is None:
        return None, "length_parameter_index_missing"
    length_value_id = str(length_parameter.get("value_id", "") or "")
    if not length_value_id or _sink_argument_value_id(sink, sink_op, length_index) != length_value_id:
        return None, "length_parameter_not_bound_to_sink_argument"
    bounded_checks = [
        row
        for row in parameter_checks
        if str(row.get("role", "")).lower()
        == str(length_parameter.get("role", "")).lower()
        and row.get("status") == "PARAMETER_BOUNDED"
    ]
    if not bounded_checks:
        return None, "no_parameter_bounded_check"
    check = next(
        (
            row
            for row in bounded_checks
            if bool(row.get("value_equivalent", False))
        ),
        None,
    )
    if check is None:
        return None, "checked_value_not_equivalent_to_sink_length"
    if str(check.get("comparison_mnemonic", "")) != "INT_LESS":
        return None, "signed_comparison_not_capacity_proof"
    bound = _integer(check.get("bound_constant"))
    relation = str(check.get("upper_bound_relation", ""))
    if bound is None:
        return None, "capacity_bound_not_constant"
    if relation not in {"LT", "LE"}:
        return None, "unsupported_capacity_bound_relation"

    destination_value_id = _sink_argument_value_id(sink, sink_op, 0)
    if not destination_value_id:
        return None, "destination_argument_not_bound"
    destination = _resolve_static_destination(
        destination_value_id,
        index,
        static_objects,
        stack_pointer_offset,
    )
    if destination is None:
        return None, "static_destination_object_unresolved"
    static_object = dict(destination["static_object"])
    extent = int(_integer(static_object.get("extent")) or 0)
    offset = int(_integer(destination.get("destination_offset")) or 0)
    if extent <= 0 or offset < 0 or offset > extent:
        return None, "destination_extent_or_offset_invalid"
    remaining = extent - offset
    maximum_length = bound - 1 if relation == "LT" else bound
    if maximum_length < 0 or maximum_length > remaining:
        return None, "check_bound_exceeds_remaining_destination_capacity"
    return {
        "status": "CAPACITY_SAFE",
        "reason": "branch_bound_fits_static_destination_capacity",
        "sink_label": str(sink.get("label", "")),
        "sink_site_id": str(sink.get("site_id", "")),
        "destination_value_id": destination_value_id,
        "destination_object_id": str(static_object.get("object_id", "")),
        "destination_object_name": str(static_object.get("name", "")),
        "destination_extent": extent,
        "destination_offset": offset,
        "remaining_capacity": remaining,
        "length_value_id": length_value_id,
        "upper_bound_relation": relation,
        "upper_bound_constant": bound,
        "maximum_sink_length": maximum_length,
        "comparison_site_id": str(check.get("comparison_site_id", "")),
        "branch_site_id": str(check.get("branch_site_id", "")),
        "extent_evidence": str(static_object.get("extent_evidence", "")),
        "corroborating_extent_evidence": list(
            static_object.get("corroborating_extent_evidence", []) or []
        ),
        "destination_resolution": str(destination.get("resolution", "")),
        "arithmetic_safe": True,
        "intraprocedural": True,
        "value_equivalent": True,
    }, ""


def _comparison_for_branch(
    branch: dict[str, Any], defs: dict[str, dict[str, Any]]
) -> tuple[dict[str, Any] | None, bool]:
    inputs = list(branch.get("inputs", []) or [])
    condition_id = _value_id(inputs[-1]) if inputs else ""
    inverted = False
    visited: set[str] = set()
    while condition_id and condition_id not in visited:
        visited.add(condition_id)
        op = defs.get(condition_id)
        if op is None:
            break
        mnemonic = str(op.get("mnemonic", ""))
        if mnemonic in ORDERED_COMPARISONS:
            return op, inverted
        if mnemonic not in BOOLEAN_TRANSPARENT_OPS:
            break
        if mnemonic == "BOOL_NEGATE":
            inverted = not inverted
        op_inputs = list(op.get("inputs", []) or [])
        condition_id = _value_id(op_inputs[0]) if op_inputs else ""
    return None, inverted


def _can_reach(
    start: str,
    target: str,
    successors: dict[str, tuple[str, ...]],
    *,
    max_blocks: int = 4096,
) -> bool:
    queue: deque[str] = deque([start])
    seen: set[str] = set()
    while queue and len(seen) < max_blocks:
        block_id = queue.popleft()
        if block_id == target:
            return True
        if block_id in seen:
            continue
        seen.add(block_id)
        queue.extend(value for value in successors.get(block_id, ()) if value not in seen)
    return False


def _bind_parameter(
    role: str,
    start_value_id: str,
    sink_block_id: str,
    index: dict[str, Any],
) -> dict[str, Any]:
    lineage = _backward_lineage(start_value_id, index["defs"])
    equivalent_lineage = _value_equivalent_lineage(start_value_id, index["defs"])
    observed: list[dict[str, Any]] = []
    effective: list[dict[str, Any]] = []

    for op in index["ops_by_site"].values():
        if str(op.get("mnemonic", "")) != "CBRANCH":
            continue
        branch_block_id = str(op.get("block_id", "") or "")
        if branch_block_id not in index["dominators"].get(sink_block_id, frozenset()):
            continue
        block = index["blocks"].get(branch_block_id, {})
        true_successor = str(block.get("true_successor_block_id", "") or "")
        false_successor = str(block.get("false_successor_block_id", "") or "")
        if not true_successor or not false_successor:
            continue
        true_reaches = _can_reach(true_successor, sink_block_id, index["successors"])
        false_reaches = _can_reach(false_successor, sink_block_id, index["successors"])
        if true_reaches == false_reaches:
            continue

        comparison, inverted = _comparison_for_branch(op, index["defs"])
        if comparison is None:
            continue
        comparison_inputs = list(comparison.get("inputs", []) or [])[:2]
        linked_indexes = [
            position
            for position, input_node in enumerate(comparison_inputs)
            if _value_id(input_node) in lineage
        ]
        if len(linked_indexes) != 1:
            continue
        linked_index = linked_indexes[0]
        compare_true_on_sink_path = bool(true_reaches) ^ bool(inverted)
        upper_bound = (linked_index == 0 and compare_true_on_sink_path) or (
            linked_index == 1 and not compare_true_on_sink_path
        )
        if linked_index == 0 and compare_true_on_sink_path:
            upper_bound_relation = "LT"
        elif linked_index == 1 and not compare_true_on_sink_path:
            upper_bound_relation = "LE"
        else:
            upper_bound_relation = ""
        bound_node = comparison_inputs[1 - linked_index]
        linked_value_id = _value_id(comparison_inputs[linked_index])
        evidence = {
            "role": role,
            "status": "PARAMETER_BOUNDED" if upper_bound else "OBSERVED_NOT_BOUND",
            "reason": (
                "ordered_comparison_upper_bounds_sink_parameter_on_sink_path"
                if upper_bound
                else "ordered_comparison_does_not_upper_bound_parameter_on_sink_path"
            ),
            "sink_value_id": start_value_id,
            "comparison_site_id": str(comparison.get("site_id", "")),
            "comparison_mnemonic": str(comparison.get("mnemonic", "")),
            "branch_site_id": str(op.get("site_id", "")),
            "branch_block_id": branch_block_id,
            "sink_block_id": sink_block_id,
            "linked_input_index": linked_index,
            "linked_value_id": linked_value_id,
            "value_equivalent": linked_value_id in equivalent_lineage,
            "upper_bound_relation": upper_bound_relation,
            "bound_value_id": _value_id(bound_node),
            "bound_name": str(bound_node.get("high_name", "") or ""),
            "bound_constant": _constant_value(bound_node),
            "dominates_sink": True,
            "sink_reachable_from_true": true_reaches,
            "sink_reachable_from_false": false_reaches,
            "condition_inverted": inverted,
            "capacity_equivalence_proven": False,
        }
        observed.append(evidence)
        if upper_bound:
            effective.append(evidence)

    if effective:
        return min(effective, key=lambda row: str(row.get("branch_site_id", "")))
    if observed:
        return min(observed, key=lambda row: str(row.get("branch_site_id", "")))
    return {
        "role": role,
        "status": "UNKNOWN",
        "reason": "no_dominating_ssa_bound_check_gates_sink",
        "sink_value_id": start_value_id,
    }
