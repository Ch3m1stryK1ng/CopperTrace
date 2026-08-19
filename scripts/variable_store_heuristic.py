#!/usr/bin/env python3
"""Audit variable-address High P-code STORE effects.

The recognizer is deliberately narrow and name independent.  It records a
STORE only when the destination address has the structural form

    writable_base + variable_offset

and the variable term comes from a function scalar parameter or an existing
Source Association VALUE.  A fixed field STORE (``object->field = value``)
has no variable address term and is therefore outside this rule.

Rows produced here are audit candidates.  The Sink artifact builder keeps
them out of BFS/RDA until the registry rule is explicitly enabled after an
independent precision audit.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from high_pcode_loop_analysis import FunctionCFG, node_constant, node_object_id, node_text, node_value_id, parse_int
from parser_oob_read_heuristic import SourceAssociationIndex, decompose_address


def _inputs(op: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(item or {}) for item in list(op.get("inputs", []) or [])]


def _parameter_types(function: dict[str, Any]) -> dict[int, str]:
    return {
        int(row.get("index")): str(row.get("data_type", ""))
        for row in list(function.get("parameters", []) or [])
        if isinstance(row.get("index"), int)
    }


def _pointer_type(type_name: str) -> bool:
    text = str(type_name or "").replace(" ", "")
    return "*" in text or text.endswith("[]")


def _memory_block(program_facts: dict[str, Any], address: int) -> dict[str, Any]:
    for raw in list(program_facts.get("memory_blocks", []) or []):
        row = dict(raw or {})
        start = parse_int(row.get("start"))
        end = parse_int(row.get("end"))
        if start is not None and end is not None and start <= address <= end:
            return row
    return {}


def _parameter_slot(node: dict[str, Any]) -> int | None:
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


def _formal_slots_in_lineage(
    cfg: FunctionCFG,
    node: dict[str, Any],
    *,
    limit: int = 128,
) -> set[int]:
    """Return explicit formal inputs used to compute a local SSA value."""

    queue = [dict(node)]
    seen: set[str] = set()
    slots: set[int] = set()
    steps = 0
    while queue and steps < limit:
        current = queue.pop()
        steps += 1
        slot = _parameter_slot(current)
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
        queue.extend(_inputs(definition))
    return slots


def _parameter(
    role: str,
    node: dict[str, Any],
    cfg: FunctionCFG,
    *,
    parameter_slots: Iterable[int] = (),
    origin_kind: str = "scalar",
) -> dict[str, Any]:
    slots = sorted(set(int(slot) for slot in parameter_slots))
    row: dict[str, Any] = {
        "role": role,
        "expr": node_text(node),
        "constant": node_constant(node) is not None,
        "origin_kind": origin_kind,
    }
    if node_value_id(node):
        row["value_id"] = node_value_id(node)
    if node_object_id(node):
        row["object_id"] = node_object_id(node)
    if len(slots) == 1:
        row["parameter_slot"] = slots[0]
    elif slots:
        row["parameter_slots"] = slots
    return row


@dataclass(frozen=True)
class StoreDecision:
    function_id: str
    function: str
    site_id: str
    status: str
    reason_code: str
    evidence: dict[str, Any]

    def as_candidate(self) -> dict[str, Any]:
        return {
            "pattern": "variable_address_store",
            "function_id": self.function_id,
            "function": self.function,
            "site_id": self.site_id,
            "loop_id": "",
            "status": self.status,
            "reason_code": self.reason_code,
            "evidence": self.evidence,
        }


def _base_proof(
    program_facts: dict[str, Any],
    function: dict[str, Any],
    cfg: FunctionCFG,
    base: dict[str, Any],
    associations: SourceAssociationIndex,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Return base evidence and an optional vulnerable destination parameter."""

    parameter_types = _parameter_types(function)
    direct = cfg.formal_access(base)
    if direct is not None and _pointer_type(parameter_types.get(direct[0], "")):
        return (
            {
                "kind": "formal_pointer",
                "parameter_slot": direct[0],
                "access_path": list(direct[1]),
            },
            _parameter(
                "dst",
                base,
                cfg,
                parameter_slots={direct[0]},
                origin_kind="memory_object",
            ),
        )

    object_id = node_object_id(base)
    if object_id.startswith("stack:"):
        return ({"kind": "stack_object", "object_id": object_id}, None)

    address = node_constant(base)
    if address is None and bool(base.get("is_address")):
        address = parse_int(base.get("offset"))
    if address is not None:
        block = _memory_block(program_facts, address)
        if block and bool(block.get("write")):
            return (
                {
                    "kind": "static_writable_object",
                    "address": hex(address),
                    "memory_block": str(block.get("name", "")),
                },
                None,
            )
        return ({"kind": "non_writable_or_unknown_static_address", "address": hex(address)}, None)

    # A pointer loaded from a formal object field is a common aggregate base.
    definition = cfg.definitions.get(node_value_id(base))
    if definition and str(definition.get("mnemonic", "")) == "LOAD":
        parts = _inputs(definition)
        load_address = parts[-1] if len(parts) >= 2 else {}
        access = cfg.formal_access(load_address)
        if access is not None and _pointer_type(str(base.get("high_data_type", ""))):
            return (
                {
                    "kind": "pointer_loaded_from_formal_object",
                    "parameter_slot": access[0],
                    "access_path": list(access[1]),
                    "load_site_id": str(definition.get("site_id", "")),
                },
                _parameter(
                    "dst",
                    base,
                    cfg,
                    parameter_slots={access[0]},
                    origin_kind="memory_object",
                ),
            )

    source_rows = associations.buffer_lineage(cfg, base)
    if source_rows:
        return (
            {
                "kind": "source_associated_object_reference",
                "association_ids": [
                    str(row.get("association_id", "")) for row in source_rows
                ],
            },
            _parameter("dst", base, cfg, origin_kind="memory_object"),
        )
    return ({"kind": "unresolved_base_object"}, None)


def discover_variable_address_stores(
    program_facts: dict[str, Any],
    function: dict[str, Any],
    cfg: FunctionCFG,
    *,
    source_associations: SourceAssociationIndex,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return accepted audit descriptors and structural candidate decisions."""

    accepted: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    function_id = str(function.get("function_id", ""))
    function_name = str(function.get("name", ""))
    parameter_types = _parameter_types(function)
    for store in cfg.ops:
        if str(store.get("mnemonic", "")) != "STORE":
            continue
        parts = _inputs(store)
        if len(parts) < 3:
            continue
        address_node = parts[-2]
        stored_node = parts[-1]
        shape = decompose_address(cfg, function, address_node)
        # Fixed field updates are intentionally not candidates for this rule.
        if not shape.dynamic_nodes:
            continue
        evidence: dict[str, Any] = {
            "store_site_id": str(store.get("site_id", "")),
            "address": shape.as_json(),
            "stored_value_id": node_value_id(stored_node),
            "stored_value_expr": node_text(stored_node),
        }

        def reject(reason: str) -> None:
            decisions.append(
                StoreDecision(
                    function_id,
                    function_name,
                    str(store.get("site_id", "")),
                    "rejected",
                    reason,
                    evidence,
                ).as_candidate()
            )

        if not shape.complete:
            reject(shape.blocker or "variable_store_address_incomplete")
            continue
        base_evidence, base_parameter = _base_proof(
            program_facts,
            function,
            cfg,
            shape.base_node,
            source_associations,
        )
        evidence["base_proof"] = base_evidence
        if str(base_evidence.get("kind", "")) in {
            "unresolved_base_object",
            "non_writable_or_unknown_static_address",
        }:
            reject("variable_store_base_not_proved_writable")
            continue

        parameters: list[dict[str, Any]] = []
        dynamic_evidence: list[dict[str, Any]] = []
        for dynamic in shape.dynamic_nodes:
            formal_slots = {
                slot
                for slot in _formal_slots_in_lineage(cfg, dynamic)
                if not _pointer_type(parameter_types.get(slot, ""))
            }
            source_rows = source_associations.dynamic_lineage(cfg, dynamic)
            if not formal_slots and not source_rows:
                continue
            role = "index" if len(shape.dynamic_nodes) == 1 else "offset"
            parameters.append(
                _parameter(
                    role,
                    dynamic,
                    cfg,
                    parameter_slots=formal_slots,
                    origin_kind="scalar",
                )
            )
            dynamic_evidence.append(
                {
                    "value_id": node_value_id(dynamic),
                    "expr": node_text(dynamic),
                    "formal_slots": sorted(formal_slots),
                    "source_association_ids": [
                        str(row.get("association_id", "")) for row in source_rows
                    ],
                }
            )
        if not parameters:
            evidence["dynamic_terms"] = dynamic_evidence
            reject("variable_store_offset_not_formal_or_source_associated")
            continue
        if base_parameter is not None:
            parameters.insert(0, base_parameter)

        deduped: list[dict[str, Any]] = []
        seen_parameters: set[tuple[str, str]] = set()
        for parameter in parameters:
            key = (str(parameter.get("role", "")), str(parameter.get("value_id", "")))
            if bool(parameter.get("constant")) or key in seen_parameters:
                continue
            seen_parameters.add(key)
            deduped.append(parameter)
        if not deduped:
            reject("variable_store_no_trackable_parameter")
            continue

        evidence["dynamic_terms"] = dynamic_evidence
        descriptor = {
            "site": dict(store),
            "roles": {
                "dst": node_text(shape.base_node),
                "address": node_text(address_node),
                "value": node_text(stored_node),
            },
            "vulnerable_parameters": deduped,
            "object_roles": {
                "dst": {
                    "expr": node_text(shape.base_node),
                    "value_id": node_value_id(shape.base_node),
                    "object_id": node_object_id(shape.base_node),
                    "base_proof": base_evidence,
                }
            },
            "proof": {
                "proof_kind": "variable_address_store",
                "audit_only": True,
                **evidence,
            },
        }
        accepted.append(descriptor)
        decisions.append(
            StoreDecision(
                function_id,
                function_name,
                str(store.get("site_id", "")),
                "confirmed",
                "variable_address_store_candidate",
                evidence,
            ).as_candidate()
        )
    return accepted, decisions
