#!/usr/bin/env python3
"""Recover narrowly supported parser out-of-bounds read candidates.

This module is intentionally name-independent except for standard range-read
contracts supplied by the Sink registry.  Direct reads are recovered from
High P-code LOAD operations.  A read becomes a Sink candidate only when its
address/range is controlled by Source-associated data, or when the buffer and
its available extent are outputs of the same SourceDefinition.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Iterable

from high_pcode_loop_analysis import (
    FunctionCFG,
    comparison_for_branch,
    node_constant,
    node_object_id,
    node_signed_constant,
    node_text,
    node_value_id,
    parse_int,
)
from software_source_engine import ProgramIndex


TRANSPARENT_OPS = {
    "COPY",
    "CAST",
    "INT_ZEXT",
    "INT_SEXT",
    "SUBPIECE",
    "INDIRECT",
}
ADDRESS_OPS = {"PTRADD", "PTRSUB", "INT_ADD", "INT_SUB"}
LINEAGE_OPS = TRANSPARENT_OPS | ADDRESS_OPS | {
    "INT_MULT",
    "INT_LEFT",
    "INT_RIGHT",
    "INT_SRIGHT",
    "INT_AND",
    "INT_OR",
    "INT_XOR",
    "MULTIEQUAL",
    "PIECE",
}
SOURCE_DECISIONS = {"ACCEPT_DETERMINISTIC", "ACCEPT_HEURISTIC"}
BUFFER_ROLES = {"output_buffer", "source_buffer", "callback_input"}
EXTENT_ROLES = {"available_length", "received_length", "input_length"}


def _stable_id(prefix: str, *parts: Any) -> str:
    payload = "\x1f".join(str(part or "") for part in parts).encode(
        "utf-8", "replace"
    )
    return f"{prefix}:{hashlib.sha256(payload).hexdigest()[:20]}"


def _inputs(op: dict[str, Any]) -> list[dict[str, Any]]:
    return [dict(item or {}) for item in list(op.get("inputs", []) or [])]


def _output(op: dict[str, Any]) -> dict[str, Any]:
    return dict(op.get("output", {}) or {})


def _site(op: dict[str, Any]) -> str:
    return str(op.get("site_id", ""))


def _node_key(node: dict[str, Any]) -> str:
    return node_value_id(node) or node_object_id(node)


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


def _memory_block(program_facts: dict[str, Any], address: int) -> dict[str, Any]:
    for raw in list(program_facts.get("memory_blocks", []) or []):
        row = dict(raw or {})
        start = parse_int(row.get("start"))
        end = parse_int(row.get("end"))
        if start is not None and end is not None and start <= address <= end:
            return row
    return {}


def immutable_pointer(program_facts: dict[str, Any], node: dict[str, Any]) -> bool:
    address = node_constant(node)
    if address is None and bool(node.get("is_address")):
        address = parse_int(node.get("offset"))
    if address is None:
        return False
    block = _memory_block(program_facts, address)
    return bool(
        block
        and block.get("read")
        and not block.get("write")
        and block.get("initialized")
    )


@dataclass(frozen=True)
class AddressShape:
    base_node: dict[str, Any]
    dynamic_nodes: tuple[dict[str, Any], ...]
    fixed_offset: int
    complete: bool
    blocker: str = ""

    def as_json(self) -> dict[str, Any]:
        return {
            "base_value_id": node_value_id(self.base_node),
            "base_object_id": node_object_id(self.base_node),
            "base_expr": node_text(self.base_node),
            "dynamic_value_ids": [
                node_value_id(node) for node in self.dynamic_nodes if node_value_id(node)
            ],
            "dynamic_exprs": [node_text(node) for node in self.dynamic_nodes],
            "fixed_offset": self.fixed_offset,
            "complete": self.complete,
            "blocker": self.blocker,
        }


@dataclass(frozen=True)
class ReadEffect:
    kind: str
    function_id: str
    function: str
    site: dict[str, Any]
    address_node: dict[str, Any]
    shape: AddressShape
    width_node: dict[str, Any]
    width_constant: int | None
    read_operand_index: int | None = None
    callee: str = ""

    @property
    def effect_id(self) -> str:
        return _stable_id(
            "read-effect",
            self.function_id,
            _site(self.site),
            self.kind,
            self.read_operand_index,
        )

    def as_json(self) -> dict[str, Any]:
        return {
            "read_effect_id": self.effect_id,
            "kind": self.kind,
            "site_id": _site(self.site),
            "block_id": str(self.site.get("block_id", "")),
            "instruction_address": str(self.site.get("instruction_address", "")),
            "callee": self.callee,
            "read_operand_index": self.read_operand_index,
            "address_value_id": node_value_id(self.address_node),
            "address_object_id": node_object_id(self.address_node),
            "address_expr": node_text(self.address_node),
            "width_value_id": node_value_id(self.width_node),
            "width_expr": node_text(self.width_node),
            "width_constant": self.width_constant,
            **self.shape.as_json(),
        }


class SourceAssociationIndex:
    """Query explicit Source Association facts without inventing provenance."""

    def __init__(self, rows: Iterable[dict[str, Any]]) -> None:
        self.rows = [
            dict(row or {})
            for row in rows
            if str(dict(row or {}).get("source_decision", "")) in SOURCE_DECISIONS
        ]
        self.by_atom: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self.by_object: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self.by_definition: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in self.rows:
            function_id = str(row.get("function_id", ""))
            atom_id = str(row.get("atom_id", ""))
            if function_id and atom_id:
                self.by_atom[(function_id, atom_id)].append(row)
            object_ids = {
                str(row.get("object_id", "")),
                str(row.get("pointee_object_id", "")),
                str(dict(row.get("region", {}) or {}).get("object_id", "")),
                str(dict(row.get("region", {}) or {}).get("base_object_id", "")),
            }
            for object_id in object_ids - {""}:
                self.by_object[(function_id, object_id)].append(row)
            definition_id = str(row.get("source_definition_id", ""))
            if definition_id:
                self.by_definition[definition_id].append(row)

    @staticmethod
    def _dedupe(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in rows:
            key = str(row.get("association_id", "")) or repr(sorted(row.items()))
            if key in seen:
                continue
            seen.add(key)
            result.append(row)
        return result

    def direct(self, function_id: str, node: dict[str, Any]) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        atom_id = _node_key(node)
        object_id = node_object_id(node)
        if atom_id:
            rows.extend(self.by_atom.get((function_id, atom_id), []))
        if object_id:
            rows.extend(self.by_object.get((function_id, object_id), []))
        return self._dedupe(rows)

    def lineage(
        self,
        cfg: FunctionCFG,
        node: dict[str, Any],
        *,
        allowed_states: set[str] | None = None,
        limit: int = 96,
    ) -> list[dict[str, Any]]:
        queue: deque[dict[str, Any]] = deque([dict(node)])
        seen: set[str] = set()
        matches: list[dict[str, Any]] = []
        steps = 0
        while queue and steps < limit:
            current = queue.popleft()
            steps += 1
            key = _node_key(current)
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            matches.extend(self.direct(cfg.function_id, current))
            definition = cfg.definitions.get(node_value_id(current))
            if not definition or str(definition.get("mnemonic", "")) not in LINEAGE_OPS:
                continue
            queue.extend(_inputs(definition))
        if allowed_states is not None:
            matches = [
                row for row in matches if str(row.get("state_kind", "")) in allowed_states
            ]
        return self._dedupe(matches)

    @staticmethod
    def is_dynamic_value(row: dict[str, Any]) -> bool:
        # OBJECT_REFERENCE means that a pointer identifies a Source-derived
        # object. It does not mean that attacker bytes control the numerical
        # pointer value. Only VALUE lineage can control an offset/width/cursor.
        return str(row.get("state_kind", "")) == "VALUE"

    def dynamic_lineage(
        self, cfg: FunctionCFG, node: dict[str, Any]
    ) -> list[dict[str, Any]]:
        return [
            row
            for row in self.lineage(
                cfg, node, allowed_states={"VALUE"}
            )
            if self.is_dynamic_value(row)
        ]

    def buffer_lineage(
        self, cfg: FunctionCFG, node: dict[str, Any]
    ) -> list[dict[str, Any]]:
        return [
            row
            for row in self.lineage(cfg, node)
            if str(row.get("source_output_role", "")) in BUFFER_ROLES
            and str(row.get("state_kind", "")) in {
                "MEMORY_CONTENT",
                "OBJECT_REFERENCE",
            }
        ]

    def extent_rows(
        self, *, function_id: str, source_definition_id: str
    ) -> list[dict[str, Any]]:
        return self._dedupe(
            row
            for row in self.by_definition.get(source_definition_id, [])
            if str(row.get("function_id", "")) == function_id
            and str(row.get("state_kind", "")) == "VALUE"
            and str(row.get("source_output_role", "")) in EXTENT_ROLES
            and (
                str(row.get("extent_for_role", "")) in BUFFER_ROLES
                or (
                    str(row.get("source_output_role", "")) == "available_length"
                    and not str(row.get("extent_for_role", ""))
                )
            )
            and str(row.get("atom_id", ""))
        )


def _parameter_types(function: dict[str, Any]) -> dict[int, str]:
    return {
        int(row.get("index")): str(row.get("data_type", ""))
        for row in list(function.get("parameters", []) or [])
        if isinstance(row.get("index"), int)
    }


def _looks_like_pointer(node: dict[str, Any], function: dict[str, Any]) -> bool:
    data_type = str(node.get("high_data_type", ""))
    if "*" in data_type or data_type.rstrip().endswith("[]"):
        return True
    slot = _parameter_slot(node)
    parameter_type = _parameter_types(function).get(slot, "") if slot is not None else ""
    if "*" in parameter_type or parameter_type.rstrip().endswith("[]"):
        return True
    object_id = node_object_id(node)
    return bool(
        node.get("is_address")
        or object_id.startswith(("global:", "stack:", "symbol:", "obj:"))
    )


def decompose_address(
    cfg: FunctionCFG,
    function: dict[str, Any],
    node: dict[str, Any],
    *,
    limit: int = 48,
) -> AddressShape:
    """Split a pointer expression into one base, dynamic terms, and constants."""

    active: set[str] = set()

    def visit(current: dict[str, Any], depth: int, root: bool = False) -> AddressShape:
        if depth > limit:
            return AddressShape(current, (), 0, False, "address_resolution_limit")
        value_id = node_value_id(current)
        if value_id and value_id in active:
            return AddressShape(current, (), 0, False, "address_definition_cycle")
        definition = cfg.definitions.get(value_id)
        if not definition:
            if root or _looks_like_pointer(current, function):
                return AddressShape(current, (), 0, True)
            return AddressShape({}, (), 0, False, "address_base_not_pointer_like")
        mnemonic = str(definition.get("mnemonic", ""))
        parts = _inputs(definition)
        if value_id:
            active.add(value_id)
        try:
            if mnemonic in TRANSPARENT_OPS and parts:
                return visit(parts[0], depth + 1, root=True)
            if mnemonic == "PTRADD" and len(parts) >= 3:
                base = visit(parts[0], depth + 1, root=True)
                scale = node_signed_constant(parts[2])
                index = node_signed_constant(parts[1])
                if scale is None:
                    return AddressShape(
                        base.base_node, base.dynamic_nodes, base.fixed_offset,
                        False, "ptradd_scale_not_constant"
                    )
                if index is not None:
                    return AddressShape(
                        base.base_node,
                        base.dynamic_nodes,
                        base.fixed_offset + index * scale,
                        base.complete,
                        base.blocker,
                    )
                return AddressShape(
                    base.base_node,
                    base.dynamic_nodes + (parts[1],),
                    base.fixed_offset,
                    base.complete,
                    base.blocker,
                )
            if mnemonic in {"PTRSUB", "INT_ADD", "INT_SUB"} and len(parts) >= 2:
                left = visit(parts[0], depth + 1, root=True)
                if not left.base_node:
                    return AddressShape(current, (), 0, False, "address_base_unresolved")
                delta = node_signed_constant(parts[1])
                sign = -1 if mnemonic == "INT_SUB" else 1
                if delta is not None:
                    return AddressShape(
                        left.base_node,
                        left.dynamic_nodes,
                        left.fixed_offset + sign * delta,
                        left.complete,
                        left.blocker,
                    )
                return AddressShape(
                    left.base_node,
                    left.dynamic_nodes + (parts[1],),
                    left.fixed_offset,
                    left.complete,
                    left.blocker,
                )
            # A pointer loaded from an object or selected by PHI is still a
            # concrete cursor value, but its deeper alias is outside this
            # local address decomposition.
            if mnemonic in {"LOAD", "MULTIEQUAL", "CALL", "CALLIND"} or root:
                return AddressShape(current, (), 0, True)
            return AddressShape(current, (), 0, False, "unsupported_address_operation")
        finally:
            if value_id:
                active.discard(value_id)

    shape = visit(dict(node), 0, root=True)
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for dynamic in shape.dynamic_nodes:
        key = _node_key(dynamic)
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        unique.append(dynamic)
    return AddressShape(
        shape.base_node,
        tuple(unique),
        shape.fixed_offset,
        shape.complete,
        shape.blocker,
    )


def _node_for_atom(cfg: FunctionCFG, atom_id: str) -> dict[str, Any]:
    definition = cfg.definitions.get(atom_id)
    if definition:
        return _output(definition)
    for op in cfg.ops:
        for node in _inputs(op):
            if _node_key(node) == atom_id:
                return node
    return {"value_id": atom_id, "object_id": "", "high_name": atom_id}


def _parameter(
    role: str,
    node: dict[str, Any],
    cfg: FunctionCFG,
    *,
    origin_kind: str = "scalar",
) -> dict[str, Any]:
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
    access = cfg.formal_access(node)
    if access is not None:
        row["parameter_slot"] = access[0]
        row["access_path"] = list(access[1])
        if not row["expr"]:
            row["expr"] = f"arg{access[0]}"
    return row


def _source_controlled_loop_read(
    effect: ReadEffect,
    cfg: FunctionCFG,
    associations: SourceAssociationIndex,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Bind parser reads driven by a Source-controlled cursor loop.

    A parser commonly keeps the current record pointer in a PHI node.  The
    concrete LOAD then has a constant field offset, while attacker bytes
    control the loop count and/or the amount added to the pointer after each
    record.  Looking only at the final LOAD address loses both dependencies.

    This path deliberately requires three structural facts: the read occurs
    in a natural loop, its base is a loop-header PHI with a concrete pointer
    update, and a loop-exit comparison has explicit Source VALUE lineage.
    Names, CVE identities, and framework contracts are not consulted.
    """

    read_block = str(effect.site.get("block_id", ""))
    base_value_id = node_value_id(effect.shape.base_node)
    base_definition = cfg.definitions.get(base_value_id)
    if not base_definition or str(base_definition.get("mnemonic", "")) != "MULTIEQUAL":
        return [], {}

    parameters: list[dict[str, Any]] = []
    source_rows: list[dict[str, Any]] = []
    loop_evidence: list[dict[str, Any]] = []
    for loop in cfg.loops:
        if read_block not in loop.blocks:
            continue
        if str(base_definition.get("block_id", "")) != loop.header:
            continue

        update_rows: list[dict[str, Any]] = []
        update_source_rows: list[dict[str, Any]] = []
        update_parameters: list[dict[str, Any]] = []
        seen_updates: set[str] = set()
        for phi_input in _inputs(base_definition):
            update_value_id = node_value_id(phi_input)
            if not update_value_id or update_value_id in seen_updates:
                continue
            seen_updates.add(update_value_id)
            update = cfg.definitions.get(update_value_id)
            if not update or str(update.get("block_id", "")) not in loop.blocks:
                continue
            mnemonic = str(update.get("mnemonic", ""))
            if mnemonic not in ADDRESS_OPS:
                continue
            if not cfg.depends_on(
                phi_input,
                base_value_id,
                allowed_ops=TRANSPARENT_OPS | ADDRESS_OPS,
            ):
                continue

            dynamic_step = False
            fixed_step = False
            for part in _inputs(update):
                if cfg.depends_on(
                    part,
                    base_value_id,
                    allowed_ops=TRANSPARENT_OPS | ADDRESS_OPS,
                ):
                    continue
                constant = node_signed_constant(part)
                if constant is not None:
                    fixed_step = fixed_step or constant != 0
                    continue
                rows = associations.dynamic_lineage(cfg, part)
                if rows:
                    dynamic_step = True
                    update_source_rows.extend(rows)
                    update_parameters.append(_parameter("offset", part, cfg))
            if dynamic_step or fixed_step:
                update_rows.append(
                    {
                        "site_id": str(update.get("site_id", "")),
                        "value_id": update_value_id,
                        "mnemonic": mnemonic,
                        "source_derived_step": dynamic_step,
                    }
                )
        if not update_rows:
            continue

        control_rows: list[dict[str, Any]] = []
        control_parameters: list[dict[str, Any]] = []
        branch_rows: list[dict[str, Any]] = []
        for branch in cfg.controlling_branches(loop):
            parsed = comparison_for_branch(cfg, branch)
            if parsed is None:
                continue
            comparison, operands = parsed
            matched_operands: list[str] = []
            for operand in operands:
                rows = associations.dynamic_lineage(cfg, operand)
                if not rows:
                    continue
                control_rows.extend(rows)
                control_parameters.append(_parameter("index", operand, cfg))
                matched_operands.append(node_value_id(operand))
            if matched_operands:
                branch_rows.append(
                    {
                        "branch_site_id": str(branch.get("site_id", "")),
                        "comparison_site_id": str(comparison.get("site_id", "")),
                        "comparison": str(comparison.get("mnemonic", "")),
                        "source_derived_operand_value_ids": matched_operands,
                    }
                )
        if not branch_rows:
            continue

        parameters.extend(control_parameters)
        parameters.extend(update_parameters)
        source_rows.extend(control_rows)
        source_rows.extend(update_source_rows)
        loop_evidence.append(
            {
                "loop_id": loop.loop_id,
                "header_block_id": loop.header,
                "pointer_phi_value_id": base_value_id,
                "pointer_phi_site_id": str(base_definition.get("site_id", "")),
                "pointer_updates": update_rows,
                "exit_controls": branch_rows,
            }
        )

    deduped_parameters: list[dict[str, Any]] = []
    seen_parameters: set[tuple[str, str]] = set()
    for row in parameters:
        key = (str(row.get("role", "")), str(row.get("value_id", "")))
        if not key[1] or key in seen_parameters or bool(row.get("constant", False)):
            continue
        seen_parameters.add(key)
        deduped_parameters.append(row)
    if not deduped_parameters:
        return [], {}

    source_rows = SourceAssociationIndex._dedupe(source_rows)
    return deduped_parameters, {
        "admission_path": "SOURCE_DERIVED_LOOP_CONTROL",
        "source_association_ids": [
            str(row.get("association_id", "")) for row in source_rows
        ],
        "source_definition_ids": sorted(
            {str(row.get("source_definition_id", "")) for row in source_rows}
            - {""}
        ),
        "loop_evidence": loop_evidence,
    }


def _admit_effect(
    effect: ReadEffect,
    cfg: FunctionCFG,
    associations: SourceAssociationIndex,
) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
    """Return vulnerable parameters, admission proof, and rejection reason."""

    parameters: list[dict[str, Any]] = []
    dynamic_evidence: list[dict[str, Any]] = []
    for position, node in enumerate(effect.shape.dynamic_nodes):
        rows = associations.dynamic_lineage(cfg, node)
        if not rows:
            continue
        role = "offset"
        parameters.append(_parameter(role, node, cfg))
        dynamic_evidence.extend(rows)

    width_evidence: list[dict[str, Any]] = []
    if effect.width_constant is None and node_value_id(effect.width_node):
        width_evidence = associations.dynamic_lineage(cfg, effect.width_node)
        if width_evidence:
            parameters.append(_parameter("width", effect.width_node, cfg))

    if parameters:
        deduped: list[dict[str, Any]] = []
        seen = set()
        for row in parameters:
            key = (str(row.get("role", "")), str(row.get("value_id", "")))
            if key in seen or bool(row.get("constant", False)):
                continue
            seen.add(key)
            deduped.append(row)
        if deduped:
            evidence_rows = SourceAssociationIndex._dedupe(
                [*dynamic_evidence, *width_evidence]
            )
            admission = {
                "admission_path": "SOURCE_DERIVED_ADDRESS_OR_WIDTH",
                "source_association_ids": [
                    str(row.get("association_id", "")) for row in evidence_rows
                ],
                "source_definition_ids": sorted(
                    {str(row.get("source_definition_id", "")) for row in evidence_rows}
                    - {""}
                ),
            }
            # Preserve a matching receive-length value when the same Source
            # contract also defines the base buffer. It is not needed for
            # admission Path A, but it lets the local Check binder prove an
            # exact range guard without inventing a capacity variable.
            extent_rows: list[dict[str, Any]] = []
            buffer_rows = associations.buffer_lineage(cfg, effect.shape.base_node)
            for buffer_row in buffer_rows:
                extent_rows.extend(
                    associations.extent_rows(
                        function_id=cfg.function_id,
                        source_definition_id=str(
                            buffer_row.get("source_definition_id", "")
                        ),
                    )
                )
            extent_atoms = sorted(
                {
                    str(row.get("atom_id", ""))
                    for row in SourceAssociationIndex._dedupe(extent_rows)
                }
                - {""}
            )
            if len(extent_atoms) == 1:
                admission["available_length_value_id"] = extent_atoms[0]
                admission["extent_source_association_ids"] = [
                    str(row.get("association_id", ""))
                    for row in SourceAssociationIndex._dedupe(extent_rows)
                ]
            return deduped, admission, ""

    loop_parameters, loop_admission = _source_controlled_loop_read(
        effect, cfg, associations
    )
    if loop_parameters:
        return loop_parameters, loop_admission, ""

    buffer_rows = associations.buffer_lineage(cfg, effect.shape.base_node)
    extent_candidates: list[dict[str, Any]] = []
    matching_buffer_rows: list[dict[str, Any]] = []
    for buffer_row in buffer_rows:
        definition_id = str(buffer_row.get("source_definition_id", ""))
        extent_rows = associations.extent_rows(
            function_id=cfg.function_id,
            source_definition_id=definition_id,
        )
        if extent_rows:
            matching_buffer_rows.append(buffer_row)
            extent_candidates.extend(extent_rows)
    extent_candidates = SourceAssociationIndex._dedupe(extent_candidates)
    extent_atoms = sorted(
        {str(row.get("atom_id", "")) for row in extent_candidates} - {""}
    )
    if not matching_buffer_rows:
        return [], {}, "no_source_derived_address_or_buffer_extent_contract"
    if len(extent_atoms) != 1:
        return [], {
            "buffer_source_association_ids": [
                str(row.get("association_id", "")) for row in matching_buffer_rows
            ],
            "available_length_value_ids": extent_atoms,
        }, "available_length_not_unique_for_source_buffer"

    extent_node = _node_for_atom(cfg, extent_atoms[0])
    parameter = _parameter("available_length", extent_node, cfg)
    if bool(parameter.get("constant", False)) or not parameter.get("value_id"):
        return [], {}, "available_length_not_traceable"
    definition_ids = sorted(
        {
            str(row.get("source_definition_id", ""))
            for row in matching_buffer_rows
        }
        & {
            str(row.get("source_definition_id", ""))
            for row in extent_candidates
        }
        - {""}
    )
    return [parameter], {
        "admission_path": "SAME_SOURCE_BUFFER_AND_AVAILABLE_LENGTH_CONTRACT",
        "source_definition_ids": definition_ids,
        "buffer_source_association_ids": [
            str(row.get("association_id", "")) for row in matching_buffer_rows
        ],
        "extent_source_association_ids": [
            str(row.get("association_id", "")) for row in extent_candidates
        ],
        "available_length_value_id": extent_atoms[0],
    }, ""


def _direct_load_effects(
    function: dict[str, Any], cfg: FunctionCFG
) -> Iterable[ReadEffect]:
    for op in cfg.ops:
        if str(op.get("mnemonic", "")) != "LOAD":
            continue
        inputs = _inputs(op)
        if len(inputs) < 2 or not _site(op):
            continue
        address = inputs[-1]
        output = _output(op)
        width = int(output.get("size", 0) or 0)
        if width <= 0:
            continue
        yield ReadEffect(
            kind="direct_load",
            function_id=cfg.function_id,
            function=str(function.get("name", "")),
            site=op,
            address_node=address,
            shape=decompose_address(cfg, function, address),
            width_node={
                "value_id": f"const:{width}:read-width",
                "object_id": f"const:{width}:read-width",
                "is_constant": True,
                "offset": hex(width),
                "size": 4,
                "high_name": str(width),
            },
            width_constant=width,
        )


def _range_read_effects(
    program_facts: dict[str, Any],
    function: dict[str, Any],
    cfg: FunctionCFG,
    program_index: ProgramIndex,
    specifications: list[dict[str, Any]],
) -> Iterable[ReadEffect]:
    by_name = {
        str(spec.get("name", "")): dict(spec)
        for spec in specifications
        if str(spec.get("name", ""))
    }
    if not by_name:
        return
    for op in cfg.ops:
        if str(op.get("mnemonic", "")) not in {"CALL", "CALLIND"}:
            continue
        call = dict(op.get("call", {}) or {})
        target = program_index.resolve_call_target(function, op)
        target_name = str((target or {}).get("name", "")) or str(
            call.get("target_function", "")
        )
        spec = by_name.get(target_name)
        if spec is None:
            continue
        actuals = program_index.call_actuals(function, op)
        length_slot = spec.get("length_arg")
        if not isinstance(length_slot, int) or length_slot >= len(actuals):
            continue
        width_node = actuals[length_slot]
        width_constant = node_constant(width_node)
        for pointer_slot in list(spec.get("read_pointer_args", []) or []):
            if not isinstance(pointer_slot, int) or pointer_slot >= len(actuals):
                continue
            address = actuals[pointer_slot]
            if immutable_pointer(program_facts, address):
                continue
            yield ReadEffect(
                kind="range_read_call",
                function_id=cfg.function_id,
                function=str(function.get("name", "")),
                site=op,
                address_node=address,
                shape=decompose_address(cfg, function, address),
                width_node=width_node,
                width_constant=width_constant,
                read_operand_index=pointer_slot,
                callee=target_name,
            )


def discover_parser_oob_reads(
    program_facts: dict[str, Any],
    function: dict[str, Any],
    cfg: FunctionCFG,
    *,
    source_associations: Iterable[dict[str, Any]] | SourceAssociationIndex,
    rule: dict[str, Any],
    program_index: ProgramIndex,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return admitted read effects and auditable candidate decisions."""

    association_index = (
        source_associations
        if isinstance(source_associations, SourceAssociationIndex)
        else SourceAssociationIndex(source_associations)
    )
    effects = list(_direct_load_effects(function, cfg))
    effects.extend(
        _range_read_effects(
            program_facts,
            function,
            cfg,
            program_index,
            list(rule.get("range_read_primitives", []) or []),
        )
    )
    accepted: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    for effect in effects:
        read_json = effect.as_json()
        if not effect.shape.complete:
            decisions.append(
                {
                    "pattern": "parser_oob_read",
                    "function_id": cfg.function_id,
                    "function": str(function.get("name", "")),
                    "site_id": _site(effect.site),
                    "status": "rejected",
                    "reason_code": effect.shape.blocker or "read_address_unresolved",
                    "evidence": {"read_effect": read_json},
                }
            )
            continue
        parameters, admission, rejection = _admit_effect(
            effect, cfg, association_index
        )
        if rejection:
            # Ordinary non-Source LOADs are not parser candidates and would
            # dominate audit volume. Preserve only near-misses that had a
            # Source buffer or ambiguous extent contract.
            if admission or association_index.buffer_lineage(
                cfg, effect.shape.base_node
            ):
                decisions.append(
                    {
                        "pattern": "parser_oob_read",
                        "function_id": cfg.function_id,
                        "function": str(function.get("name", "")),
                        "site_id": _site(effect.site),
                        "status": "rejected",
                        "reason_code": rejection,
                        "evidence": {
                            "read_effect": read_json,
                            "admission": admission,
                        },
                    }
                )
            continue
        proof = {
            "pattern": "parser_oob_read_v1",
            "read_effect": read_json,
            "admission": admission,
            "recognition_boundary": (
                "high_pcode_load_or_registry_range_read_plus_source_association"
            ),
        }
        accepted.append(
            {
                "site": effect.site,
                "read_effect_id": effect.effect_id,
                "roles": {
                    str(row.get("role", "")): str(row.get("expr", ""))
                    for row in parameters
                },
                "vulnerable_parameters": parameters,
                "object_roles": {},
                "proof": proof,
            }
        )
        decisions.append(
            {
                "pattern": "parser_oob_read",
                "function_id": cfg.function_id,
                "function": str(function.get("name", "")),
                "site_id": _site(effect.site),
                "status": "confirmed",
                "reason_code": "source_associated_parser_read_effect",
                "evidence": proof,
            }
        )
    return accepted, decisions
