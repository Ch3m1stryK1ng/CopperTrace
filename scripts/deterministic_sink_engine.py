#!/usr/bin/env python3
"""Deterministic Sink discovery over whole-image Ghidra High P-code.

The engine deliberately supports a narrow class of Sink effects:

* exact standard C/runtime primitive calls; and
* internal functions whose effect can be derived recursively from those
  primitives by unique actual/formal High P-code bindings.

Generic STOREs, loops, parser-state updates, lifetime patterns, and indirect
control-flow vulnerability candidates are not promoted here.  Body-derived
patterns, including paired buffer-state effects, belong to the heuristic
recognizer and must not be reported by this deterministic engine.
"""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable

from software_source_engine import (
    ProgramIndex,
    formal_access_path,
    node_object_id,
    node_value_id,
    parse_int,
)
from sink_artifact_schema import (
    RECOGNITION_DETERMINISTIC,
    SINK_ARTIFACT_SCHEMA_VERSION,
    normalize_sink_registry,
    role_tracking,
    semantic_roles,
)


def stable_id(prefix: str, *parts: Any) -> str:
    payload = "\x1f".join(str(part or "") for part in parts).encode("utf-8", "replace")
    return f"{prefix}:{hashlib.sha256(payload).hexdigest()[:20]}"


def normalize_expr(value: Any) -> str:
    return re.sub(r"\s+", "", str(value or "")).lower()


def display_integer_literal(value: Any) -> int | None:
    """Parse only an explicit C integer literal, never a symbolic expression."""

    text = str(value or "").strip()
    while True:
        without_cast = re.sub(
            r"^\(\s*[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*(?:\s*\*)*\s*\)\s*",
            "",
            text,
            count=1,
        )
        if without_cast == text:
            break
        text = without_cast.strip()
    while len(text) >= 2 and text[0] == "(" and text[-1] == ")":
        text = text[1:-1].strip()
    match = re.fullmatch(r"([+-]?(?:0[xX][0-9a-fA-F]+|\d+))[uUlL]*", text)
    if match is None:
        return None
    try:
        return int(match.group(1), 0)
    except ValueError:
        return None


def display_argument_score(
    index: ProgramIndex,
    function_id: str,
    c_argument: Any,
    actual: dict[str, Any],
) -> tuple[int, bool]:
    """Score review-text alignment without changing authoritative P-code facts."""

    expression = str(c_argument or "").strip()
    normalized = normalize_expr(expression)
    literal = display_integer_literal(expression)
    actual_constant = resolved_constant(index, function_id, actual)
    if literal is not None and actual_constant is not None:
        return (12, False) if literal == actual_constant else (-100, True)
    if literal is not None:
        return (-4, False)

    score = 0
    high_name = normalize_expr(actual.get("high_name", ""))
    if high_name:
        identifiers = {
            normalize_expr(token)
            for token in re.findall(r"[A-Za-z_]\w*", expression)
        }
        if high_name == normalized or high_name in identifiers:
            score += 6

    slot = actual.get("parameter_slot")
    if isinstance(slot, int) and f"arg{slot}" in {
        token.lower() for token in re.findall(r"[A-Za-z_]\w*", expression)
    }:
        score += 5

    if literal is None and actual_constant is None:
        score += 1
    return score, False


def node_expression(node: dict[str, Any], fallback: str = "") -> str:
    return (
        str(fallback or "").strip()
        or str(node.get("high_name", "") or "").strip()
        or str(node.get("address", "") or "").strip()
        or node_value_id(node)
        or node_object_id(node)
    )


def role_arg_index(spec: dict[str, Any], role: str) -> int | None:
    value = spec.get(f"{role}_arg")
    return int(value) if isinstance(value, int) else None


def primitive_specs(registry: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = registry.get("primitive_sinks", {}) or {}
    if isinstance(rows, list):
        return {
            str(row.get("name", "")): {
                key: value
                for key, value in dict(row).items()
                if key not in {"name", "enabled"}
            }
            for row in rows
            if row.get("enabled", True) is not False and str(row.get("name", ""))
        }
    return {str(name): dict(spec) for name, spec in dict(rows).items()}


@dataclass(frozen=True)
class RoleBinding:
    kind: str
    parameter_slot: int | None = None
    access_path: tuple[int, ...] = ()
    constant: int | None = None
    supporting_access_paths: tuple[tuple[int, ...], ...] = ()

    def as_json(self) -> dict[str, Any]:
        row: dict[str, Any] = {"kind": self.kind}
        if self.parameter_slot is not None:
            key = (
                "base_parameter_slot"
                if self.kind == "derived_formal_object"
                else "parameter_slot"
            )
            row[key] = self.parameter_slot
        if self.access_path:
            row["access_path"] = list(self.access_path)
        if self.constant is not None:
            row["constant"] = self.constant
        if self.supporting_access_paths:
            row["supporting_access_paths"] = [
                list(path) for path in self.supporting_access_paths
            ]
        return row


@dataclass(frozen=True)
class EffectSummary:
    summary_id: str
    function_id: str
    function_name: str
    effect_site_id: str
    seed_name: str
    label: str
    sink_kind: str
    vulnerable_roles: tuple[str, ...]
    admission_roles: tuple[str, ...]
    role_tracking_kinds: tuple[tuple[str, str], ...]
    role_bindings: tuple[tuple[str, RoleBinding], ...]
    depth: int
    proof_path: tuple[str, ...]
    proof_kind: str = "primitive_call"

    @property
    def roles(self) -> dict[str, RoleBinding]:
        return dict(self.role_bindings)

    def key(self) -> tuple[Any, ...]:
        return (
            self.function_id,
            self.effect_site_id,
            self.label,
            self.role_bindings,
        )

    def as_json(self) -> dict[str, Any]:
        row = {
            "summary_id": self.summary_id,
            "function_id": self.function_id,
            "function_name": self.function_name,
            "effect_site_id": self.effect_site_id,
            "seed_name": self.seed_name,
            "label": self.label,
            "sink_kind": self.sink_kind,
            "vulnerable_parameter_roles": list(self.vulnerable_roles),
            "admission_roles": list(self.admission_roles),
            "semantic_roles": [role for role, _binding in self.role_bindings],
            "role_tracking": dict(self.role_tracking_kinds),
            "role_bindings": {
                role: binding.as_json() for role, binding in self.role_bindings
            },
            "depth": self.depth,
            "proof_path": list(self.proof_path),
            "proof_kind": self.proof_kind,
        }
        return row


class DisplayIndex:
    """Attach pseudo-C only as review text to authoritative P-code sites."""

    def __init__(
        self,
        index: ProgramIndex,
        display_calls: Iterable[dict[str, Any]],
    ) -> None:
        self.by_site: dict[str, dict[str, Any]] = {}
        pcode_groups: dict[tuple[str, str], list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
        for function, op in index.calls:
            target = index.resolve_call_target(function, op)
            call = dict(op.get("call", {}) or {})
            target_name = str((target or {}).get("name", "") or call.get("target_function", ""))
            if not target_name:
                continue
            pcode_groups[(str(function.get("name", "")), target_name)].append((function, op))

        c_groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in display_calls:
            key = (str(row.get("function", "")), str(row.get("callee", "")))
            c_groups[key].append(dict(row))

        for key, pcode_rows in pcode_groups.items():
            c_rows = list(c_groups.get(key, []))
            if len(c_rows) != len(pcode_rows):
                continue
            self._bind_group(index, pcode_rows, c_rows)

    def _bind_group(
        self,
        index: ProgramIndex,
        pcode_rows: list[tuple[dict[str, Any], dict[str, Any]]],
        c_rows: list[dict[str, Any]],
    ) -> None:
        """Bind only evidence-compatible calls; leave ambiguous text unattached."""

        remaining_pcode = list(range(len(pcode_rows)))
        remaining_c = list(range(len(c_rows)))
        compatible: dict[tuple[int, int], tuple[int, bool]] = {}
        for pcode_index, (function, op) in enumerate(pcode_rows):
            actuals = index.call_actuals(function, op)
            function_id = str(function.get("function_id", ""))
            for c_index, row in enumerate(c_rows):
                arguments = list(row.get("args", []) or [])
                if len(arguments) != len(actuals):
                    compatible[(pcode_index, c_index)] = (-100, True)
                    continue
                score = 0
                contradiction = False
                for argument, actual in zip(arguments, actuals, strict=True):
                    item_score, item_contradiction = display_argument_score(
                        index, function_id, argument, actual
                    )
                    score += item_score
                    contradiction = contradiction or item_contradiction
                compatible[(pcode_index, c_index)] = (score, contradiction)

        while remaining_pcode and remaining_c:
            if len(remaining_pcode) == len(remaining_c) == 1:
                pcode_index = remaining_pcode[0]
                c_index = remaining_c[0]
                _score, contradiction = compatible[(pcode_index, c_index)]
                if not contradiction:
                    self.by_site[str(pcode_rows[pcode_index][1].get("site_id", ""))] = dict(
                        c_rows[c_index]
                    )
                break

            pcode_best: dict[int, tuple[int, int] | None] = {}
            for pcode_index in remaining_pcode:
                ranked = sorted(
                    (
                        (compatible[(pcode_index, c_index)][0], c_index)
                        for c_index in remaining_c
                        if not compatible[(pcode_index, c_index)][1]
                    ),
                    reverse=True,
                )
                pcode_best[pcode_index] = (
                    ranked[0]
                    if ranked
                    and ranked[0][0] >= 5
                    and (len(ranked) == 1 or ranked[0][0] > ranked[1][0])
                    else None
                )

            c_best: dict[int, tuple[int, int] | None] = {}
            for c_index in remaining_c:
                ranked = sorted(
                    (
                        (compatible[(pcode_index, c_index)][0], pcode_index)
                        for pcode_index in remaining_pcode
                        if not compatible[(pcode_index, c_index)][1]
                    ),
                    reverse=True,
                )
                c_best[c_index] = (
                    ranked[0]
                    if ranked
                    and ranked[0][0] >= 5
                    and (len(ranked) == 1 or ranked[0][0] > ranked[1][0])
                    else None
                )

            matches: list[tuple[int, int]] = []
            for pcode_index, choice in pcode_best.items():
                if choice is None:
                    continue
                score, c_index = choice
                if c_best.get(c_index) == (score, pcode_index):
                    matches.append((pcode_index, c_index))
            if not matches:
                break
            for pcode_index, c_index in matches:
                self.by_site[str(pcode_rows[pcode_index][1].get("site_id", ""))] = dict(
                    c_rows[c_index]
                )
                remaining_pcode.remove(pcode_index)
                remaining_c.remove(c_index)

    def get(self, site_id: str) -> dict[str, Any]:
        return dict(self.by_site.get(site_id, {}))


def call_target(
    index: ProgramIndex, function: dict[str, Any], op: dict[str, Any]
) -> tuple[dict[str, Any] | None, str]:
    target = index.resolve_call_target(function, op)
    call = dict(op.get("call", {}) or {})
    name = str((target or {}).get("name", "") or call.get("target_function", ""))
    return target, name


def resolved_constant(
    index: ProgramIndex, function_id: str, node: dict[str, Any]
) -> int | None:
    if bool(node.get("is_constant")):
        return parse_int(node.get("offset"))
    return index.resolve_constant(function_id, node)


def readonly_initialized_address(index: ProgramIndex, node: dict[str, Any]) -> bool:
    """Return true only for an address inside an immutable initialized block."""

    # High P-code may keep the storage address of a global pointer on the
    # varnode that represents the pointer value loaded from that storage.  A
    # defined value is therefore not itself a direct address constant.
    if not bool(node.get("is_address")) or str(node.get("def_site_id", "")):
        return False
    address = parse_int(node.get("offset"))
    if address is None:
        return False
    for block in list(index.facts.get("memory_blocks", []) or []):
        start = parse_int(block.get("start"))
        end = parse_int(block.get("end"))
        if start is None or end is None or not (start <= address <= end):
            continue
        return bool(block.get("read")) and not bool(block.get("write")) and bool(
            block.get("initialized")
        )
    return False


def resolved_address(
    index: ProgramIndex, function_id: str, node: dict[str, Any]
) -> int | None:
    # Treat the varnode offset as a concrete pointer only for an address leaf.
    # For a value produced by LOAD/INDIRECT/COPY, the offset can identify the
    # global slot that held the pointer rather than the pointer's pointee.
    if bool(node.get("is_address")) and not str(node.get("def_site_id", "")):
        address = parse_int(node.get("offset"))
        if address is not None:
            return address
    return resolved_constant(index, function_id, node)


def memory_block_at(index: ProgramIndex, address: int) -> dict[str, Any] | None:
    for block in list(index.facts.get("memory_blocks", []) or []):
        start = parse_int(block.get("start"))
        end = parse_int(block.get("end"))
        if start is not None and end is not None and start <= address <= end:
            return dict(block)
    return None


def role_nodes(
    spec: dict[str, Any], actuals: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    roles: dict[str, dict[str, Any]] = {}
    for role in ("dst", "src", "len", "value", "fmt"):
        index = role_arg_index(spec, role)
        if index is not None and 0 <= index < len(actuals):
            roles[role] = dict(actuals[index])
    return roles


def role_expressions(
    spec: dict[str, Any], nodes: dict[str, dict[str, Any]], display: dict[str, Any]
) -> dict[str, str]:
    args = list(display.get("args", []) or [])
    out: dict[str, str] = {}
    for role, node in nodes.items():
        index = role_arg_index(spec, role)
        expression = str(args[index]) if index is not None and index < len(args) else ""
        out[role] = node_expression(node, expression)
    value_expr = str(spec.get("value_expr", "") or "")
    if value_expr and "value" not in out:
        out["value"] = value_expr
    return out


def parameter_rows(
    spec: dict[str, Any], nodes: dict[str, dict[str, Any]], expressions: dict[str, str],
    *, index: ProgramIndex, function_id: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    vulnerable = {
        str(role)
        for role in list(spec.get("vulnerable_parameter_roles", []) or [])
    }
    for role in semantic_roles(spec):
        node = dict(nodes.get(str(role), {}) or {})
        value_expr = str(spec.get("value_expr", "") or "") if role == "value" else ""
        if not node and not value_expr:
            continue
        argument_index = role_arg_index(spec, str(role))
        constant = (
            resolved_constant(index, function_id, node)
            if node else parse_int(value_expr)
        )
        row: dict[str, Any] = {
            "role": str(role),
            "expr": str(expressions.get(str(role), "") or value_expr),
            "tracking": role_tracking(spec, str(role)),
            "vulnerable": str(role) in vulnerable,
            "constant": constant is not None,
        }
        if argument_index is not None:
            row["index"] = argument_index
        if node and node_object_id(node):
            row["object_id"] = node_object_id(node)
        if node and node_value_id(node):
            row["value_id"] = node_value_id(node)
        if constant is not None:
            row["constant_value"] = constant
        rows.append(row)
    return rows


def prune_vulnerable_parameters(
    parameters: Iterable[dict[str, Any]],
    *,
    index: ProgramIndex,
    function_id: str,
    nodes: dict[str, dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Prune individual parameters without withdrawing useful sibling roles."""

    node_by_role = nodes or {}
    kept: list[dict[str, Any]] = []
    pruned: list[dict[str, Any]] = []
    for raw in parameters:
        if not bool(raw.get("vulnerable")):
            continue
        row = dict(raw)
        role = str(row.get("role", ""))
        tracking = str(row.get("tracking", "scalar"))
        node = dict(node_by_role.get(role, {}) or {})
        constant = row.get("constant_value")
        if constant is None and node:
            constant = resolved_address(index, function_id, node)

        if tracking == "scalar":
            if constant is not None or bool(row.get("constant")):
                row["prune_reason"] = "constant_scalar"
                pruned.append(row)
                continue
            row["origin_kind"] = "scalar"
            kept.append(row)
            continue

        if tracking == "memory_content":
            address = parse_int(constant)
            if address is not None:
                block = memory_block_at(index, address)
                row["constant"] = True
                row["constant_address"] = f"0x{address:x}"
                if block is not None and bool(block.get("write")):
                    row["origin_kind"] = "memory_content"
                    row["track_memory_content"] = True
                    row["memory_block"] = str(block.get("name", ""))
                    kept.append(row)
                    continue
                if (
                    block is not None
                    and bool(block.get("read"))
                    and not bool(block.get("write"))
                ):
                    row["prune_reason"] = "immutable_memory_object"
                else:
                    row["prune_reason"] = "constant_pointer_region_not_writable"
                pruned.append(row)
                continue
            row["origin_kind"] = "memory_content"
            kept.append(row)
            continue

        # A vulnerable role should normally be scalar or memory content.  Keep
        # unknown tracking kinds instead of turning a schema extension into a
        # silent false negative.
        row["origin_kind"] = tracking
        kept.append(row)
    return kept, pruned


def role_binding_rows(
    spec: dict[str, Any], nodes: dict[str, dict[str, Any]],
    *, index: ProgramIndex, function_id: str,
) -> dict[str, dict[str, Any]]:
    """Preserve every semantic role at the exact High P-code callsite.

    Vulnerable parameters are the backward-analysis startpoints.  Memory
    effect construction additionally needs non-startpoint roles such as the
    destination of ``memcpy``.  Keeping both views avoids reconstructing role
    positions from a callee name in later stages.
    """

    rows: dict[str, dict[str, Any]] = {}
    for role, node in nodes.items():
        argument_index = role_arg_index(spec, role)
        row: dict[str, Any] = {
            "index": argument_index,
            "value_id": node_value_id(node),
            "object_id": node_object_id(node),
            "constant": resolved_constant(index, function_id, node),
        }
        rows[role] = row
    value_expr = str(spec.get("value_expr", "") or "").strip()
    if value_expr and "value" not in rows:
        rows["value"] = {
            "index": None,
            "value_id": "",
            "object_id": "",
            "constant": parse_int(value_expr),
        }
    return rows


def format_exclusion_reason(
    spec: dict[str, Any], nodes: dict[str, dict[str, Any]], expressions: dict[str, str],
    *, index: ProgramIndex, function_id: str,
) -> str:
    if bool(spec.get("require_nonliteral_format")):
        fmt_node = dict(nodes.get("fmt", {}) or {})
        fmt_expr = str(expressions.get("fmt", ""))
        if not fmt_node:
            return "missing_format_parameter"
        if re.fullmatch(r'"(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*', fmt_expr):
            return "literal_format"
        if readonly_initialized_address(index, fmt_node):
            return "readonly_format_object"
    return ""


def binding_from_node(
    index: ProgramIndex,
    function_id: str,
    node: dict[str, Any],
) -> RoleBinding | None:
    definitions = index.definitions_by_function.get(function_id, {})
    formal = formal_access_path(node, definitions)
    if formal is not None:
        return RoleBinding("formal", formal[0], tuple(formal[1]))
    constant = resolved_constant(index, function_id, node)
    if constant is not None:
        return RoleBinding("constant", constant=constant)
    return None


_DERIVED_FORMAL_OBJECT_OPS = {
    "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "INDIRECT",
    "PTRSUB", "PTRADD", "INT_ADD", "INT_SUB", "INT_MULT", "MULTIEQUAL",
    "LOAD",
}


def derived_formal_object_binding(
    index: ProgramIndex,
    function_id: str,
    node: dict[str, Any],
    *,
    limit: int = 96,
) -> RoleBinding | None:
    """Prove that an expression is derived only from one formal object.

    This is intentionally weaker than an exact actual/formal binding: it
    records the formal object that owns a computed address, but does not claim
    that the formal itself is the primitive's final destination.
    """

    definitions = index.definitions_by_function.get(function_id, {})
    memo: dict[str, tuple[bool, frozenset[tuple[int, tuple[int, ...]]]]] = {}
    active: set[str] = set()

    def visit(
        current: dict[str, Any], depth: int
    ) -> tuple[bool, frozenset[tuple[int, tuple[int, ...]]]]:
        if depth > limit:
            return False, frozenset()
        if bool(current.get("is_constant")):
            return True, frozenset()

        exact = formal_access_path(current, definitions, limit=max(1, limit - depth))
        if exact is not None:
            return True, frozenset({exact})

        value_id = node_value_id(current)
        if not value_id or value_id in active:
            return False, frozenset()
        if value_id in memo:
            return memo[value_id]

        op = definitions.get(value_id)
        if not op or str(op.get("mnemonic", "")) not in _DERIVED_FORMAL_OBJECT_OPS:
            memo[value_id] = (False, frozenset())
            return memo[value_id]

        active.add(value_id)
        inputs = [dict(item) for item in list(op.get("inputs", []) or [])]
        # The first LOAD input names the address space, not data provenance.
        if str(op.get("mnemonic", "")) == "LOAD" and len(inputs) >= 2:
            inputs = [inputs[-1]]

        complete = bool(inputs)
        roots: set[tuple[int, tuple[int, ...]]] = set()
        for item in inputs:
            child_complete, child_roots = visit(item, depth + 1)
            if not child_complete:
                complete = False
                break
            roots.update(child_roots)
        active.remove(value_id)
        result = (complete, frozenset(roots))
        memo[value_id] = result
        return result

    complete, roots = visit(node, 0)
    slots = {slot for slot, _path in roots}
    if not complete or len(slots) != 1:
        return None
    slot = next(iter(slots))
    paths = tuple(sorted({path for root_slot, path in roots if root_slot == slot}))
    return RoleBinding(
        "derived_formal_object",
        parameter_slot=slot,
        supporting_access_paths=paths,
    )


def required_summary_roles(spec: dict[str, Any]) -> set[str]:
    return {
        str(role)
        for role in [
            *list(spec.get("vulnerable_parameter_roles", []) or []),
            *list(spec.get("admission_roles", []) or []),
        ]
    }


def seed_summary_from_call(
    *, index: ProgramIndex, function: dict[str, Any], op: dict[str, Any],
    spec: dict[str, Any], seed_name: str,
) -> tuple[EffectSummary | None, str]:
    function_id = str(function.get("function_id", ""))
    actuals = index.call_actuals(function, op)
    nodes = role_nodes(spec, actuals)
    bindings: dict[str, RoleBinding] = {}
    required_roles = required_summary_roles(spec)
    for role in semantic_roles(spec):
        node = dict(nodes.get(str(role), {}) or {})
        if not node and role == "value":
            value = parse_int(spec.get("value_expr"))
            if value is not None:
                bindings[role] = RoleBinding("constant", constant=value)
                continue
        if not node:
            return None, f"summary_missing_role:{role}"
        binding = binding_from_node(index, function_id, node)
        if (
            binding is None
            and role not in required_roles
            and role_tracking(spec, role) == "memory_object"
        ):
            binding = derived_formal_object_binding(index, function_id, node)
        if binding is None:
            if role in required_roles:
                return None, f"summary_role_not_formal_or_constant:{role}"
            return None, f"summary_role_has_no_formal_object_lineage:{role}"
        bindings[str(role)] = binding
    site_id = str(op.get("site_id", ""))
    summary = EffectSummary(
        summary_id=stable_id("sink-summary", function_id, site_id, seed_name),
        function_id=function_id,
        function_name=str(function.get("name", "")),
        effect_site_id=site_id,
        seed_name=seed_name,
        label=str(spec.get("label", "")),
        sink_kind=str(spec.get("kind", "")),
        vulnerable_roles=tuple(str(role) for role in list(spec.get("vulnerable_parameter_roles", []) or [])),
        admission_roles=tuple(str(role) for role in list(spec.get("admission_roles", []) or [])),
        role_tracking_kinds=tuple(
            (role, role_tracking(spec, role)) for role in semantic_roles(spec)
        ),
        role_bindings=tuple(sorted(bindings.items())),
        depth=1,
        proof_path=(site_id,),
    )
    return summary, ""


def compose_summary_at_call(
    *, index: ProgramIndex, caller: dict[str, Any], op: dict[str, Any],
    callee_summary: EffectSummary,
) -> tuple[EffectSummary | None, str]:
    caller_id = str(caller.get("function_id", ""))
    call_ops = [
        dict(candidate)
        for candidate in list(caller.get("pcode_ops", []) or [])
        if str(candidate.get("mnemonic", "")) in {"CALL", "CALLIND"}
    ]
    if len(call_ops) != 1 or str(call_ops[0].get("site_id", "")) != str(
        op.get("site_id", "")
    ):
        return None, "wrapper_body_has_additional_calls"
    if any(
        str(candidate.get("mnemonic", ""))
        in {"CBRANCH", "BRANCHIND", "CALLOTHER"}
        for candidate in list(caller.get("pcode_ops", []) or [])
    ):
        return None, "wrapper_body_has_non_linear_control"
    actuals = index.call_actuals(caller, op)
    bindings: dict[str, RoleBinding] = {}
    required_roles = set(callee_summary.vulnerable_roles) | set(
        callee_summary.admission_roles
    )
    tracking_by_role = dict(callee_summary.role_tracking_kinds)
    for role, callee_binding in callee_summary.role_bindings:
        if callee_binding.kind == "constant":
            bindings[role] = callee_binding
            continue
        slot = callee_binding.parameter_slot
        if slot is None or slot >= len(actuals):
            return None, f"wrapper_missing_actual:{role}"
        actual = dict(actuals[slot])
        origin = binding_from_node(index, caller_id, actual)
        if (
            origin is None
            and role not in required_roles
            and tracking_by_role.get(role) == "memory_object"
        ):
            origin = derived_formal_object_binding(index, caller_id, actual)
        if origin is None:
            return None, f"wrapper_role_not_formal_or_constant:{role}"
        if role in required_roles and origin.kind not in {"formal", "constant"}:
            return None, f"wrapper_role_not_formal_or_constant:{role}"
        if callee_binding.kind == "derived_formal_object":
            if origin.kind != "formal":
                return None, f"wrapper_derived_object_not_formal:{role}"
            supporting_paths = {
                *callee_binding.supporting_access_paths,
                origin.access_path,
            }
            bindings[role] = RoleBinding(
                "derived_formal_object",
                parameter_slot=origin.parameter_slot,
                supporting_access_paths=tuple(sorted(supporting_paths)),
            )
            continue
        if origin.kind == "derived_formal_object":
            bindings[role] = origin
            continue
        if origin.kind == "formal":
            origin = RoleBinding(
                "formal",
                origin.parameter_slot,
                tuple(origin.access_path) + tuple(callee_binding.access_path),
            )
        bindings[role] = origin
    call_site = str(op.get("site_id", ""))
    summary = EffectSummary(
        summary_id=stable_id(
            "sink-summary", caller_id, call_site, callee_summary.summary_id
        ),
        function_id=caller_id,
        function_name=str(caller.get("name", "")),
        effect_site_id=callee_summary.effect_site_id,
        seed_name=callee_summary.seed_name,
        label=callee_summary.label,
        sink_kind=callee_summary.sink_kind,
        vulnerable_roles=callee_summary.vulnerable_roles,
        admission_roles=callee_summary.admission_roles,
        role_tracking_kinds=callee_summary.role_tracking_kinds,
        role_bindings=tuple(sorted(bindings.items())),
        depth=callee_summary.depth + 1,
        proof_path=(call_site,) + callee_summary.proof_path,
        proof_kind=callee_summary.proof_kind,
    )
    return summary, ""


def instantiate_boundary(
    *, index: ProgramIndex, caller: dict[str, Any], op: dict[str, Any],
    target: dict[str, Any], summary: EffectSummary, display: DisplayIndex,
) -> dict[str, Any] | None:
    actuals = index.call_actuals(caller, op)
    site_id = str(op.get("site_id", ""))
    shown = display.get(site_id)
    shown_args = list(shown.get("args", []) or [])
    parameters: list[dict[str, Any]] = []
    role_text: dict[str, str] = {}
    tracking_by_role = dict(summary.role_tracking_kinds)
    vulnerable_roles = set(summary.vulnerable_roles)
    for role, binding in summary.role_bindings:
        if binding.kind == "constant":
            role_text[role] = str(binding.constant)
            parameters.append({
                "role": role,
                "expr": str(binding.constant),
                "binding_kind": "constant",
                "tracking": tracking_by_role.get(role, "scalar"),
                "vulnerable": role in vulnerable_roles,
                "constant": True,
                "constant_value": binding.constant,
            })
            continue
        slot = binding.parameter_slot
        if slot is None or slot >= len(actuals):
            return None
        node = dict(actuals[slot])
        expression = str(shown_args[slot]) if slot < len(shown_args) else node_expression(node)
        if binding.kind == "derived_formal_object":
            derived_expression = f"<derived from {expression}>"
            role_text[role] = derived_expression
            row = {
                "role": role,
                "expr": derived_expression,
                "index": None,
                "base_parameter_index": slot,
                "base_expr": expression,
                "binding_kind": "derived_formal_object",
                "tracking": tracking_by_role.get(role, "memory_object"),
                "vulnerable": role in vulnerable_roles,
                "constant": False,
                "supporting_access_paths": [
                    list(path) for path in binding.supporting_access_paths
                ],
            }
            if node_object_id(node):
                row["base_object_id"] = node_object_id(node)
            if node_value_id(node):
                row["base_value_id"] = node_value_id(node)
            parameters.append(row)
            continue
        if binding.access_path:
            expression += "".join(f"[+0x{offset:x}]" for offset in binding.access_path)
        role_text[role] = expression
        row: dict[str, Any] = {
            "role": role,
            "expr": expression,
            "index": slot,
            "binding_kind": "formal",
            "tracking": tracking_by_role.get(role, "scalar"),
            "vulnerable": role in vulnerable_roles,
            "constant": resolved_address(
                index, str(caller.get("function_id", "")), node
            ) is not None,
        }
        address = resolved_address(index, str(caller.get("function_id", "")), node)
        if address is not None:
            row["constant_value"] = address
        if node_object_id(node):
            row["object_id"] = node_object_id(node)
        if node_value_id(node):
            row["value_id"] = node_value_id(node)
        if binding.access_path:
            row["access_path"] = list(binding.access_path)
        parameters.append(row)
    return {
        "site_id": site_id,
        "instruction_address": str(op.get("instruction_address", "")),
        "function_id": str(caller.get("function_id", "")),
        "function": str(caller.get("name", "")),
        "callee_function_id": str(target.get("function_id", "")),
        "callee": str(target.get("name", "")),
        "plain_line": int(shown.get("line", 0) or 0),
        "expr": str(shown.get("expr", "")) or f"{target.get('name', '')}(...)" ,
        "args": shown_args,
        "roles": role_text,
        "semantic_parameters": parameters,
        "vulnerable_parameters": [
            dict(parameter)
            for parameter in parameters
            if bool(parameter.get("vulnerable"))
        ],
        "summary_id": summary.summary_id,
        "summary_depth": summary.depth,
        "seed_name": summary.seed_name,
        "label": summary.label,
        "sink_kind": summary.sink_kind,
        "vulnerable_parameter_roles": list(summary.vulnerable_roles),
        "admission_roles": list(summary.admission_roles),
        "role_tracking": tracking_by_role,
        "effect_site_id": summary.effect_site_id,
        "proof_path": [site_id, *summary.proof_path],
    }


def canonical_wrapper_boundaries(
    rows: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Keep the outermost proved callsite on each primitive-effect lineage."""

    unique: dict[tuple[str, str], dict[str, Any]] = {}
    for raw in rows:
        row = dict(raw)
        key = (str(row.get("effect_site_id", "")), str(row.get("site_id", "")))
        previous = unique.get(key)
        if previous is None or int(row.get("summary_depth", 0) or 0) > int(
            previous.get("summary_depth", 0) or 0
        ):
            unique[key] = row

    candidates = list(unique.values())
    out: list[dict[str, Any]] = []
    for row in candidates:
        effect_site = str(row.get("effect_site_id", ""))
        site_id = str(row.get("site_id", ""))
        nested = any(
            str(other.get("effect_site_id", "")) == effect_site
            and str(other.get("site_id", "")) != site_id
            and site_id in {
                str(item) for item in list(other.get("proof_path", []) or [])[1:]
            }
            for other in candidates
        )
        if not nested:
            out.append(row)
    return sorted(
        out,
        key=lambda row: (
            str(row.get("effect_site_id", "")),
            str(row.get("site_id", "")),
        ),
    )


def deterministic_wrapper_sink_row(
    *,
    boundary: dict[str, Any],
    index: ProgramIndex,
    binary_sha256: str,
    lineage_boundaries: Iterable[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    function_id = str(boundary.get("function_id", ""))
    semantic = [
        dict(parameter)
        for parameter in list(boundary.get("semantic_parameters", []) or [])
    ]
    kept, pruned = prune_vulnerable_parameters(
        semantic, index=index, function_id=function_id
    )
    reason = "" if kept else "no_trackable_vulnerable_parameter"
    role_bindings = {
        str(parameter.get("role", "")): {
            "kind": str(parameter.get("binding_kind", "")),
            "index": parameter.get("index"),
            "base_parameter_index": parameter.get("base_parameter_index"),
            "value_id": str(parameter.get("value_id", "")),
            "object_id": str(parameter.get("object_id", "")),
            "base_value_id": str(parameter.get("base_value_id", "")),
            "base_object_id": str(parameter.get("base_object_id", "")),
            "constant": parameter.get("constant"),
            "constant_value": parameter.get("constant_value"),
            "tracking": str(parameter.get("tracking", "")),
            "access_path": list(parameter.get("access_path", []) or []),
            "supporting_access_paths": list(
                parameter.get("supporting_access_paths", []) or []
            ),
        }
        for parameter in semantic
    }
    site_id = str(boundary.get("site_id", ""))
    effect_site_id = str(boundary.get("effect_site_id", ""))
    row = {
        "id": stable_id("sink", binary_sha256, site_id, effect_site_id),
        "recognition": RECOGNITION_DETERMINISTIC,
        "recognition_class": "A2_RECURSIVE_BODY_DERIVED_WRAPPER",
        "detection_kind": "high_pcode_recursive_wrapper_call",
        "confirmation_source": "deterministic_recursive_body_summary",
        "label": str(boundary.get("label", "")),
        "sink_kind": str(boundary.get("sink_kind", "")),
        "callee": str(boundary.get("callee", "")),
        "callee_function_id": str(boundary.get("callee_function_id", "")),
        "function": str(boundary.get("function", "")),
        "function_id": function_id,
        "site_id": site_id,
        "effect_site_id": effect_site_id,
        "instruction_address": str(boundary.get("instruction_address", "")),
        "plain_line": int(boundary.get("plain_line", 0) or 0),
        "expr": str(boundary.get("expr", "")),
        "args": list(boundary.get("args", []) or []),
        "roles": dict(boundary.get("roles", {}) or {}),
        "role_argument_indexes": {
            role: binding.get("index") for role, binding in role_bindings.items()
        },
        "role_bindings": role_bindings,
        "semantic_parameters": semantic,
        "vulnerable_parameter_roles": [
            str(role)
            for role in list(boundary.get("vulnerable_parameter_roles", []) or [])
        ],
        "admission_roles": [
            str(role)
            for role in list(boundary.get("admission_roles", []) or [])
        ],
        "vulnerable_parameters": kept,
        "pruned_vulnerable_parameters": pruned,
        "binding_status": "verified_recursive_high_pcode_summary_callsite",
        "decision": "ACCEPT_DETERMINISTIC" if not reason else "WITHDRAW_OUT_OF_SCOPE",
        "evidence_level": "DETERMINISTIC_HIGH_PCODE_BODY_SUMMARY",
        "rule_id": f"SINK_WRAPPER_{boundary.get('seed_name', '')}",
        "taint_status": "not_evaluated",
        "check_status": "unknown",
        "vulnerability_status": "not_evaluated",
        "proof": {
            "proof_kind": "recursive_primitive_effect_summary",
            "primitive_identity": str(boundary.get("seed_name", "")),
            "primitive_effect_site_id": effect_site_id,
            "canonical_boundary_site_id": site_id,
            "proof_path": list(boundary.get("proof_path", []) or []),
        },
        "proof_path": list(boundary.get("proof_path", []) or []),
        "boundary_callsites": dedupe_rows(
            lineage_boundaries, "site_id", "summary_id"
        ),
    }
    if reason:
        row["withdraw_reason"] = reason
        row["withdrawal_is_safety_proof"] = False
    return row, reason


def dedupe_rows(rows: Iterable[dict[str, Any]], *keys: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for row in rows:
        key = tuple(str(row.get(name, "")) for name in keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def analyze(
    *, program_facts: dict[str, Any], registry: dict[str, Any],
    display_calls: Iterable[dict[str, Any]], input_metadata: dict[str, Any],
    max_wrapper_depth: int = 5,
) -> tuple[dict[str, Any], dict[str, Any]]:
    registry = normalize_sink_registry(
        registry, path=str(registry.get("path", ""))
    )
    index = ProgramIndex(program_facts)
    display = DisplayIndex(index, display_calls)
    specs = primitive_specs(registry)
    accepted: list[dict[str, Any]] = []
    withdrawn: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    seed_summaries: list[EffectSummary] = []

    for function, op in index.calls:
        target, target_name = call_target(index, function, op)
        spec = specs.get(target_name)
        if spec is None:
            continue
        # An indirect call is admissible only when the existing strict resolver
        # produced one concrete target.  Merely matching a recovered name is
        # not sufficient.
        if str(op.get("mnemonic", "")) == "CALLIND" and target is None:
            blockers.append({
                "reason": "unresolved_indirect_primitive_target",
                "site_id": str(op.get("site_id", "")),
                "function": str(function.get("name", "")),
                "candidate_name": target_name,
            })
            continue
        actuals = index.call_actuals(function, op)
        nodes = role_nodes(spec, actuals)
        site_id = str(op.get("site_id", ""))
        shown = display.get(site_id)
        expressions = role_expressions(spec, nodes, shown)
        reason = format_exclusion_reason(
            spec, nodes, expressions, index=index,
            function_id=str(function.get("function_id", "")),
        )
        semantic_parameters = parameter_rows(
            spec, nodes, expressions, index=index,
            function_id=str(function.get("function_id", "")),
        )
        parameters, pruned_parameters = prune_vulnerable_parameters(
            semantic_parameters,
            index=index,
            function_id=str(function.get("function_id", "")),
            nodes=nodes,
        )
        if not reason and not parameters:
            reason = "no_trackable_vulnerable_parameter"
        role_bindings = role_binding_rows(
            spec,
            nodes,
            index=index,
            function_id=str(function.get("function_id", "")),
        )
        base = {
            "id": stable_id("sink", program_facts.get("binary_sha256", ""), site_id),
            "recognition": RECOGNITION_DETERMINISTIC,
            "recognition_class": "A1_PRIMITIVE_OR_INTRINSIC",
            "detection_kind": "high_pcode_primitive_call",
            "confirmation_source": "trusted_primitive_high_pcode_call",
            "label": str(spec.get("label", "")),
            "sink_kind": str(spec.get("kind", "")),
            "callee": target_name,
            "callee_function_id": str((target or {}).get("function_id", "") or (op.get("call", {}) or {}).get("target_function_id", "")),
            "function": str(function.get("name", "")),
            "function_id": str(function.get("function_id", "")),
            "site_id": site_id,
            "effect_site_id": site_id,
            "instruction_address": str(op.get("instruction_address", "")),
            "plain_line": int(shown.get("line", 0) or 0),
            "expr": str(shown.get("expr", "")) or f"{target_name}(...)" ,
            "args": list(shown.get("args", []) or []),
            "roles": expressions,
            "role_argument_indexes": {
                role: binding.get("index")
                for role, binding in role_bindings.items()
            },
            "role_bindings": role_bindings,
            "semantic_parameters": semantic_parameters,
            "declared_vulnerable_parameter_roles": list(
                spec.get("vulnerable_parameter_roles", []) or []
            ),
            "vulnerable_parameter_roles": [
                str(parameter.get("role", "")) for parameter in parameters
            ],
            "admission_roles": list(spec.get("admission_roles", []) or []),
            "vulnerable_parameters": parameters,
            "pruned_vulnerable_parameters": pruned_parameters,
            "binding_status": "verified_high_pcode_callsite",
            "decision": "ACCEPT_DETERMINISTIC" if not reason else "WITHDRAW_OUT_OF_SCOPE",
            "evidence_level": "DETERMINISTIC_HIGH_PCODE_SEMANTICS",
            "rule_id": f"SINK_SEED_{target_name}",
            "taint_status": "not_evaluated",
            "check_status": "unknown",
            "vulnerability_status": "not_evaluated",
            "proof": {
                "primitive_identity": target_name,
                "call_site_id": site_id,
                "argument_value_ids": [node_value_id(node) for node in actuals],
                "argument_object_ids": [node_object_id(node) for node in actuals],
            },
            "boundary_callsites": [],
        }
        if reason:
            base["withdraw_reason"] = reason
            base["withdrawal_is_safety_proof"] = False
            withdrawn.append(base)
        else:
            accepted.append(base)
        summary, summary_reason = seed_summary_from_call(
            index=index, function=function, op=op, spec=spec, seed_name=target_name
        )
        if summary is not None:
            seed_summaries.append(summary)
        elif summary_reason:
            blockers.append({
                "reason": summary_reason,
                "site_id": site_id,
                "function": str(function.get("name", "")),
                "primitive": target_name,
            })

    primitive_calls_observed = len(accepted) + len(withdrawn)
    primitive_effect_sites = [dict(row) for row in [*accepted, *withdrawn]]
    summaries = list(seed_summaries)
    known = {summary.key() for summary in summaries}
    for _depth in range(max_wrapper_depth - 1):
        by_function: dict[str, list[EffectSummary]] = defaultdict(list)
        for summary in summaries:
            by_function[summary.function_id].append(summary)
        additions: list[EffectSummary] = []
        for caller, op in index.calls:
            target = index.resolve_call_target(caller, op)
            if target is None:
                continue
            for callee_summary in by_function.get(str(target.get("function_id", "")), []):
                composed, reason = compose_summary_at_call(
                    index=index, caller=caller, op=op, callee_summary=callee_summary
                )
                if composed is None:
                    if reason:
                        blockers.append({
                            "reason": reason,
                            "site_id": str(op.get("site_id", "")),
                            "function": str(caller.get("name", "")),
                            "callee": str(target.get("name", "")),
                            "callee_summary_id": callee_summary.summary_id,
                        })
                    continue
                if composed.key() not in known:
                    known.add(composed.key())
                    additions.append(composed)
        if not additions:
            break
        summaries.extend(additions)

    primitive_by_effect = {
        str(row["effect_site_id"]): row for row in primitive_effect_sites
    }
    boundary_rows: list[dict[str, Any]] = []
    summaries_by_function: dict[str, list[EffectSummary]] = defaultdict(list)
    for summary in summaries:
        summaries_by_function[summary.function_id].append(summary)
    for caller, op in index.calls:
        target = index.resolve_call_target(caller, op)
        if target is None:
            continue
        for summary in summaries_by_function.get(str(target.get("function_id", "")), []):
            boundary = instantiate_boundary(
                index=index, caller=caller, op=op, target=target,
                summary=summary, display=display,
            )
            if boundary is None:
                continue
            boundary_rows.append(boundary)
            effect = primitive_by_effect.get(summary.effect_site_id)
            if effect is not None:
                effect["boundary_callsites"].append(boundary)
                effect["recognition_class"] = "A1_PRIMITIVE_WITH_A2_BODY_DERIVED_BOUNDARIES"

    for row in primitive_effect_sites:
        row["boundary_callsites"] = dedupe_rows(
            row.get("boundary_callsites", []), "site_id", "summary_id"
        )

    boundary_rows = dedupe_rows(boundary_rows, "site_id", "summary_id")
    canonical_boundaries = canonical_wrapper_boundaries(boundary_rows)
    effects_with_boundaries = {
        str(boundary.get("effect_site_id", "")) for boundary in boundary_rows
    }
    accepted = [
        row for row in accepted
        if str(row.get("effect_site_id", "")) not in effects_with_boundaries
    ]
    withdrawn = [
        row for row in withdrawn
        if str(row.get("effect_site_id", "")) not in effects_with_boundaries
    ]
    for boundary in canonical_boundaries:
        effect_site = str(boundary.get("effect_site_id", ""))
        lineage = [
            row
            for row in boundary_rows
            if str(row.get("effect_site_id", "")) == effect_site
            and (
                str(row.get("site_id", "")) == str(boundary.get("site_id", ""))
                or str(row.get("site_id", ""))
                in {
                    str(item)
                    for item in list(boundary.get("proof_path", []) or [])[1:]
                }
            )
        ]
        wrapper_row, reason = deterministic_wrapper_sink_row(
            boundary=boundary,
            index=index,
            binary_sha256=str(program_facts.get("binary_sha256", "")),
            lineage_boundaries=lineage,
        )
        if reason:
            withdrawn.append(wrapper_row)
        else:
            accepted.append(wrapper_row)

    for row in accepted:
        row.setdefault("recognition", RECOGNITION_DETERMINISTIC)
    accepted = dedupe_rows(accepted, "site_id", "effect_site_id")
    withdrawn = dedupe_rows(
        withdrawn, "site_id", "effect_site_id", "withdraw_reason"
    )
    blockers = dedupe_rows(blockers, "site_id", "reason", "callee_summary_id")

    counts = {
        "program_functions": len(index.functions),
        "trusted_primitive_names": len(specs),
        "primitive_calls_observed": primitive_calls_observed,
        "deterministic_sink_calls": len(accepted),
        "sink_startpoints": len(accepted),
        "body_derived_summaries": len(summaries),
        "body_derived_boundary_callsites": len(boundary_rows),
        "canonical_wrapper_callsites": len(canonical_boundaries),
        "body_derived_buffer_state_summaries": 0,
        "body_derived_buffer_state_callsites": 0,
        "withdrawn_out_of_scope": len(withdrawn),
        "analysis_blockers": len(blockers),
        "heuristic_sink_startpoints": 0,
    }
    artifact = {
        "schema_version": SINK_ARTIFACT_SCHEMA_VERSION,
        "scope": "deterministic_sink_backward_dfa_startpoints",
        "input": dict(input_metadata),
        "registry": {
            "schema_version": str(registry.get("schema_version", "")),
            "name": str(registry.get("name", "")),
            "path": str(registry.get("path", "")),
            "primitive_sink_names": sorted(specs),
            "structural_sink_rule_ids": [
                str(rule.get("id", ""))
                for rule in list(registry.get("structural_sink_rules", []) or [])
            ],
        },
        "decision_policy": "deterministic_registry_direct_and_recursive_wrapper_with_role_aware_pruning",
        "supported_sink_classes": [
            "standard_primitive_or_intrinsic",
            "recursive_body_derived_wrapper",
            "nonliteral_standard_format_call",
        ],
        "unsupported_sink_classes": [
            "body_derived_paired_buffer_state_update_heuristic",
            "generic_store_or_field_update",
            "loop_copy_or_loop_write",
            "parser_out_of_bounds_read",
            "unpaired_or_ambiguous_buffer_state_mutation",
            "indirect_control_flow_vulnerability",
            "lifetime_vulnerability",
        ],
        "next_stage_ready": True,
        "counts": counts,
        "deterministic_sink_calls": accepted,
        "confirmed_sink_calls": accepted,
        "heuristic_sink_calls": [],
        "sink_startpoints": accepted,
        "primitive_effect_sites": primitive_effect_sites,
        "body_derived_summaries": [summary.as_json() for summary in summaries],
        "body_derived_boundary_callsites": boundary_rows,
        "withdrawn_out_of_scope": withdrawn,
        "dropped_proven": [],
        "dropped_candidates": [],
        "analysis_blockers": blockers,
    }
    compatibility = {
        "schema_version": "ct-mini-sink-unconfirmed-v3",
        "scope": "empty_compatibility_artifact_deterministic_front_pipeline",
        "counts": {"candidates": 0},
        "candidates": [],
        "note": "Body-derived heuristic Sink patterns are outside this deterministic engine.",
    }
    return artifact, compatibility
