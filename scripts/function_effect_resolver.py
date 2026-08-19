#!/usr/bin/env python3
"""Bounded, demand-driven function-effect resolution over High P-code.

The resolver deliberately derives effects from function bodies rather than
private function names. It supplies the backward analysis with call-result,
exact-object STORE, and resolved-call fixed-output relations.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Callable


Identity = Callable[[dict[str, Any] | None], str]
PublicValue = Callable[[dict[str, Any] | None], str]


_TRANSPARENT_VALUE_OPS = {
    "COPY",
    "CAST",
    "INDIRECT",
    "INT_ZEXT",
    "INT_SEXT",
    "SUBPIECE",
}
_CONSTANT_OFFSET_OPS = {"PTRADD", "PTRSUB", "INT_ADD", "INT_SUB"}


def _nonconstant_inputs(op: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for raw in list(op.get("inputs", []) or []):
        node = dict(raw or {})
        if bool(node.get("is_constant")) or str(node.get("space", "")) == "const":
            continue
        rows.append(node)
    return rows


def _parameter_slot(node: dict[str, Any]) -> int | None:
    slot = node.get("parameter_slot")
    if isinstance(slot, int):
        return slot
    object_id = str(node.get("object_id", ""))
    match = re.search(r"param:[^:]+:(\d+)$", object_id)
    return int(match.group(1)) if match else None


def _signed_constant(node: dict[str, Any]) -> int | None:
    if not bool(node.get("is_constant")) and str(node.get("space", "")) != "const":
        return None
    raw = node.get("offset")
    try:
        value = int(str(raw), 0)
    except (TypeError, ValueError):
        try:
            value = int(str(raw), 16)
        except (TypeError, ValueError):
            return None
    width = max(1, int(node.get("size", 4) or 4)) * 8
    mask = (1 << width) - 1
    value &= mask
    sign = 1 << (width - 1)
    return value - (1 << width) if value & sign else value


def _stable_object_id(object_id: str) -> bool:
    """Whether an actual denotes caller-owned memory, not backend storage."""

    return bool(object_id) and not object_id.startswith(
        ("reg:", "unique:", "param:", "const:", "var:")
    )


def _constant_access_path_offset(path: list[Any]) -> int | None:
    """Return the byte offset relative to the current pointee object.

    Runtime object bindings retain the full root path.  When a dereference is
    present, the binding's ``object_id`` already denotes that pointee, so only
    offsets after the final dereference are relative to the current object.
    """

    items = [str(item) for item in path]
    start = max((index + 1 for index, item in enumerate(items) if item == "deref"), default=0)
    total = 0
    for item in items[start:]:
        if item == "deref":
            total = 0
            continue
        if item.startswith("byte_offset:") or item.startswith("field_offset:"):
            try:
                total += int(item.split(":", 1)[1], 0)
            except ValueError:
                return None
            continue
        return None
    return total


@dataclass(frozen=True)
class ResolutionLimits:
    max_call_depth: int = 3
    max_ops_per_summary: int = 256
    max_alternatives: int = 8


class FunctionEffectResolver:
    """Resolve exact function effects without relying on function names."""

    def __init__(
        self,
        *,
        functions: dict[str, dict[str, Any]],
        calls_by_site: dict[str, list[dict[str, Any]]],
        calls_to: dict[str, list[dict[str, Any]]],
        resolved_object_by_atom: dict[str, str],
        identity: Identity,
        public_value: PublicValue,
        same_object: Callable[[str, str], bool],
        limits: ResolutionLimits | None = None,
    ) -> None:
        self.functions = functions
        self.calls_by_site = calls_by_site
        self.calls_to = calls_to
        self.resolved_object_by_atom = resolved_object_by_atom
        self.identity = identity
        self.public_value = public_value
        self.same_object = same_object
        self.limits = limits or ResolutionLimits()

        self.ops_by_site: dict[str, tuple[str, dict[str, Any]]] = {}
        self.defs_by_atom: dict[str, tuple[str, dict[str, Any]]] = {}
        self.returns_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.stores_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._return_cache: dict[tuple[str, int], tuple[list[dict[str, Any]], str]] = {}
        self._fixed_output_effect_cache: dict[
            str, tuple[list[dict[str, Any]], list[dict[str, Any]]]
        ] = {}
        self.stats: dict[str, int] = defaultdict(int)

        for function_id, function in functions.items():
            for op in list(function.get("pcode_ops", []) or []):
                site_id = str(op.get("site_id", ""))
                if site_id:
                    self.ops_by_site[site_id] = (function_id, op)
                output = dict(op.get("output", {}) or {})
                output_atom = identity(output)
                if output_atom:
                    self.defs_by_atom[output_atom] = (function_id, op)
                mnemonic = str(op.get("mnemonic", ""))
                if mnemonic == "RETURN":
                    self.returns_by_function[function_id].append(op)
                elif mnemonic == "STORE":
                    self._index_store(function_id, op)

    def _definition_for_node(
        self, function_id: str, node: dict[str, Any]
    ) -> dict[str, Any] | None:
        atom_id = self.identity(node)
        entry = self.defs_by_atom.get(atom_id)
        if entry and entry[0] == function_id:
            return entry[1]
        site_id = str(node.get("def_site_id", ""))
        site_entry = self.ops_by_site.get(site_id)
        if site_entry and site_entry[0] == function_id:
            return site_entry[1]
        return None

    def _formal_address_lineage(
        self,
        function_id: str,
        node: dict[str, Any],
        *,
        depth: int = 0,
        seen: set[str] | None = None,
    ) -> dict[str, Any] | None:
        """Resolve an address to ``formal pointer + constant byte offset``.

        A result with ``dynamic_offset`` still identifies the formal base, but
        is deliberately not a fixed-output effect.  Keeping that distinction
        lets callers emit a precise blocker instead of silently losing the
        STORE.
        """

        if depth > 24:
            return None
        slot = _parameter_slot(node)
        if slot is not None:
            return {
                "parameter_slot": slot,
                "offset": 0,
                "dynamic_offset": False,
                "base_atom_id": self.identity(node),
                "proof_site_ids": [],
            }

        atom_id = self.identity(node)
        seen = set(seen or set())
        if atom_id and atom_id in seen:
            return None
        if atom_id:
            seen.add(atom_id)
        op = self._definition_for_node(function_id, node)
        if not op:
            return None
        mnemonic = str(op.get("mnemonic", ""))
        inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
        site_id = str(op.get("site_id", ""))

        if mnemonic in _TRANSPARENT_VALUE_OPS:
            dynamic = [item for item in inputs if _signed_constant(item) is None]
            lineages = [
                self._formal_address_lineage(
                    function_id,
                    item,
                    depth=depth + 1,
                    seen=seen,
                )
                for item in dynamic
            ]
            lineages = [row for row in lineages if row]
            if len(lineages) != 1:
                return None
            result = dict(lineages[0])
            result["proof_site_ids"] = list(result["proof_site_ids"]) + [site_id]
            return result

        if mnemonic == "MULTIEQUAL":
            lineages = [
                self._formal_address_lineage(
                    function_id,
                    item,
                    depth=depth + 1,
                    seen=seen,
                )
                for item in inputs
                if _signed_constant(item) is None
            ]
            lineages = [row for row in lineages if row]
            identities = {
                (
                    int(row["parameter_slot"]),
                    int(row["offset"]),
                    bool(row["dynamic_offset"]),
                )
                for row in lineages
            }
            if not lineages or len(identities) != 1:
                return None
            result = dict(lineages[0])
            result["proof_site_ids"] = list(result["proof_site_ids"]) + [site_id]
            return result

        if mnemonic not in _CONSTANT_OFFSET_OPS or not inputs:
            return None

        # PTRADD/PTRSUB have a designated pointer base. INT_ADD may place the
        # base on either side, so select the one uniquely rooted in a formal.
        candidate_indexes = (
            [0]
            if mnemonic in {"PTRADD", "PTRSUB", "INT_SUB"}
            else list(range(len(inputs)))
        )
        base_candidates: list[tuple[int, dict[str, Any]]] = []
        for index in candidate_indexes:
            if index >= len(inputs) or _signed_constant(inputs[index]) is not None:
                continue
            lineage = self._formal_address_lineage(
                function_id,
                inputs[index],
                depth=depth + 1,
                seen=seen,
            )
            if lineage:
                base_candidates.append((index, lineage))
        if len(base_candidates) != 1:
            return None
        base_index, result = base_candidates[0]
        result = dict(result)
        other_inputs = [item for index, item in enumerate(inputs) if index != base_index]
        constants = [_signed_constant(item) for item in other_inputs]
        if any(value is None for value in constants):
            result["dynamic_offset"] = True
            result["proof_site_ids"] = list(result["proof_site_ids"]) + [site_id]
            return result

        constant_values = [int(value) for value in constants if value is not None]
        delta = 0
        if mnemonic == "PTRADD":
            if len(constant_values) == 1:
                delta = constant_values[0]
            elif len(constant_values) >= 2:
                delta = constant_values[0] * constant_values[1]
        elif mnemonic == "INT_SUB":
            delta = -sum(constant_values)
        else:
            delta = sum(constant_values)
        result["offset"] = int(result["offset"]) + delta
        result["proof_site_ids"] = list(result["proof_site_ids"]) + [site_id]
        return result

    def _stored_value_lineage(
        self, function_id: str, node: dict[str, Any]
    ) -> dict[str, Any] | None:
        """Bind a STORE value to a formal or one exact callee-local SSA def."""

        if bool(node.get("is_constant")) or str(node.get("space", "")) == "const":
            return None
        atom_id = self.identity(node)
        value_id = self.public_value(node)
        object_id = self._object_for_node(node)
        slot = _parameter_slot(node)
        if slot is not None:
            return {
                "lineage_kind": "FORMAL_VALUE",
                "parameter_slot": slot,
                "formal_parameter_slots": [slot],
                "atom_id": atom_id,
                "value_id": value_id,
                "object_id": object_id,
                "definition_site_id": "",
            }
        definition = self._definition_for_node(function_id, node)
        if not atom_id or not definition:
            return None

        formal_slots: set[int] = set()
        definition_sites: set[str] = set()
        worklist = [node]
        seen: set[str] = set()
        while worklist and len(seen) < self.limits.max_ops_per_summary:
            current = dict(worklist.pop() or {})
            current_slot = _parameter_slot(current)
            if current_slot is not None:
                formal_slots.add(current_slot)
                continue
            current_atom = self.identity(current)
            if not current_atom or current_atom in seen:
                continue
            seen.add(current_atom)
            current_def = self._definition_for_node(function_id, current)
            if not current_def:
                continue
            definition_sites.add(str(current_def.get("site_id", "")))
            worklist.extend(_nonconstant_inputs(current_def))

        return {
            "lineage_kind": "LOCAL_SSA_VALUE",
            "parameter_slot": None,
            "formal_parameter_slots": sorted(formal_slots),
            "atom_id": atom_id,
            "value_id": value_id,
            "object_id": object_id,
            "definition_site_id": str(definition.get("site_id", "")),
            "lineage_atom_ids": sorted(seen),
            "lineage_definition_site_ids": sorted(definition_sites - {""}),
        }

    def extract_fixed_output_effects(
        self, function_id: str
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Summarize fixed-offset STOREs rooted in callee formal pointers.

        The summary is body-derived and name-independent.  Each STORE is an
        independent effect; recovered types and field names are evidence only
        and are not required for recognition.
        """

        cached = self._fixed_output_effect_cache.get(function_id)
        if cached is not None:
            return ([dict(row) for row in cached[0]], [dict(row) for row in cached[1]])
        function = self.functions.get(function_id)
        if not function:
            blocker = {
                "reason": "call_output_callee_body_unavailable",
                "function_id": function_id,
                "site_id": "",
            }
            self._fixed_output_effect_cache[function_id] = ([], [blocker])
            return [], [dict(blocker)]
        ops = list(function.get("pcode_ops", []) or [])
        if len(ops) > self.limits.max_ops_per_summary:
            blocker = {
                "reason": "call_output_summary_operation_budget_exhausted",
                "function_id": function_id,
                "site_id": "",
            }
            self._fixed_output_effect_cache[function_id] = ([], [blocker])
            return [], [dict(blocker)]

        effects: list[dict[str, Any]] = []
        blockers: list[dict[str, Any]] = []
        for op in ops:
            if str(op.get("mnemonic", "")) != "STORE":
                continue
            inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
            if len(inputs) < 2:
                continue
            address, stored = inputs[-2], inputs[-1]
            address_lineage = self._formal_address_lineage(function_id, address)
            if not address_lineage:
                continue
            site_id = str(op.get("site_id", ""))
            common = {
                "function_id": function_id,
                "site_id": site_id,
                "output_parameter_slot": int(address_lineage["parameter_slot"]),
            }
            if bool(address_lineage.get("dynamic_offset")):
                blockers.append(
                    {
                        **common,
                        "reason": "call_output_dynamic_offset_unsupported",
                        "address_atom_id": self.identity(address),
                    }
                )
                continue
            stored_lineage = self._stored_value_lineage(function_id, stored)
            if not stored_lineage:
                blockers.append(
                    {
                        **common,
                        "reason": "call_output_stored_value_unresolved",
                        "stored_atom_id": self.identity(stored),
                    }
                )
                continue
            offset = int(address_lineage.get("offset", 0) or 0)
            extent = max(1, int(stored.get("size", 0) or 1))
            effects.append(
                {
                    "effect_id": f"fixed-output:{function_id}:{site_id}",
                    "effect_kind": "FIXED_OUTPUT_STORE",
                    "function_id": function_id,
                    "store_site_id": site_id,
                    "output": {
                        "parameter_slot": int(address_lineage["parameter_slot"]),
                        "base_atom_id": str(address_lineage.get("base_atom_id", "")),
                        "offset": offset,
                        "extent": extent,
                    },
                    "stored_value": stored_lineage,
                    "proof": {
                        "kind": "HIGH_PCODE_FORMAL_FIXED_OFFSET_STORE",
                        "address_atom_id": self.identity(address),
                        "address_definition_site_ids": list(
                            address_lineage.get("proof_site_ids", []) or []
                        ),
                        "store_site_id": site_id,
                    },
                }
            )
        # Ghidra emits High P-code in the function's stable operation order.
        # Preserve that order so several output fields retain their body-level
        # evidence sequence instead of depending on lexical SiteId ordering.
        blockers.sort(key=lambda row: (str(row.get("site_id", "")), str(row["reason"])))
        self._fixed_output_effect_cache[function_id] = (effects, blockers)
        if effects:
            self.stats["fixed_output_summaries"] += len(effects)
        return [dict(row) for row in effects], [dict(row) for row in blockers]

    def _object_for_node(self, node: dict[str, Any]) -> str:
        atom_id = self.identity(node)
        return str(self.resolved_object_by_atom.get(atom_id, node.get("object_id", "")))

    def _index_store(self, function_id: str, op: dict[str, Any]) -> None:
        inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
        if len(inputs) < 2:
            return
        address = inputs[-2]
        value = inputs[-1]
        object_id = self._object_for_node(address)
        if not object_id or object_id.startswith(("reg:", "unique:", "param:")):
            return
        row = {
            "function_id": function_id,
            "site_id": str(op.get("site_id", "")),
            "object_id": object_id,
            "address_atom_id": self.identity(address),
            "stored_atom_id": self.identity(value),
            "stored_value_id": self.public_value(value),
            "stored_object_id": self._object_for_node(value),
            "op": op,
        }
        self.stores_by_object[object_id].append(row)

    def _resolved_targets(
        self,
        caller_function_id: str,
        op: dict[str, Any],
        *,
        allowed_edge_ids: set[str] | None,
        admit_exact_nested_call: bool = False,
    ) -> list[tuple[str, dict[str, Any] | None]]:
        site_id = str(op.get("site_id", ""))
        rows = list(self.calls_by_site.get(site_id, []))
        admitted_rows = rows
        if allowed_edge_ids is not None:
            admitted_rows = [
                row
                for row in rows
                if str(row.get("edge_id", "")) in allowed_edge_ids
            ]
        targets: dict[str, dict[str, Any] | None] = {}
        for row in admitted_rows:
            target = str(row.get("dst_node_id", ""))
            if target and not target.startswith("unknown-call-target:"):
                targets[target] = row
        direct = str(dict(op.get("call", {}) or {}).get("target_function_id", ""))
        if direct and allowed_edge_ids is None:
            targets.setdefault(direct, None)
        if not targets and admit_exact_nested_call and direct:
            # Reverse BFS follows callers and therefore does not pre-enumerate
            # every callee invoked by a retained function. RDA may nevertheless
            # enter the one callee whose return value defines the value currently
            # being traced. Preserve that exact callsite edge so actual/formal
            # binding in the nested body uses the correct caller context.
            nested_rows = [
                row
                for row in rows
                if str(row.get("src_node_id", "")) == caller_function_id
                and str(row.get("dst_node_id", "")) == direct
                and str(row.get("edge_id", ""))
            ]
            nested_by_edge = {
                str(row.get("edge_id", "")): row for row in nested_rows
            }
            if len(nested_by_edge) == 1:
                edge = next(iter(nested_by_edge.values()))
                targets[direct] = edge
        return sorted(targets.items())

    @staticmethod
    def _call_edge_semantics(
        graph_edge: dict[str, Any] | None,
    ) -> dict[str, str]:
        edge = dict(graph_edge or {})
        resolution = str(edge.get("resolution", ""))
        precision = str(edge.get("analysis_precision", ""))
        if not precision:
            precision = "MAY" if resolution == "FINITE_TABLE_MAY_TARGET" else "EXACT"
        recognition = str(edge.get("recognition", ""))
        if not recognition:
            recognition = "heuristic" if precision == "MAY" else "deterministic"
        return {
            "analysis_precision": precision,
            "recognition": recognition,
            "resolution": resolution,
            "resolution_kind": str(edge.get("resolution_kind", "")),
        }

    def _actual_binding(
        self,
        op: dict[str, Any],
        graph_edge: dict[str, Any] | None,
        slot: int,
    ) -> dict[str, Any] | None:
        actuals = [dict(item or {}) for item in list(op.get("inputs", []) or [])[1:]]
        if slot < 0 or slot >= len(actuals):
            return None
        node = actuals[slot]
        edge = dict(graph_edge or {})
        explicit: dict[str, Any] = {}
        bindings = list(edge.get("argument_bindings", []) or [])
        for index, raw in enumerate(bindings):
            candidate = dict(raw or {})
            candidate_slot = candidate.get("slot", index)
            if candidate_slot == slot:
                explicit = candidate
                break

        def indexed(key: str) -> str:
            values = list(edge.get(key, []) or [])
            return str(values[slot]) if slot < len(values) else ""

        explicit_path = list(explicit.get("access_path", []) or [])
        edge_paths = list(edge.get("argument_access_paths", []) or [])
        access_path = explicit_path or (
            list(edge_paths[slot] or []) if slot < len(edge_paths) else []
        )

        atom_id = (
            str(explicit.get("atom_id", ""))
            or self.identity(node)
            or indexed("argument_atom_ids")
        )
        value_id = (
            str(explicit.get("value_id", ""))
            or self.public_value(node)
            or indexed("argument_value_ids")
        )
        object_candidates = [
            str(self.resolved_object_by_atom.get(atom_id, "")),
            str(explicit.get("object_id", "")),
            indexed("resolved_argument_object_ids"),
            self._object_for_node(node),
            indexed("argument_object_ids"),
        ]
        stable_object = next(
            (candidate for candidate in object_candidates if _stable_object_id(candidate)),
            "",
        )
        return {
            "slot": slot,
            "atom_id": atom_id,
            "value_id": value_id,
            "object_id": stable_object or next(
                (candidate for candidate in object_candidates if candidate), ""
            ),
            "stable_object_id": stable_object,
            "access_path": access_path,
            "byte_offset": _constant_access_path_offset(access_path),
            "node": node,
        }

    def _bind_one_output_call(
        self,
        caller_function_id: str,
        op: dict[str, Any],
        *,
        allowed_edge_ids: set[str] | None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        mnemonic = str(op.get("mnemonic", ""))
        if mnemonic not in {"CALL", "CALLIND"}:
            return [], []
        call_site_id = str(op.get("site_id", ""))
        targets = self._resolved_targets(
            caller_function_id,
            op,
            allowed_edge_ids=allowed_edge_ids,
        )
        if len(targets) > 1:
            return [], [
                {
                    "reason": "call_output_target_ambiguous",
                    "function_id": caller_function_id,
                    "site_id": call_site_id,
                    "target_function_ids": [target for target, _ in targets],
                }
            ]
        if not targets:
            return [], [
                {
                    "reason": "call_output_target_unresolved",
                    "function_id": caller_function_id,
                    "site_id": call_site_id,
                }
            ]

        target_function_id, graph_edge = targets[0]
        summaries, summary_blockers = self.extract_fixed_output_effects(
            target_function_id
        )
        blockers = [
            {
                **row,
                "caller_function_id": caller_function_id,
                "call_site_id": call_site_id,
                "callee_function_id": target_function_id,
            }
            for row in summary_blockers
        ]
        edge_id = str((graph_edge or {}).get("edge_id", ""))
        semantics = self._call_edge_semantics(graph_edge)
        bound: list[dict[str, Any]] = []
        for summary in summaries:
            output = dict(summary.get("output", {}) or {})
            output_slot = output.get("parameter_slot")
            if not isinstance(output_slot, int):
                continue
            destination_actual = self._actual_binding(
                op, graph_edge, output_slot
            )
            if not destination_actual or not str(
                destination_actual.get("stable_object_id", "")
            ):
                blockers.append(
                    {
                        "reason": "call_output_actual_object_unresolved",
                        "function_id": caller_function_id,
                        "site_id": call_site_id,
                        "callee_function_id": target_function_id,
                        "callee_store_site_id": str(summary.get("store_site_id", "")),
                        "output_parameter_slot": output_slot,
                    }
                )
                continue
            actual_offset = destination_actual.get("byte_offset")
            if actual_offset is None:
                blockers.append(
                    {
                        "reason": "call_output_actual_access_path_unresolved",
                        "function_id": caller_function_id,
                        "site_id": call_site_id,
                        "callee_function_id": target_function_id,
                        "callee_store_site_id": str(summary.get("store_site_id", "")),
                        "output_parameter_slot": output_slot,
                        "actual_access_path": list(
                            destination_actual.get("access_path", []) or []
                        ),
                    }
                )
                continue

            stored = dict(summary.get("stored_value", {}) or {})
            lineage_kind = str(stored.get("lineage_kind", ""))
            formal_bindings: list[dict[str, Any]] = []
            binding_failed = False
            for slot in list(stored.get("formal_parameter_slots", []) or []):
                actual = self._actual_binding(op, graph_edge, int(slot))
                if not actual or not (
                    str(actual.get("atom_id", ""))
                    or str(actual.get("value_id", ""))
                    or str(actual.get("object_id", ""))
                ):
                    binding_failed = True
                    break
                formal_bindings.append(
                    {
                        "parameter_slot": int(slot),
                        "atom_id": str(actual.get("atom_id", "")),
                        "value_id": str(actual.get("value_id", "")),
                        "object_id": str(actual.get("object_id", "")),
                    }
                )
            if binding_failed:
                blockers.append(
                    {
                        "reason": "call_output_stored_value_unresolved",
                        "function_id": caller_function_id,
                        "site_id": call_site_id,
                        "callee_function_id": target_function_id,
                        "callee_store_site_id": str(summary.get("store_site_id", "")),
                    }
                )
                continue

            if lineage_kind == "FORMAL_VALUE":
                if len(formal_bindings) != 1:
                    blockers.append(
                        {
                            "reason": "call_output_stored_value_unresolved",
                            "function_id": caller_function_id,
                            "site_id": call_site_id,
                            "callee_function_id": target_function_id,
                            "callee_store_site_id": str(summary.get("store_site_id", "")),
                        }
                    )
                    continue
                stored_binding = {
                    **formal_bindings[0],
                    "lineage_kind": "CALLER_ACTUAL_VALUE",
                    "callee_atom_id": str(stored.get("atom_id", "")),
                }
            elif lineage_kind == "LOCAL_SSA_VALUE":
                stored_binding = {
                    "lineage_kind": "CALLEE_LOCAL_SSA_VALUE",
                    "atom_id": str(stored.get("atom_id", "")),
                    "value_id": str(stored.get("value_id", "")),
                    "object_id": str(stored.get("object_id", "")),
                    "callee_atom_id": str(stored.get("atom_id", "")),
                    "definition_site_id": str(stored.get("definition_site_id", "")),
                }
            else:
                blockers.append(
                    {
                        "reason": "call_output_stored_value_unresolved",
                        "function_id": caller_function_id,
                        "site_id": call_site_id,
                        "callee_function_id": target_function_id,
                        "callee_store_site_id": str(summary.get("store_site_id", "")),
                    }
                )
                continue

            base_object_id = str(destination_actual["stable_object_id"])
            offset = int(actual_offset) + int(output.get("offset", 0) or 0)
            extent = max(1, int(output.get("extent", 1) or 1))
            destination = {
                "object_id": base_object_id,
                "base_object_id": base_object_id,
                "offset": offset,
                "extent": extent,
                "region_id": f"region:{base_object_id}:{offset}:{extent}",
                "actual_atom_id": str(destination_actual.get("atom_id", "")),
                "actual_value_id": str(destination_actual.get("value_id", "")),
                "formal_parameter_slot": output_slot,
            }
            if destination_actual.get("access_path"):
                destination["actual_access_path"] = list(
                    destination_actual.get("access_path", []) or []
                )
            effect_id = (
                f"bound-fixed-output:{call_site_id}:"
                f"{summary.get('store_site_id', '')}"
            )
            bound.append(
                {
                    "effect_id": effect_id,
                    "effect_kind": "RESOLVED_CALL_FIXED_OUTPUT_STORE",
                    "caller_function_id": caller_function_id,
                    "callee_function_id": target_function_id,
                    "call_site_id": call_site_id,
                    "call_edge_id": edge_id,
                    "callee_store_site_id": str(summary.get("store_site_id", "")),
                    "destination": destination,
                    "stored_value": stored_binding,
                    "formal_value_bindings": formal_bindings,
                    **semantics,
                    "proof": {
                        "kind": "HIGH_PCODE_RESOLVED_CALL_FIXED_OUTPUT_STORE",
                        "callee_effect_id": str(summary.get("effect_id", "")),
                        "callee_proof": dict(summary.get("proof", {}) or {}),
                    },
                    "edge": {
                        "kind": "CALL_OUTPUT_EFFECT",
                        "summary_kind": "FIXED_OUTPUT_STORE",
                        "graph_edge_id": edge_id,
                        "graph_edge_kind": mnemonic,
                        "call_site_id": call_site_id,
                        "store_site_id": str(summary.get("store_site_id", "")),
                        "from_function_id": caller_function_id,
                        "to_function_id": target_function_id,
                        "destination_object_id": base_object_id,
                        "destination_region_id": destination["region_id"],
                        **semantics,
                    },
                }
            )
        if bound:
            self.stats["bound_fixed_output_effects"] += len(bound)
        return bound, blockers

    def bind_output_effects_to_calls(
        self,
        caller_function_id: str = "",
        op: dict[str, Any] | None = None,
        *,
        allowed_edge_ids: set[str] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Instantiate fixed-output summaries at resolved callsites.

        Passing ``op`` binds one call.  Omitting it enumerates calls in the
        selected caller, or all callers when ``caller_function_id`` is empty.
        The returned effects are directly consumable by Source Association;
        :meth:`call_output_predecessors` exposes the same facts to RDA.
        """

        if op is not None:
            return self._bind_one_output_call(
                caller_function_id,
                op,
                allowed_edge_ids=allowed_edge_ids,
            )
        effects: list[dict[str, Any]] = []
        blockers: list[dict[str, Any]] = []
        functions = (
            [(caller_function_id, self.functions.get(caller_function_id, {}))]
            if caller_function_id
            else sorted(self.functions.items())
        )
        for function_id, function in functions:
            for candidate in list(function.get("pcode_ops", []) or []):
                if str(candidate.get("mnemonic", "")) not in {"CALL", "CALLIND"}:
                    continue
                rows, reasons = self._bind_one_output_call(
                    function_id,
                    candidate,
                    allowed_edge_ids=allowed_edge_ids,
                )
                effects.extend(rows)
                # A call to a body with no output effect is not itself a
                # blocker. Preserve only calls where extraction or binding
                # found a relevant output STORE, or a target was ambiguous.
                if rows or any(
                    str(reason.get("reason", ""))
                    in {
                        "call_output_actual_object_unresolved",
                        "call_output_actual_access_path_unresolved",
                        "call_output_dynamic_offset_unsupported",
                        "call_output_stored_value_unresolved",
                        "call_output_target_ambiguous",
                    }
                    for reason in reasons
                ):
                    blockers.extend(reasons)
        effects.sort(key=lambda row: str(row.get("effect_id", "")))
        blockers.sort(
            key=lambda row: (
                str(row.get("site_id", row.get("call_site_id", ""))),
                str(row.get("reason", "")),
            )
        )
        return effects, blockers

    def call_output_predecessors(
        self,
        object_id: str,
        *,
        offset: int | None = None,
        allowed_edge_ids: set[str] | None = None,
        allowed_node_ids: set[str] | None = None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Expose bound CALL output definitions for backward RDA."""

        effects, blockers = self.bind_output_effects_to_calls(
            allowed_edge_ids=allowed_edge_ids
        )
        # Reverse Callgraph BFS contains incoming caller relations.  A body
        # summary that defines the object currently being traced may instead
        # be an exact outgoing call from an already admitted Function.  Admit
        # that nested call just as return-summary recovery does; no unrelated
        # Function is searched.
        if allowed_edge_ids is not None and allowed_node_ids:
            for function_id in sorted(allowed_node_ids):
                nested_effects, nested_blockers = self.bind_output_effects_to_calls(
                    function_id, allowed_edge_ids=None
                )
                effects.extend(nested_effects)
                blockers.extend(nested_blockers)
        effects = list(
            {
                str(effect.get("effect_id", "")): effect
                for effect in effects
                if str(effect.get("effect_id", ""))
            }.values()
        )
        blockers = list(
            {
                (
                    str(blocker.get("reason", "")),
                    str(blocker.get("site_id", blocker.get("call_site_id", ""))),
                    str(blocker.get("callee_store_site_id", "")),
                ): blocker
                for blocker in blockers
            }.values()
        )
        predecessors: list[dict[str, Any]] = []
        for effect in effects:
            if allowed_node_ids is not None and str(
                effect.get("caller_function_id", "")
            ) not in allowed_node_ids:
                continue
            destination = dict(effect.get("destination", {}) or {})
            if not self.same_object(str(destination.get("object_id", "")), object_id):
                continue
            if offset is not None and int(destination.get("offset", 0) or 0) != offset:
                continue
            stored = dict(effect.get("stored_value", {}) or {})
            if not (
                str(stored.get("atom_id", ""))
                or str(stored.get("value_id", ""))
                or str(stored.get("object_id", ""))
            ):
                continue
            predecessors.append(
                {
                    "atom_id": str(stored.get("atom_id", "")),
                    "value_id": str(stored.get("value_id", "")),
                    "object_id": str(stored.get("object_id", "")),
                    "call_context_edge_id": str(effect.get("call_edge_id", "")),
                    "edge": dict(effect.get("edge", {}) or {}),
                    "effect": effect,
                }
            )
            if len(predecessors) >= self.limits.max_alternatives:
                break
        if predecessors:
            self.stats["call_output_predecessors"] += len(predecessors)
        return predecessors, blockers

    def return_predecessors(
        self,
        caller_function_id: str,
        op: dict[str, Any],
        *,
        call_depth: int,
        allowed_edge_ids: set[str] | None,
    ) -> tuple[list[dict[str, Any]], str]:
        """Enter a uniquely resolved callee and expose its RETURN definitions."""

        mnemonic = str(op.get("mnemonic", ""))
        if mnemonic not in {"CALL", "CALLIND"}:
            return [], "unresolved_call_return_summary"
        if call_depth >= self.limits.max_call_depth:
            self.stats["depth_exhausted"] += 1
            return [], "function_resolution_depth_exhausted"

        targets = self._resolved_targets(
            caller_function_id,
            op,
            allowed_edge_ids=allowed_edge_ids,
            admit_exact_nested_call=call_depth > 0,
        )
        if not targets:
            return [], (
                "unresolved_indirect_call_target"
                if mnemonic == "CALLIND"
                else "unresolved_call_return_summary"
            )
        if len(targets) != 1:
            self.stats["ambiguous_targets"] += 1
            return [], "ambiguous_call_target"

        target_function_id, graph_edge = targets[0]
        edge_semantics = self._call_edge_semantics(graph_edge)
        function = self.functions.get(target_function_id)
        if not function:
            return [], "callee_body_unavailable"
        ops = list(function.get("pcode_ops", []) or [])
        if len(ops) > self.limits.max_ops_per_summary:
            self.stats["oversized_functions"] += 1
            return [], "function_summary_operation_budget_exhausted"

        returns = self.returns_by_function.get(target_function_id, [])
        if not returns:
            return [], "unresolved_call_return_summary"
        out: list[dict[str, Any]] = []
        for return_op in returns:
            for node in _nonconstant_inputs(return_op):
                atom_id = self.identity(node)
                object_id = self._object_for_node(node)
                if not atom_id and not object_id:
                    continue
                out.append(
                    {
                        "atom_id": atom_id,
                        "value_id": self.public_value(node),
                        "object_id": object_id,
                        "next_call_depth": call_depth + 1,
                        "call_context_edge_id": str((graph_edge or {}).get("edge_id", "")),
                        "edge": {
                            "kind": "CALL_RETURN",
                            "summary_kind": "BODY_DERIVED_RETURN",
                            "graph_edge_id": str((graph_edge or {}).get("edge_id", "")),
                            "graph_edge_kind": mnemonic,
                            "call_site_id": str(op.get("site_id", "")),
                            "return_site_id": str(return_op.get("site_id", "")),
                            "from_function_id": caller_function_id,
                            "to_function_id": target_function_id,
                            "resolution_depth": call_depth + 1,
                            "proof": "HIGH_PCODE_RETURN_DEF_USE",
                            **edge_semantics,
                        },
                    }
                )
                if len(out) > self.limits.max_alternatives:
                    self.stats["alternative_exhausted"] += 1
                    return [], "function_summary_alternative_budget_exhausted"
        self.stats["return_summaries"] += 1
        return out, ""

    def exact_store_predecessors(
        self,
        object_id: str,
        *,
        allowed_edge_ids: set[str] | None,
        allowed_node_ids: set[str] | None,
        exclude_function_id: str = "",
    ) -> list[dict[str, Any]]:
        """Return exact STORE values for the same object.

        A setter body may not itself appear in reverse Callgraph BFS.  It is
        admitted when the function is already in the candidate graph or one
        of its incoming callsites is present in that graph.
        """

        if not object_id:
            return []
        candidates: list[dict[str, Any]] = []
        for indexed_object, rows in self.stores_by_object.items():
            if self.same_object(indexed_object, object_id):
                candidates.extend(rows)
        out: list[dict[str, Any]] = []
        for row in candidates:
            function_id = str(row.get("function_id", ""))
            if exclude_function_id and function_id == exclude_function_id:
                continue
            incoming = list(self.calls_to.get(function_id, []))
            admitted_calls = [
                edge
                for edge in incoming
                if allowed_edge_ids is None
                or str(edge.get("edge_id", "")) in allowed_edge_ids
            ]
            admitted = (
                allowed_node_ids is None
                or function_id in allowed_node_ids
                or bool(admitted_calls)
            )
            if not admitted:
                continue
            atom_id = str(row.get("stored_atom_id", ""))
            stored_object = str(row.get("stored_object_id", ""))
            if not atom_id and not stored_object:
                continue
            out.append(
                {
                    "atom_id": atom_id,
                    "value_id": str(row.get("stored_value_id", "")),
                    "object_id": stored_object,
                    "edge": {
                        "kind": "FUNCTION_SUMMARY",
                        "summary_kind": "EXACT_OBJECT_STORE",
                        "site_id": str(row.get("site_id", "")),
                        "object_id": str(row.get("object_id", "")),
                        "from_function_id": function_id,
                        "proof": "HIGH_PCODE_STORE_TO_EXACT_OBJECT",
                        "caller_edge_ids": sorted(
                            str(edge.get("edge_id", "")) for edge in admitted_calls
                        ),
                    },
                }
            )
            if len(out) >= self.limits.max_alternatives:
                break
        if out:
            self.stats["global_store_summaries"] += 1
        return out

    def artifact_counts(self) -> dict[str, int]:
        return {
            "indexed_exact_store_objects": len(self.stores_by_object),
            **dict(sorted(self.stats.items())),
        }
