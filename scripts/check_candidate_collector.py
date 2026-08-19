#!/usr/bin/env python3
"""Collect Check candidates for every A2 canonical CopperTrace Static Alert.

The collector is deliberately non-semantic.  It follows only the already
reported vulnerable-parameter lineage, then uses High P-code def-use and CFG
facts to attach nearby comparisons and value-limiting effects.  It never
decides that an Alert is safe or vulnerable.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "ct-mini-check-candidates-v2"

COMPARE_OPS = frozenset(
    {
        "BOOL_AND",
        "BOOL_NEGATE",
        "BOOL_OR",
        "FLOAT_EQUAL",
        "FLOAT_LESS",
        "FLOAT_LESSEQUAL",
        "FLOAT_NOTEQUAL",
        "INT_EQUAL",
        "INT_LESS",
        "INT_LESSEQUAL",
        "INT_NOTEQUAL",
        "INT_SLESS",
        "INT_SLESSEQUAL",
    }
)

# These operations may preserve a vulnerable value or derive the scalar used
# by a comparison.  Following them is local def-use, not semantic inference.
FORWARD_LINEAGE_OPS = frozenset(
    {
        "BOOL_AND",
        "BOOL_NEGATE",
        "BOOL_OR",
        "CAST",
        "COPY",
        "INT_2COMP",
        "INT_ADD",
        "INT_AND",
        "INT_LEFT",
        "INT_MULT",
        "INT_NEGATE",
        "INT_OR",
        "INT_REM",
        "INT_RIGHT",
        "INT_SDIV",
        "INT_SEXT",
        "INT_SREM",
        "INT_SRIGHT",
        "INT_SUB",
        "INT_XOR",
        "INT_ZEXT",
        "MULTIEQUAL",
        "PTRADD",
        "PTRSUB",
        "SUBPIECE",
    }
)

VALUE_LIMITING_OPS = frozenset(
    {
        "INT_AND",
        "INT_REM",
        "INT_SREM",
        "SUBPIECE",
    }
)

RETURN_OPS = frozenset({"RETURN"})
CALL_OPS = frozenset({"CALL", "CALLIND"})
EARLY_EXIT_RE = re.compile(r"\b(return|break|continue|goto)\b")
COMPARE_TEXT_RE = re.compile(r"(?:==|!=|<=|>=|<|>)")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _stable_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()[:20]
    return f"{prefix}:{digest}"


def _identity(row: dict[str, Any] | None) -> str:
    row = dict(row or {})
    for key in ("atom_id", "value_id", "backend_atom_id", "binding_id"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    binding = row.get("backend_binding")
    if isinstance(binding, dict):
        for key in ("atom_id", "value_id", "id"):
            value = binding.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def _node_fact(row: dict[str, Any] | None) -> dict[str, Any]:
    row = dict(row or {})
    return {
        "atom_id": _identity(row),
        "value_id": str(row.get("value_id", "") or ""),
        "object_id": str(row.get("object_id", "") or ""),
        "size": int(row.get("size", 0) or 0),
        "is_constant": bool(row.get("is_constant", False)),
        "constant_value": str(row.get("offset", "") or "")
        if bool(row.get("is_constant", False))
        else "",
        "high_name": str(row.get("high_name", "") or ""),
        "high_type": str(row.get("high_type", "") or row.get("data_type", "") or ""),
    }


class ProgramFactsIndex:
    """Read-only indexes over exported High P-code and CFG facts."""

    def __init__(self, program_facts: dict[str, Any]):
        self.functions: dict[str, dict[str, Any]] = {}
        self.ops_by_site: dict[str, tuple[str, dict[str, Any]]] = {}
        self.defs_by_atom: dict[str, tuple[str, dict[str, Any]]] = {}
        self.uses_by_atom: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        self.nodes_by_atom: dict[str, dict[str, Any]] = {}
        self.calls_by_site: dict[str, tuple[str, dict[str, Any]]] = {}
        self.calls_from: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.calls_to: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        self.parameter_atoms: dict[tuple[str, int], set[str]] = defaultdict(set)
        self.return_ops: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.blocks: dict[str, dict[str, dict[str, Any]]] = {}
        self.block_by_site: dict[str, str] = {}
        self.successors: dict[str, dict[str, tuple[str, ...]]] = {}
        self.predecessors: dict[str, dict[str, tuple[str, ...]]] = {}
        self._dominators: dict[str, dict[str, set[str]]] = {}
        self.static_objects: dict[str, list[dict[str, Any]]] = defaultdict(list)

        for raw_object in list(program_facts.get("static_objects", []) or []):
            row = dict(raw_object or {})
            object_id = str(row.get("object_id", "") or "")
            if object_id:
                self.static_objects[object_id].append(row)

        for raw_function in list(program_facts.get("functions", []) or []):
            function = dict(raw_function or {})
            function_id = str(function.get("function_id", "") or "")
            if not function_id:
                continue
            self.functions[function_id] = function
            block_rows = {
                str(row.get("block_id", "")): dict(row or {})
                for row in list(function.get("basic_blocks", []) or [])
                if str(row.get("block_id", ""))
            }
            self.blocks[function_id] = block_rows
            self.successors[function_id] = {
                block_id: tuple(
                    str(value)
                    for value in list(row.get("successor_block_ids", []) or [])
                    if str(value)
                )
                for block_id, row in block_rows.items()
            }
            self.predecessors[function_id] = {
                block_id: tuple(
                    str(value)
                    for value in list(row.get("predecessor_block_ids", []) or [])
                    if str(value)
                )
                for block_id, row in block_rows.items()
            }
            for raw_op in list(function.get("pcode_ops", []) or []):
                op = dict(raw_op or {})
                site_id = str(op.get("site_id", "") or "")
                if site_id:
                    self.ops_by_site[site_id] = (function_id, op)
                    self.block_by_site[site_id] = str(op.get("block_id", "") or "")
                output_atom = _identity(dict(op.get("output", {}) or {}))
                if output_atom:
                    self.defs_by_atom[output_atom] = (function_id, op)
                    self.nodes_by_atom[output_atom] = dict(op.get("output", {}) or {})
                    output = dict(op.get("output", {}) or {})
                    if output.get("is_parameter") and output.get("parameter_slot") is not None:
                        self.parameter_atoms[
                            (function_id, int(output["parameter_slot"]))
                        ].add(output_atom)
                for raw_input in list(op.get("inputs", []) or []):
                    input_node = dict(raw_input or {})
                    input_atom = _identity(input_node)
                    if input_atom:
                        self.uses_by_atom[input_atom].append((function_id, op))
                        self.nodes_by_atom[input_atom] = input_node
                        if input_node.get("is_parameter") and input_node.get("parameter_slot") is not None:
                            self.parameter_atoms[
                                (function_id, int(input_node["parameter_slot"]))
                            ].add(input_atom)
                mnemonic = str(op.get("mnemonic", "") or "")
                if mnemonic in CALL_OPS and site_id:
                    self.calls_by_site[site_id] = (function_id, op)
                    self.calls_from[function_id].append(op)
                    target = str(dict(op.get("call", {}) or {}).get("target_function_id", "") or "")
                    if target:
                        self.calls_to[target].append((function_id, op))
                if mnemonic in RETURN_OPS:
                    self.return_ops[function_id].append(op)

    @staticmethod
    def call_arguments(op: dict[str, Any]) -> list[str]:
        call = dict(op.get("call", {}) or {})
        arguments = [
            str(value)
            for value in list(call.get("argument_value_ids", []) or [])
            if str(value)
        ]
        if arguments:
            return arguments
        return [
            _identity(dict(value or {}))
            for value in list(op.get("inputs", []) or [])[1:]
            if _identity(dict(value or {}))
        ]

    def formal_atoms(self, function_id: str, slot: int) -> set[str]:
        result = set(self.parameter_atoms.get((function_id, slot), set()))
        function = self.functions.get(function_id, {})
        for row in list(function.get("parameters", []) or []):
            raw_index = row.get("index", -1)
            if int(raw_index if raw_index is not None else -1) != slot:
                continue
            object_id = str(row.get("object_id", "") or "")
            for atom, node in self.nodes_by_atom.items():
                if str(node.get("object_id", "") or "") == object_id:
                    result.add(atom)
        return result

    def expand_interprocedural_lineage(
        self,
        functions: set[str],
        targets: dict[str, set[str]],
        lineage_atoms: set[str],
        *,
        max_helper_depth: int,
    ) -> tuple[set[str], dict[str, set[str]], set[str], list[dict[str, Any]]]:
        """Bind path calls and data-dependent helper returns without name rules."""

        functions = set(functions)
        targets = defaultdict(set, {key: set(value) for key, value in targets.items()})
        atoms = set(lineage_atoms)
        bindings: list[dict[str, Any]] = []
        seen_functions: set[tuple[str, int]] = set()
        changed = True
        while changed:
            changed = False
            for caller_id, calls in list(self.calls_from.items()):
                for op in calls:
                    site_id = str(op.get("site_id", "") or "")
                    target_id = str(
                        dict(op.get("call", {}) or {}).get("target_function_id", "") or ""
                    )
                    call_is_on_path = site_id in targets.get(caller_id, set())
                    if not call_is_on_path or not target_id:
                        continue
                    arguments = self.call_arguments(op)
                    for slot, actual_atom in enumerate(arguments):
                        formals = self.formal_atoms(target_id, slot)
                        if actual_atom in atoms or atoms.intersection(formals):
                            before = len(atoms)
                            atoms.add(actual_atom)
                            atoms.update(formals)
                            functions.update({caller_id, target_id})
                            targets[caller_id].add(site_id)
                            bindings.append(
                                {
                                    "kind": "CALL_ACTUAL_FORMAL",
                                    "evidence_level": "deterministic",
                                    "call_site_id": site_id,
                                    "caller_function_id": caller_id,
                                    "callee_function_id": target_id,
                                    "parameter_slot": slot,
                                    "actual_value_id": actual_atom,
                                    "formal_value_ids": sorted(formals),
                                }
                            )
                            changed = changed or len(atoms) != before

        queue = deque((function_id, 0) for function_id in sorted(functions))
        while queue:
            function_id, depth = queue.popleft()
            if (function_id, depth) in seen_functions or depth >= max_helper_depth:
                continue
            seen_functions.add((function_id, depth))
            for op in self.calls_from.get(function_id, []):
                output_atom = _identity(dict(op.get("output", {}) or {}))
                if not output_atom or output_atom not in atoms:
                    continue
                target_id = str(
                    dict(op.get("call", {}) or {}).get("target_function_id", "") or ""
                )
                if not target_id or target_id not in self.functions:
                    continue
                return_atoms = {
                    _identity(dict(value or {}))
                    for return_op in self.return_ops.get(target_id, [])
                    for value in list(return_op.get("inputs", []) or [])
                    if _identity(dict(value or {}))
                }
                if not return_atoms:
                    continue
                atoms.update(return_atoms)
                functions.add(target_id)
                for return_op in self.return_ops.get(target_id, []):
                    targets[target_id].add(str(return_op.get("site_id", "") or ""))
                bindings.append(
                    {
                        "kind": "CALL_RETURN",
                        "evidence_level": "deterministic",
                        "call_site_id": str(op.get("site_id", "") or ""),
                        "caller_function_id": function_id,
                        "callee_function_id": target_id,
                        "call_output_value_id": output_atom,
                        "return_value_ids": sorted(return_atoms),
                        "helper_depth": depth + 1,
                    }
                )
                queue.append((target_id, depth + 1))
        unique_bindings = {
            _canonical_json(binding): binding for binding in bindings
        }
        return functions, targets, atoms, [
            unique_bindings[key] for key in sorted(unique_bindings)
        ]

    def function_for_site(self, site_id: str) -> str:
        entry = self.ops_by_site.get(str(site_id or ""))
        return entry[0] if entry else ""

    def target_block(self, site_id: str) -> str:
        return self.block_by_site.get(str(site_id or ""), "")

    def reachable(self, function_id: str, start: str, target: str) -> bool:
        if not start or not target:
            return False
        queue = deque([start])
        seen: set[str] = set()
        while queue:
            block = queue.popleft()
            if block == target:
                return True
            if block in seen:
                continue
            seen.add(block)
            queue.extend(self.successors.get(function_id, {}).get(block, ()))
        return False

    def dominators(self, function_id: str) -> dict[str, set[str]]:
        if function_id in self._dominators:
            return self._dominators[function_id]
        blocks = set(self.blocks.get(function_id, {}))
        if not blocks:
            self._dominators[function_id] = {}
            return {}
        entries = {
            block
            for block in blocks
            if not self.predecessors.get(function_id, {}).get(block, ())
        }
        if not entries:
            entries = {min(blocks)}
        dom = {
            block: ({block} if block in entries else set(blocks))
            for block in blocks
        }
        changed = True
        while changed:
            changed = False
            for block in sorted(blocks - entries):
                preds = [
                    value
                    for value in self.predecessors.get(function_id, {}).get(block, ())
                    if value in blocks
                ]
                incoming = set.intersection(*(dom[value] for value in preds)) if preds else set()
                updated = {block} | incoming
                if updated != dom[block]:
                    dom[block] = updated
                    changed = True
        self._dominators[function_id] = dom
        return dom

    def branch_relation(
        self,
        function_id: str,
        branch_op: dict[str, Any],
        target_sites: Iterable[str],
    ) -> dict[str, Any] | None:
        branch_site = str(branch_op.get("site_id", "") or "")
        branch_block = str(branch_op.get("block_id", "") or "")
        successors = self.successors.get(function_id, {}).get(branch_block, ())
        for target_site in sorted(set(str(value) for value in target_sites if str(value))):
            if self.function_for_site(target_site) != function_id:
                continue
            target_block = self.target_block(target_site)
            if not target_block:
                continue
            successor_reach = [
                successor
                for successor in successors
                if self.reachable(function_id, successor, target_block)
            ]
            if successors and 0 < len(successor_reach) < len(successors):
                return {
                    "relation": "ONE_BRANCH_SUCCESSOR_REACHES_TARGET",
                    "branch_site_id": branch_site,
                    "branch_block_id": branch_block,
                    "target_site_id": target_site,
                    "target_block_id": target_block,
                    "reaching_successor_block_ids": successor_reach,
                }
        return None


def _path_functions_and_targets(
    chain: dict[str, Any], parameter: dict[str, Any], index: ProgramFactsIndex
) -> tuple[set[str], dict[str, set[str]], set[str]]:
    functions: set[str] = set()
    targets: dict[str, set[str]] = defaultdict(set)
    lineage_atoms: set[str] = set()
    sink_site = str(chain.get("sink_site_id", "") or "")
    sink_function = str(chain.get("sink_function_id", "") or index.function_for_site(sink_site))
    if sink_function:
        functions.add(sink_function)
        if sink_site:
            targets[sink_function].add(sink_site)

    start_value = str(parameter.get("start_value_id", "") or "")
    if start_value:
        lineage_atoms.add(start_value)
    for path in list(parameter.get("paths", []) or []):
        for raw_step in list(path.get("path", []) or []):
            step = dict(raw_step or {})
            site_id = str(step.get("site_id") or step.get("call_site_id") or "")
            function_id = str(step.get("function_id", "") or index.function_for_site(site_id))
            for field in ("from_function_id", "to_function_id"):
                if str(step.get(field, "")):
                    functions.add(str(step[field]))
            if function_id:
                functions.add(function_id)
                if site_id:
                    targets[function_id].add(site_id)
            for binding_name in ("consumer_binding", "predecessor_binding"):
                binding = dict(step.get(binding_name, {}) or {})
                for value in (_identity(binding), str(binding.get("value_id", "") or "")):
                    if value:
                        lineage_atoms.add(value)
            for field in ("atom_id", "value_atom_id", "value_id"):
                if str(step.get(field, "")):
                    lineage_atoms.add(str(step[field]))
    return functions, targets, lineage_atoms


def _backward_context(
    index: ProgramFactsIndex,
    seed_atoms: Iterable[str],
    *,
    allowed_function: str,
    budget: int,
) -> tuple[list[dict[str, Any]], bool]:
    queue = deque(str(value) for value in seed_atoms if str(value))
    seen_atoms: set[str] = set()
    rows: list[dict[str, Any]] = []
    truncated = False
    while queue:
        atom = queue.popleft()
        if atom in seen_atoms:
            continue
        seen_atoms.add(atom)
        entry = index.defs_by_atom.get(atom)
        if not entry or entry[0] != allowed_function:
            continue
        if len(rows) >= budget:
            truncated = True
            break
        op = entry[1]
        rows.append(
            {
                "site_id": str(op.get("site_id", "") or ""),
                "mnemonic": str(op.get("mnemonic", "") or ""),
                "output": _node_fact(dict(op.get("output", {}) or {})),
                "inputs": [_node_fact(dict(value or {})) for value in list(op.get("inputs", []) or [])],
            }
        )
        for value in list(op.get("inputs", []) or []):
            input_atom = _identity(dict(value or {}))
            if input_atom:
                queue.append(input_atom)
    return rows, truncated


def _check_candidate(
    *,
    kind: str,
    alert_id: str,
    role: str,
    function_id: str,
    op: dict[str, Any],
    branch: dict[str, Any] | None,
    relation: dict[str, Any] | None,
    checked_atoms: set[str],
    context: list[dict[str, Any]],
    evidence_level: str,
    parameter_relation: str,
    capacity_relation: str,
    execution_relation: str,
) -> dict[str, Any]:
    # The represented Alert ID is provenance, not part of the Check identity.
    # A2 can merge equivalent paths; a shared function/site Check should occur
    # once in the reviewer packet instead of once per represented path.
    identity_payload = {
        "kind": kind,
        "role": role,
        "function_id": function_id,
        "site_id": str(op.get("site_id", "") or ""),
        "branch_site_id": str((branch or {}).get("site_id", "") or ""),
        "target_site_id": str((relation or {}).get("target_site_id", "") or ""),
        "checked_atoms": sorted(checked_atoms),
    }
    return {
        "check_id": _stable_id("check", identity_payload),
        **identity_payload,
        "represented_alert_id": alert_id,
        "mnemonic": str(op.get("mnemonic", "") or ""),
        "output": _node_fact(dict(op.get("output", {}) or {})),
        "operands": [_node_fact(dict(value or {})) for value in list(op.get("inputs", []) or [])],
        "branch_relation": dict(relation or {}),
        "context_slice": context,
        "evidence_level": evidence_level,
        "parameter_relation": parameter_relation,
        "capacity_relation": capacity_relation,
        "execution_relation": execution_relation,
        "semantic_decision": "NOT_PERFORMED",
    }


def _parameter_candidates(
    *,
    alert_id: str,
    chain: dict[str, Any],
    parameter: dict[str, Any],
    index: ProgramFactsIndex,
    max_context_ops: int,
    max_check_candidates: int,
    max_helper_depth: int,
) -> dict[str, Any]:
    role = str(parameter.get("role", "") or "unknown")
    allowed_functions, targets, lineage_atoms = _path_functions_and_targets(
        chain, parameter, index
    )
    (
        allowed_functions,
        targets,
        lineage_atoms,
        interprocedural_bindings,
    ) = index.expand_interprocedural_lineage(
        allowed_functions,
        targets,
        lineage_atoms,
        max_helper_depth=max_helper_depth,
    )
    queue = deque(sorted(lineage_atoms))
    visited_atoms: set[str] = set()
    visited_uses: set[str] = set()
    candidates_by_id: dict[str, dict[str, Any]] = {}
    context_ops_used = 0
    truncation_reasons: set[str] = set()
    parameter_path_site_ids = {
        str(step.get("site_id") or step.get("call_site_id") or "")
        for path in list(parameter.get("paths", []) or [])
        for step in list(path.get("path", []) or [])
        if str(step.get("site_id") or step.get("call_site_id") or "")
    }
    start_value_id = str(parameter.get("start_value_id", "") or "")

    def add_candidate(candidate: dict[str, Any]) -> None:
        candidates_by_id.setdefault(candidate["check_id"], candidate)

    while queue:
        atom = queue.popleft()
        if atom in visited_atoms:
            continue
        visited_atoms.add(atom)
        for function_id, op in index.uses_by_atom.get(atom, []):
            if function_id not in allowed_functions:
                continue
            site_id = str(op.get("site_id", "") or "")
            visit_key = f"{site_id}|{atom}"
            if visit_key in visited_uses:
                continue
            visited_uses.add(visit_key)
            if context_ops_used >= max_context_ops:
                truncation_reasons.add("max_context_ops")
                queue.clear()
                break
            context_ops_used += 1
            mnemonic = str(op.get("mnemonic", "") or "")
            output_atom = _identity(dict(op.get("output", {}) or {}))

            if mnemonic in COMPARE_OPS:
                checked = {
                    _identity(dict(value or {}))
                    for value in list(op.get("inputs", []) or [])
                } & visited_atoms
                other_atoms = [
                    _identity(dict(value or {}))
                    for value in list(op.get("inputs", []) or [])
                    if _identity(dict(value or {})) not in checked
                    and _identity(dict(value or {}))
                ]
                remaining = max(0, max_context_ops - context_ops_used)
                context, context_truncated = _backward_context(
                    index,
                    other_atoms,
                    allowed_function=function_id,
                    budget=remaining,
                )
                context_ops_used += len(context)
                if context_truncated:
                    truncation_reasons.add("max_context_ops")
                branches = [
                    branch_op
                    for branch_function, branch_op in index.uses_by_atom.get(output_atom, [])
                    if branch_function == function_id
                    and str(branch_op.get("mnemonic", "")) == "CBRANCH"
                ]
                emitted = False
                for branch_op in branches:
                    relation = index.branch_relation(
                        function_id, branch_op, targets.get(function_id, set())
                    )
                    if relation:
                        add_candidate(
                            _check_candidate(
                                kind="BRANCH_GATED_CHECK",
                                alert_id=alert_id,
                                role=role,
                                function_id=function_id,
                                op=op,
                                branch=branch_op,
                                relation=relation,
                                checked_atoms=checked or {atom},
                                context=context,
                                evidence_level="deterministic",
                                parameter_relation="BINDS",
                                capacity_relation="UNKNOWN",
                                execution_relation="GOVERNS_SINK",
                            )
                        )
                        emitted = True
                if not emitted and branches:
                    add_candidate(
                        _check_candidate(
                            kind="UNCLASSIFIED_RELATED_CHECK",
                            alert_id=alert_id,
                            role=role,
                            function_id=function_id,
                            op=op,
                            branch=branches[0] if branches else None,
                            relation=None,
                            checked_atoms=checked or {atom},
                            context=context,
                            evidence_level="heuristic",
                            parameter_relation="BINDS",
                            capacity_relation="UNKNOWN",
                            execution_relation="UNKNOWN",
                        )
                    )

            if mnemonic in VALUE_LIMITING_OPS and (
                output_atom == start_value_id or site_id in parameter_path_site_ids
            ):
                other_atoms = [
                    _identity(dict(value or {}))
                    for value in list(op.get("inputs", []) or [])
                    if _identity(dict(value or {})) and _identity(dict(value or {})) != atom
                ]
                remaining = max(0, max_context_ops - context_ops_used)
                context, context_truncated = _backward_context(
                    index,
                    other_atoms,
                    allowed_function=function_id,
                    budget=remaining,
                )
                context_ops_used += len(context)
                if context_truncated:
                    truncation_reasons.add("max_context_ops")
                add_candidate(
                    _check_candidate(
                        kind="VALUE_LIMITING_CHECK",
                        alert_id=alert_id,
                        role=role,
                        function_id=function_id,
                        op=op,
                        branch=None,
                        relation=None,
                        checked_atoms={atom},
                        context=context,
                        evidence_level="deterministic",
                        parameter_relation="BINDS",
                        capacity_relation="UNKNOWN",
                        execution_relation="GOVERNS_SINK_VALUE",
                    )
                )

            if output_atom and mnemonic in FORWARD_LINEAGE_OPS:
                queue.append(output_atom)

    pcode_evidence_functions = {
        row["function_id"] for row in candidates_by_id.values()
    }
    for candidate in _decompiled_structural_candidates(
        alert_id=alert_id,
        role=role,
        allowed_functions=allowed_functions,
        lineage_atoms=lineage_atoms,
        index=index,
        excluded_functions=pcode_evidence_functions,
    ):
        add_candidate(candidate)

    priority = {
        "BRANCH_GATED_CHECK": 0,
        "VALUE_LIMITING_CHECK": 1,
        "UNCLASSIFIED_RELATED_CHECK": 2,
        "DECOMPILED_BRANCH_CHECK": 3,
    }
    ordered = sorted(
        candidates_by_id.values(),
        key=lambda row: (
            priority.get(str(row.get("kind", "")), 9),
            str(row.get("function_id", "")),
            str(row.get("site_id", "")),
            str(row.get("check_id", "")),
        ),
    )
    # An ungated comparison is useful heuristic context, but repeated
    # comparisons in the same function should not dominate the packet.
    related_functions: set[str] = set()
    reduced: list[dict[str, Any]] = []
    for row in ordered:
        if row.get("kind") == "UNCLASSIFIED_RELATED_CHECK":
            function_id = str(row.get("function_id", ""))
            if function_id in related_functions:
                continue
            related_functions.add(function_id)
        reduced.append(row)
    if len(reduced) > max_check_candidates:
        truncation_reasons.add("max_check_candidates")
    candidates = reduced[:max_check_candidates]
    return {
        "role": role,
        "start_value_id": str(parameter.get("start_value_id", "") or ""),
        "lineage_atom_ids": sorted(lineage_atoms),
        "allowed_function_ids": sorted(allowed_functions),
        "interprocedural_bindings": interprocedural_bindings,
        "check_candidates": candidates,
        "collection_status": "TRUNCATED" if truncation_reasons else "COMPLETE",
        "truncation_reasons": sorted(truncation_reasons),
        "context_ops_visited": context_ops_used,
    }


def _decompiled_structural_candidates(
    *,
    alert_id: str,
    role: str,
    allowed_functions: set[str],
    lineage_atoms: set[str],
    index: ProgramFactsIndex,
    excluded_functions: set[str],
) -> list[dict[str, Any]]:
    """Collect structural C evidence; identifiers alone never create a Check."""

    rows: list[dict[str, Any]] = []
    for function_id in sorted(allowed_functions):
        # Decompiled C is a fallback for structure lost from CFG/P-code, not a
        # second copy of evidence that is already represented precisely.
        if function_id in excluded_functions:
            continue
        local_atoms = {
            atom
            for atom in lineage_atoms
            if (
                index.defs_by_atom.get(atom, ("", {}))[0] == function_id
                or any(
                    use_function == function_id
                    for use_function, _op in index.uses_by_atom.get(atom, [])
                )
            )
        }
        names = {
            str(index.nodes_by_atom.get(atom, {}).get("high_name", "") or "")
            for atom in local_atoms
        }
        names = {
            name
            for name in names
            if name and name not in {"UNNAMED", "this", "param_1", "param_2"}
        }
        if not names:
            continue
        code = str(index.functions.get(function_id, {}).get("decompiled_c", "") or "")
        lines = code.splitlines()
        function_rows: list[tuple[int, dict[str, Any]]] = []
        for line_index, line in enumerate(lines):
            stripped = line.strip()
            if "if" not in stripped or not COMPARE_TEXT_RE.search(stripped):
                continue
            matched = sorted(
                name
                for name in names
                if re.search(rf"\b{re.escape(name)}\b", stripped)
            )
            if not matched:
                continue
            following = lines[line_index + 1 : line_index + 7]
            window = "\n".join([line, *following]).strip()
            has_early_exit = bool(EARLY_EXIT_RE.search("\n".join([line, *following])))
            has_conditional_assignment = any(
                re.search(rf"\b{re.escape(name)}\b\s*=", child)
                for name in matched
                for child in following
            )
            scalar_role = role in {
                "amount",
                "count",
                "index",
                "len",
                "length",
                "offset",
                "size",
                "value",
            }
            if not has_early_exit and not (scalar_role and has_conditional_assignment):
                continue
            payload = {
                "kind": "DECOMPILED_BRANCH_CHECK",
                "role": role,
                "function_id": function_id,
                "decompiled_line": line_index + 1,
                "matched_names": matched,
                "snippet": window,
            }
            function_rows.append(
                (
                    0 if has_early_exit else 1,
                    {
                    "check_id": _stable_id("check", payload),
                    **payload,
                    "represented_alert_id": alert_id,
                    "site_id": "",
                    "branch_site_id": "",
                    "target_site_id": "",
                    "mnemonic": "DECOMPILED_IF",
                    "output": {},
                    "operands": [],
                    "branch_relation": {},
                    "context_slice": [],
                    "evidence_level": "heuristic",
                    "parameter_relation": "LIKELY_BINDS",
                    "capacity_relation": "UNKNOWN",
                    "execution_relation": (
                        "LIKELY_GOVERNS" if has_early_exit else "UNKNOWN"
                    ),
                    "semantic_decision": "NOT_PERFORMED",
                    },
                )
            )
        # Keep a small, deterministic fallback slice per function. The full
        # function remains available to the read-only reviewer query.
        rows.extend(
            row
            for _score, row in sorted(
                function_rows,
                key=lambda value: (
                    value[0],
                    int(value[1].get("decompiled_line", 0) or 0),
                    str(value[1].get("check_id", "")),
                ),
            )[:2]
        )
    return rows


def _destination_capacity_evidence(
    sink: dict[str, Any], index: ProgramFactsIndex
) -> list[dict[str, Any]]:
    role_bindings = dict(sink.get("role_bindings", {}) or {})
    role = "dst" if "dst" in role_bindings else "buffer" if "buffer" in role_bindings else ""
    binding = dict(role_bindings.get(role, {}) or {})
    object_id = str(binding.get("object_id", "") or "")
    value_id = str(binding.get("value_id", "") or "")
    rows: list[dict[str, Any]] = []

    for object_row in index.static_objects.get(object_id, []):
        extent = int(object_row.get("extent", 0) or 0)
        if extent <= 0:
            continue
        payload = {
            "kind": "STATIC_OBJECT_EXTENT",
            "object_id": object_id,
            "extent": extent,
            "extent_evidence": str(object_row.get("extent_evidence", "") or ""),
        }
        rows.append(
            {
                "evidence_id": _stable_id("capacity", payload),
                **payload,
                "evidence_level": "deterministic",
                "role": role,
                "function_id": str(object_row.get("function_id", "") or ""),
                "storage_space": str(object_row.get("storage_space", "") or ""),
                "semantic_decision": "NOT_PERFORMED",
            }
        )

    definition = index.defs_by_atom.get(value_id)
    if definition and str(definition[1].get("mnemonic", "") or "") in CALL_OPS:
        call = dict(definition[1].get("call", {}) or {})
        arguments = [
            _node_fact(index.nodes_by_atom.get(atom, {}))
            for atom in index.call_arguments(definition[1])
        ]
        payload = {
            "kind": "CALL_RESULT_OBJECT",
            "site_id": str(definition[1].get("site_id", "") or ""),
            "target_function_id": str(call.get("target_function_id", "") or ""),
            "result_value_id": value_id,
        }
        rows.append(
            {
                "evidence_id": _stable_id("capacity", payload),
                **payload,
                "evidence_level": "heuristic",
                "role": role,
                "candidate_extent_arguments": arguments,
                "semantic_decision": "NOT_PERFORMED",
            }
        )

    if str(sink.get("label", "") or "") == "BUFFER_STATE_SINK":
        proof = dict(sink.get("proof", {}) or {})
        payload = {
            "kind": "BUFFER_STATE_EFFECT",
            "sink_id": str(sink.get("id", "") or sink.get("sink_id", "") or ""),
            "body_function_id": str(proof.get("body_function_id", "") or ""),
            "effect_site_ids": list(proof.get("effect_site_ids", []) or []),
        }
        rows.append(
            {
                "evidence_id": _stable_id("capacity", payload),
                **payload,
                "evidence_level": (
                    "deterministic"
                    if str(sink.get("recognition", "") or "") == "deterministic"
                    else "heuristic"
                ),
                "role": role,
                "amount_binding": dict(role_bindings.get("amount", {}) or {}),
                "semantic_decision": "NOT_PERFORMED",
            }
        )
    return rows


def _sink_review_question(sink: dict[str, Any]) -> dict[str, Any]:
    label = str(sink.get("label", "") or "UNKNOWN_SINK")
    parameters = list(sink.get("vulnerable_parameters", []) or [])
    roles = [str(row.get("role", "") or "unknown") for row in parameters]
    expressions = {
        str(row.get("role", "") or "unknown"): str(
            row.get("actual_expression")
            or row.get("expression")
            or row.get("expr")
            or row.get("node")
            or ""
        )
        for row in parameters
    }
    sink_roles = {
        str(role): str(expression)
        for role, expression in dict(sink.get("roles", {}) or {}).items()
        if str(role)
    }
    role_bindings = {
        str(role): {
            "value_id": str(dict(binding or {}).get("value_id", "") or ""),
            "object_id": str(dict(binding or {}).get("object_id", "") or ""),
            "constant": dict(binding or {}).get("constant"),
        }
        for role, binding in dict(sink.get("role_bindings", {}) or {}).items()
        if str(role)
    }
    requires_destination_validity = label in {
        "COPY_SINK",
        "MEMSET_SINK",
        "BUFFER_STATE_SINK",
        "STORE_SINK",
        "LOOP_WRITE_SINK",
    }
    role_set = {role.lower() for role in roles}
    dangerous_conditions: list[str] = []
    if label == "COPY_SINK":
        if "src" in role_set:
            dangerous_conditions.append(
                "if the source address, index, offset, or requested extent is attacker-influenced, the selected source read range can be invalid"
            )
        if "dst" in role_set:
            dangerous_conditions.append(
                "the selected destination object or destination write range can be invalid"
            )
        if {"len", "length", "size"} & role_set:
            dangerous_conditions.append(
                "the requested extent or its arithmetic can exceed a valid source or destination range"
            )
        # Destination selection remains part of COPY safety even when the
        # backward-DFA roots intentionally omit dst.
        dangerous_conditions.append(
            "the destination object selection and valid extent must cover the complete write"
        )
    elif label == "MEMSET_SINK":
        dangerous_conditions.extend(
            [
                "the selected destination object or fill range can be invalid",
                "the destination valid extent must cover the complete fill",
            ]
        )
    elif label == "BUFFER_STATE_SINK":
        dangerous_conditions.extend(
            [
                "the buffer object, cursor, length, or type-state can be invalid",
                "the reported amount can violate the buffer cursor/length invariant",
            ]
        )
    elif label == "STORE_SINK":
        dangerous_conditions.append(
            "the stored value, target object, or destination selection can be invalid"
        )
    elif label == "LOOP_WRITE_SINK":
        dangerous_conditions.append(
            "the loop bound, object selection, or address progression can exceed the valid destination range"
        )
    else:
        dangerous_conditions.append(
            "the reported vulnerable parameters can cause the Sink's dangerous memory effect"
        )

    dangerous_conditions = list(dict.fromkeys(dangerous_conditions))
    return {
        "sink_label": label,
        "vulnerable_parameter_roles": roles,
        "vulnerable_parameter_expressions": expressions,
        "sink_roles": sink_roles,
        "role_bindings": role_bindings,
        "destination": {
            "expression": sink_roles.get("dst", sink_roles.get("buffer", "")),
            "value_id": str(
                role_bindings.get("dst", role_bindings.get("buffer", {})).get(
                    "value_id", ""
                )
            ),
            "object_id": str(
                role_bindings.get("dst", role_bindings.get("buffer", {})).get(
                    "object_id", ""
                )
            ),
        },
        "requires_destination_validity": requires_destination_validity,
        "requires_source_validity": label == "COPY_SINK" and "src" in role_set,
        "source_validity_scope": (
            "REQUIRED_IF_ADDRESS_INDEX_OFFSET_OR_EXTENT_IS_ATTACKER_INFLUENCED"
            if label == "COPY_SINK" and "src" in role_set
            else "NOT_APPLICABLE"
        ),
        "dangerous_conditions": dangerous_conditions,
        "reject_only_if_all_conditions_blocked": True,
        "question": (
            "Do the supplied Checks, object evidence, and value-limiting effects "
            "prove that every listed dangerous condition is prevented at this exact Sink site?"
        ),
    }


def collect_alert_checks(
    alert: dict[str, Any],
    *,
    chains_doc: dict[str, Any],
    sinks_doc: dict[str, Any],
    program_facts: dict[str, Any],
    max_context_ops: int = 128,
    max_check_candidates: int = 16,
    max_helper_depth: int = 2,
    _index: ProgramFactsIndex | None = None,
) -> dict[str, Any]:
    index = _index or ProgramFactsIndex(program_facts)
    chains = {
        str(row.get("chain_id", "")): row
        for row in list(chains_doc.get("chains", []) or [])
        if str(row.get("chain_id", ""))
    }
    sinks = {
        str(row.get("id", "")): row
        for row in list(sinks_doc.get("sink_startpoints", []) or sinks_doc.get("sinks", []) or [])
        if str(row.get("id", ""))
    }
    represented = list(alert.get("represented_alert_ids", []) or [alert.get("alert_id", "")])
    represented_results: list[dict[str, Any]] = []
    all_check_ids: set[str] = set()
    all_complete = True
    sink = sinks.get(str(alert.get("sink_id", "")), {})

    for represented_id in sorted(str(value) for value in represented if str(value)):
        chain = chains.get(represented_id)
        if not chain:
            all_complete = False
            represented_results.append(
                {
                    "alert_id": represented_id,
                    "collection_status": "ERROR",
                    "error": "represented_alert_missing_from_chains",
                    "parameters": [],
                }
            )
            continue
        parameters = [
            _parameter_candidates(
                alert_id=represented_id,
                chain=chain,
                parameter=dict(parameter or {}),
                index=index,
                max_context_ops=max_context_ops,
                max_check_candidates=max_check_candidates,
                max_helper_depth=max_helper_depth,
            )
            for parameter in list(chain.get("parameter_results", []) or [])
            if str(parameter.get("role", ""))
            in set(str(value) for value in list(alert.get("vulnerable_parameter_roles", []) or []))
        ]
        for parameter in parameters:
            unique_candidates: list[dict[str, Any]] = []
            reused_check_ids: list[str] = []
            for row in list(parameter.get("check_candidates", []) or []):
                check_id = str(row.get("check_id", "") or "")
                if not check_id:
                    continue
                if check_id in all_check_ids:
                    reused_check_ids.append(check_id)
                    continue
                all_check_ids.add(check_id)
                unique_candidates.append(row)
            parameter["check_candidates"] = unique_candidates
            parameter["reused_check_ids"] = sorted(set(reused_check_ids))
        status = (
            "TRUNCATED"
            if any(row.get("collection_status") == "TRUNCATED" for row in parameters)
            else "COMPLETE"
        )
        all_complete = all_complete and status == "COMPLETE"
        represented_results.append(
            {
                "alert_id": represented_id,
                "collection_status": status,
                "parameters": parameters,
            }
        )

    return {
        "alert": copy.deepcopy(alert),
        "sink_review_question": _sink_review_question(sink),
        "check_evidence": {
            "schema_version": SCHEMA_VERSION,
            "collection_status": "COMPLETE" if all_complete else "TRUNCATED",
            "max_context_ops_per_parameter": max_context_ops,
            "max_check_candidates_per_parameter": max_check_candidates,
            "max_helper_depth": max_helper_depth,
            "check_candidate_count": len(all_check_ids),
            "represented_alerts": represented_results,
            "destination_capacity_evidence": _destination_capacity_evidence(
                sink, index
            ),
            "semantic_decision": "NOT_PERFORMED",
        },
    }


def collect_canonical_alerts(
    a2_doc: dict[str, Any],
    *,
    chains_doc: dict[str, Any],
    sinks_doc: dict[str, Any],
    program_facts: dict[str, Any],
    max_context_ops: int = 128,
    max_check_candidates: int = 16,
    max_helper_depth: int = 2,
) -> list[dict[str, Any]]:
    index = ProgramFactsIndex(program_facts)
    return [
        collect_alert_checks(
            dict(alert or {}),
            chains_doc=chains_doc,
            sinks_doc=sinks_doc,
            program_facts=program_facts,
            max_context_ops=max_context_ops,
            max_check_candidates=max_check_candidates,
            max_helper_depth=max_helper_depth,
            _index=index,
        )
        for alert in list(a2_doc.get("canonical_alerts", []) or [])
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--a2", required=True, type=Path)
    parser.add_argument("--chains", required=True, type=Path)
    parser.add_argument("--sinks", required=True, type=Path)
    parser.add_argument("--program-facts", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--max-context-ops", type=int, default=128)
    parser.add_argument("--max-check-candidates", type=int, default=16)
    parser.add_argument("--max-helper-depth", type=int, default=2)
    args = parser.parse_args()
    result = {
        "schema_version": "ct-mini-check-enriched-canonical-alerts-v3",
        "alerts": collect_canonical_alerts(
            read_json(args.a2),
            chains_doc=read_json(args.chains),
            sinks_doc=read_json(args.sinks),
            program_facts=read_json(args.program_facts),
            max_context_ops=max(1, args.max_context_ops),
            max_check_candidates=max(1, args.max_check_candidates),
            max_helper_depth=max(0, args.max_helper_depth),
        ),
    }
    write_json(args.out, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
