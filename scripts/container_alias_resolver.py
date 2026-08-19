#!/usr/bin/env python3
"""Recover bounded container-member aliases from High P-code.

The resolver is deliberately name-agnostic.  It recognizes a loop-carried
pointer phi with (1) an initial value loaded through a formal parameter and
(2) a recurrence value loaded from another node.  The result is a MAY alias:
the loop pointer denotes one member reachable from the formal-rooted
container, but node count, list shape, and runtime mutation are not proved.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any


TRANSPARENT = {"CAST", "COPY", "INDIRECT", "INT_SEXT", "INT_ZEXT", "SUBPIECE"}
ADDRESS_OPS = {"INT_ADD", "PTRADD", "PTRSUB"}


def identity(node: dict[str, Any] | None) -> str:
    node = dict(node or {})
    return str(node.get("value_id", "") or node.get("object_id", ""))


def parameter_slot(node: dict[str, Any] | None) -> int | None:
    node = dict(node or {})
    slot = node.get("parameter_slot")
    return slot if isinstance(slot, int) else None


@dataclass(frozen=True)
class FormalPath:
    slot: int
    load_sites: tuple[str, ...]
    operation_sites: tuple[str, ...]


class FunctionIndex:
    def __init__(self, function: dict[str, Any]) -> None:
        self.function = function
        self.definitions = {
            identity(dict(op.get("output", {}) or {})): op
            for op in list(function.get("pcode_ops", []) or [])
            if identity(dict(op.get("output", {}) or {}))
        }

    def definition(self, node: dict[str, Any]) -> dict[str, Any] | None:
        return self.definitions.get(identity(node))

    def formal_paths(
        self,
        node: dict[str, Any],
        *,
        depth: int = 0,
        seen: frozenset[str] = frozenset(),
        max_depth: int = 16,
    ) -> list[FormalPath]:
        if depth > max_depth:
            return []
        slot = parameter_slot(node)
        if slot is not None:
            return [FormalPath(slot, (), ())]
        atom = identity(node)
        if not atom or atom in seen:
            return []
        definition = self.definition(node)
        if definition is None:
            return []
        mnemonic = str(definition.get("mnemonic", ""))
        site = str(definition.get("site_id", ""))
        inputs = [dict(item or {}) for item in list(definition.get("inputs", []) or [])]
        next_seen = seen | {atom}
        if mnemonic in TRANSPARENT | ADDRESS_OPS:
            rows: list[FormalPath] = []
            for item in inputs:
                if bool(item.get("is_constant")):
                    continue
                rows.extend(
                    self.formal_paths(
                        item,
                        depth=depth + 1,
                        seen=next_seen,
                        max_depth=max_depth,
                    )
                )
            return [
                FormalPath(row.slot, row.load_sites, row.operation_sites + ((site,) if site else ()))
                for row in rows
            ]
        if mnemonic == "LOAD" and inputs:
            rows = self.formal_paths(
                inputs[-1],
                depth=depth + 1,
                seen=next_seen,
                max_depth=max_depth,
            )
            return [
                FormalPath(
                    row.slot,
                    row.load_sites + ((site,) if site else ()),
                    row.operation_sites + ((site,) if site else ()),
                )
                for row in rows
            ]
        return []

    def input_atom_for_formal(self, slot: int, fallback: str) -> str:
        candidates: set[str] = set()
        for op in list(self.function.get("pcode_ops", []) or []):
            nodes = list(op.get("inputs", []) or [])
            if isinstance(op.get("output"), dict):
                nodes.append(op["output"])
            for node in nodes:
                node = dict(node or {})
                if (
                    parameter_slot(node) == slot
                    and bool(node.get("is_input"))
                    and identity(node)
                ):
                    candidates.add(identity(node))
        return next(iter(candidates)) if len(candidates) == 1 else fallback

    def depends_on_atom(
        self,
        node: dict[str, Any],
        target_atom: str,
        *,
        depth: int = 0,
        seen: frozenset[str] = frozenset(),
        max_depth: int = 16,
    ) -> bool:
        """Return whether one value has an explicit High P-code def-use path."""

        atom = identity(node)
        if atom == target_atom:
            return True
        if depth > max_depth or not atom or atom in seen:
            return False
        definition = self.definition(node)
        if definition is None:
            return False
        mnemonic = str(definition.get("mnemonic", ""))
        if mnemonic not in TRANSPARENT | ADDRESS_OPS | {"LOAD"}:
            return False
        return any(
            self.depends_on_atom(
                dict(item or {}),
                target_atom,
                depth=depth + 1,
                seen=seen | {atom},
                max_depth=max_depth,
            )
            for item in list(definition.get("inputs", []) or [])
            if not bool(dict(item or {}).get("is_constant"))
        )


def build_bounded_container_aliases(
    program_facts: dict[str, Any],
    *,
    max_aliases_per_function: int = 16,
) -> list[dict[str, Any]]:
    aliases: list[dict[str, Any]] = []
    for function in list(program_facts.get("functions", []) or []):
        function_id = str(function.get("function_id", ""))
        index = FunctionIndex(function)
        function_rows: list[dict[str, Any]] = []
        parameters = {
            int(parameter.get("index")): dict(parameter or {})
            for parameter in list(function.get("parameters", []) or [])
            if isinstance(parameter.get("index"), int)
        }
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "MULTIEQUAL":
                continue
            output = dict(op.get("output", {}) or {})
            output_atom = identity(output)
            if not output_atom or int(output.get("size", 0) or 0) not in {4, 8}:
                continue
            initial_paths: list[tuple[dict[str, Any], FormalPath]] = []
            recurrence_loads: list[dict[str, Any]] = []
            for input_node in [dict(item or {}) for item in list(op.get("inputs", []) or [])]:
                definition = index.definition(input_node)
                paths = index.formal_paths(input_node)
                initial_paths.extend((input_node, path) for path in paths if path.load_sites)
                if (
                    definition is not None
                    and str(definition.get("mnemonic", "")) == "LOAD"
                    and not paths
                ):
                    load_inputs = [
                        dict(item or {})
                        for item in list(definition.get("inputs", []) or [])
                    ]
                    if load_inputs and index.depends_on_atom(
                        load_inputs[-1], output_atom
                    ):
                        recurrence_loads.append(definition)
            initial_slots = {path.slot for _, path in initial_paths}
            if len(initial_slots) != 1 or not recurrence_loads:
                continue
            slot = next(iter(initial_slots))
            parameter = parameters.get(slot, {})
            root_object = str(parameter.get("object_id", ""))
            root_atom = index.input_atom_for_formal(slot, root_object)
            if not root_atom or not root_object:
                continue
            token = hashlib.sha256((function_id + "|" + output_atom).encode()).hexdigest()[:20]
            function_rows.append(
                {
                    "alias_id": f"container-alias:{token}",
                    "function_id": function_id,
                    "function": str(function.get("name", "")),
                    "loop_atom_id": output_atom,
                    "loop_object_id": str(output.get("object_id", "")),
                    "root_parameter_slot": slot,
                    "root_atom_id": root_atom,
                    "root_object_id": root_object,
                    "phi_site_id": str(op.get("site_id", "")),
                    "initial_load_sites": sorted(
                        {site for _, path in initial_paths for site in path.load_sites}
                    ),
                    "recurrence_load_sites": sorted(
                        {str(load.get("site_id", "")) for load in recurrence_loads}
                    ),
                    "analysis_precision": "MAY",
                    "max_container_hops": 1,
                    "assumptions": [
                        "loop_carried_pointer_remains_in_formal_rooted_container",
                        "container_mutation_does_not_replace_payload_provenance",
                    ],
                }
            )
        aliases.extend(function_rows[:max_aliases_per_function])
    unique = {str(row["alias_id"]): row for row in aliases}
    return [unique[key] for key in sorted(unique)]
