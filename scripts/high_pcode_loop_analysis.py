#!/usr/bin/env python3
"""Bounded High P-code and CFG helpers for body-derived Sink recognition.

This module intentionally does not infer a CFG from instruction addresses.
Callers must provide Ghidra High P-code operations with ``block_id`` and a
``basic_blocks`` graph.  Old flat ProgramFacts therefore produce explicit
blockers instead of lower-confidence guesses.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Iterable


VALUE_PRESERVING_OPS = {
    "COPY",
    "CAST",
    "INT_ZEXT",
    "INT_SEXT",
    "SUBPIECE",
    "INDIRECT",
}
ADDRESS_OPS = {"PTRADD", "PTRSUB", "INT_ADD", "INT_SUB"}
COMPARISON_OPS = {
    "INT_EQUAL",
    "INT_NOTEQUAL",
    "INT_LESS",
    "INT_LESSEQUAL",
    "INT_SLESS",
    "INT_SLESSEQUAL",
}
CONTROL_OPS = {"BRANCH", "CBRANCH", "BRANCHIND", "RETURN"}


def parse_int(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def node_value_id(node: dict[str, Any] | None) -> str:
    return str((node or {}).get("value_id", ""))


def node_object_id(node: dict[str, Any] | None) -> str:
    return str((node or {}).get("object_id", ""))


def node_constant(node: dict[str, Any] | None) -> int | None:
    row = dict(node or {})
    if not bool(row.get("is_constant")):
        return None
    return parse_int(row.get("offset"))


def node_signed_constant(node: dict[str, Any] | None) -> int | None:
    """Interpret a constant with the varnode width used by High P-code.

    Ghidra serializes negative PTRADD indices as their unsigned bit pattern
    (for example, ``0xffffffff`` for ``-1`` in a 32-bit varnode).  Loop
    progressions need the signed step or opposite pointer directions appear
    to have unrelated strides.
    """

    row = dict(node or {})
    value = node_constant(row)
    if value is None:
        return None
    try:
        size = int(row.get("size", 0) or 0)
    except (TypeError, ValueError):
        size = 0
    if size <= 0:
        return value
    bits = size * 8
    mask = (1 << bits) - 1
    value &= mask
    sign_bit = 1 << (bits - 1)
    return value - (1 << bits) if value & sign_bit else value


def node_text(node: dict[str, Any] | None) -> str:
    row = dict(node or {})
    return (
        str(row.get("high_name", "") or "")
        or str(row.get("address", "") or "")
        or node_value_id(row)
        or node_object_id(row)
    )


def block_ref(value: Any) -> str:
    if isinstance(value, dict):
        for key in ("block_id", "id", "target", "successor"):
            if value.get(key):
                return str(value[key])
        return ""
    return str(value or "")


@dataclass(frozen=True)
class AnalysisBlocker:
    code: str
    message: str
    function_id: str = ""
    evidence: tuple[str, ...] = ()

    def as_json(self) -> dict[str, Any]:
        row: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        if self.function_id:
            row["function_id"] = self.function_id
        if self.evidence:
            row["evidence"] = list(self.evidence)
        return row


@dataclass(frozen=True)
class NaturalLoop:
    header: str
    tails: tuple[str, ...]
    blocks: frozenset[str]
    exits: tuple[tuple[str, str], ...]

    @property
    def loop_id(self) -> str:
        return f"loop:{self.header}"

    def as_json(self) -> dict[str, Any]:
        return {
            "loop_id": self.loop_id,
            "header": self.header,
            "tails": list(self.tails),
            "blocks": sorted(self.blocks),
            "exits": [{"from": source, "to": target} for source, target in self.exits],
        }


@dataclass(frozen=True)
class Recurrence:
    phi_value_id: str
    phi_site_id: str
    header_block_id: str
    initial_node: dict[str, Any]
    update_value_id: str
    update_site_id: str
    update_block_id: str
    step: int

    def as_json(self) -> dict[str, Any]:
        return {
            "phi_value_id": self.phi_value_id,
            "phi_site_id": self.phi_site_id,
            "header_block_id": self.header_block_id,
            "initial": node_text(self.initial_node),
            "initial_value_id": node_value_id(self.initial_node),
            "update_value_id": self.update_value_id,
            "update_site_id": self.update_site_id,
            "update_block_id": self.update_block_id,
            "step": self.step,
        }


@dataclass(frozen=True)
class AddressProgression:
    base_node: dict[str, Any]
    recurrence: Recurrence
    stride: int
    address_value_id: str
    address_site_id: str

    def as_json(self) -> dict[str, Any]:
        return {
            "base": node_text(self.base_node),
            "base_value_id": node_value_id(self.base_node),
            "base_object_id": node_object_id(self.base_node),
            "recurrence": self.recurrence.as_json(),
            "stride": self.stride,
            "address_value_id": self.address_value_id,
            "address_site_id": self.address_site_id,
        }


@dataclass(frozen=True)
class LoopBound:
    recurrence: Recurrence
    bound_node: dict[str, Any]
    comparison: str
    comparison_site_id: str
    branch_site_id: str
    branch_block_id: str

    def as_json(self) -> dict[str, Any]:
        return {
            "recurrence": self.recurrence.as_json(),
            "bound": node_text(self.bound_node),
            "bound_value_id": node_value_id(self.bound_node),
            "bound_object_id": node_object_id(self.bound_node),
            "bound_constant": node_constant(self.bound_node),
            "comparison": self.comparison,
            "comparison_site_id": self.comparison_site_id,
            "branch_site_id": self.branch_site_id,
            "branch_block_id": self.branch_block_id,
        }


class FunctionCFG:
    """Index one function's High P-code, SSA definitions, and natural loops."""

    def __init__(
        self,
        function: dict[str, Any],
        *,
        blocks: dict[str, dict[str, Any]],
        successors: dict[str, set[str]],
        predecessors: dict[str, set[str]],
        ops_by_block: dict[str, list[dict[str, Any]]],
    ) -> None:
        self.function = function
        self.function_id = str(function.get("function_id", ""))
        self.blocks = blocks
        self.successors = successors
        self.predecessors = predecessors
        self.ops_by_block = ops_by_block
        self.ops = [dict(op) for op in list(function.get("pcode_ops", []) or [])]
        self.definitions: dict[str, dict[str, Any]] = {}
        self.uses: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.op_by_site: dict[str, dict[str, Any]] = {}
        for op in self.ops:
            site_id = str(op.get("site_id", ""))
            if site_id:
                self.op_by_site[site_id] = op
            output_id = node_value_id(dict(op.get("output", {}) or {}))
            if output_id:
                self.definitions[output_id] = op
            for item in list(op.get("inputs", []) or []):
                value_id = node_value_id(dict(item))
                if value_id:
                    self.uses[value_id].append(op)
        self.entry = self._entry_block()
        self.reachable_blocks = self._reachable_blocks()
        self.dominators = self._dominators()
        self.loops = self._natural_loops()

    @classmethod
    def build(
        cls, function: dict[str, Any]
    ) -> tuple["FunctionCFG | None", list[AnalysisBlocker]]:
        function_id = str(function.get("function_id", ""))
        raw_blocks = list(function.get("basic_blocks", []) or [])
        if not raw_blocks:
            return None, [
                AnalysisBlocker(
                    "missing_cfg_basic_blocks",
                    "Function has flat High P-code but no basic_blocks graph.",
                    function_id,
                )
            ]

        blocks: dict[str, dict[str, Any]] = {}
        for position, raw in enumerate(raw_blocks):
            row = dict(raw)
            block_id = str(row.get("block_id", "") or row.get("id", ""))
            if not block_id:
                block_id = f"block:{function_id}:{row.get('index', position)}"
                row["block_id"] = block_id
            if block_id in blocks:
                return None, [
                    AnalysisBlocker(
                        "duplicate_cfg_block_id",
                        f"Duplicate basic block identifier {block_id}.",
                        function_id,
                    )
                ]
            blocks[block_id] = row

        successors: dict[str, set[str]] = {block_id: set() for block_id in blocks}
        for block_id, row in blocks.items():
            raw_successors = list(
                row.get("successor_block_ids", row.get("successors", [])) or []
            )
            for key in (
                "true_successor_block_id",
                "false_successor_block_id",
                "true_successor",
                "false_successor",
            ):
                if row.get(key):
                    raw_successors.append(row[key])
            for raw_target in raw_successors:
                target = block_ref(raw_target)
                if target and target in blocks:
                    successors[block_id].add(target)

        predecessors: dict[str, set[str]] = {block_id: set() for block_id in blocks}
        for source, targets in successors.items():
            for target in targets:
                predecessors[target].add(source)

        ops_by_block: dict[str, list[dict[str, Any]]] = defaultdict(list)
        missing_block_sites: list[str] = []
        for op in list(function.get("pcode_ops", []) or []):
            block_id = str(op.get("block_id", ""))
            if not block_id or block_id not in blocks:
                missing_block_sites.append(str(op.get("site_id", "") or "<unknown>"))
                continue
            ops_by_block[block_id].append(dict(op))
        if missing_block_sites:
            return None, [
                AnalysisBlocker(
                    "pcode_op_missing_block_id",
                    "At least one High P-code operation is not bound to a known basic block.",
                    function_id,
                    tuple(missing_block_sites[:8]),
                )
            ]

        for rows in ops_by_block.values():
            rows.sort(
                key=lambda op: (
                    parse_int(op.get("instruction_address")) or -1,
                    int(op.get("op_order", -1) or -1),
                )
            )
        return cls(
            function,
            blocks=blocks,
            successors=successors,
            predecessors=predecessors,
            ops_by_block=dict(ops_by_block),
        ), []

    def _entry_block(self) -> str:
        no_predecessor = [
            block_id for block_id in self.blocks if not self.predecessors[block_id]
        ]
        candidates = no_predecessor or list(self.blocks)
        return min(
            candidates,
            key=lambda block_id: (
                int(self.blocks[block_id].get("index", 1 << 30) or 1 << 30),
                parse_int(self.blocks[block_id].get("start")) or 1 << 62,
                block_id,
            ),
        )

    def _dominators(self) -> dict[str, set[str]]:
        all_blocks = set(self.reachable_blocks)
        dom = {
            block_id: (
                {block_id}
                if block_id == self.entry or block_id not in self.reachable_blocks
                else set(all_blocks)
            )
            for block_id in self.blocks
        }
        changed = True
        while changed:
            changed = False
            for block_id in self.blocks:
                if block_id == self.entry:
                    continue
                if block_id not in self.reachable_blocks:
                    continue
                preds = self.predecessors[block_id]
                inherited = (
                    set.intersection(*(dom[pred] for pred in preds))
                    if preds
                    else set()
                )
                updated = {block_id} | inherited
                if updated != dom[block_id]:
                    dom[block_id] = updated
                    changed = True
        return dom

    def _reachable_blocks(self) -> set[str]:
        queue = deque([self.entry])
        seen: set[str] = set()
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(self.successors.get(current, ()))
        return seen

    def _natural_loops(self) -> list[NaturalLoop]:
        by_header: dict[str, dict[str, Any]] = {}
        for tail, targets in self.successors.items():
            if tail not in self.reachable_blocks:
                continue
            for header in targets:
                if header not in self.reachable_blocks:
                    continue
                if header not in self.dominators.get(tail, set()):
                    continue
                region = {header, tail}
                # A self-loop contains only its header before predecessor
                # closure.  Seeding the header itself would incorrectly pull
                # the preheader into the natural loop.
                queue = deque([] if tail == header else [tail])
                while queue:
                    current = queue.popleft()
                    for pred in self.predecessors[current]:
                        if pred not in region:
                            region.add(pred)
                            if pred != header:
                                queue.append(pred)
                slot = by_header.setdefault(header, {"tails": set(), "blocks": set()})
                slot["tails"].add(tail)
                slot["blocks"].update(region)

        loops: list[NaturalLoop] = []
        for header, row in by_header.items():
            region = frozenset(row["blocks"])
            exits = tuple(
                sorted(
                    (source, target)
                    for source in region
                    for target in self.successors[source]
                    if target not in region
                )
            )
            loops.append(
                NaturalLoop(
                    header=header,
                    tails=tuple(sorted(row["tails"])),
                    blocks=region,
                    exits=exits,
                )
            )
        return sorted(loops, key=lambda loop: loop.header)

    def op_block(self, op: dict[str, Any]) -> str:
        return str(op.get("block_id", ""))

    def loop_ops(self, loop: NaturalLoop) -> list[dict[str, Any]]:
        return [
            op
            for block_id in loop.blocks
            for op in self.ops_by_block.get(block_id, [])
        ]

    def block_reaches(self, source: str, target: str, *, limit: int = 512) -> bool:
        queue = deque([source])
        seen: set[str] = set()
        while queue and len(seen) < limit:
            current = queue.popleft()
            if current == target:
                return True
            if current in seen:
                continue
            seen.add(current)
            queue.extend(self.successors.get(current, ()))
        return False

    def can_coexecute(self, first: str, second: str) -> bool:
        if first == second:
            return True
        # If one block dominates the other, every execution of the latter has
        # observed the former.  This deliberately rejects sibling branch arms.
        return first in self.dominators.get(second, set()) or second in self.dominators.get(
            first, set()
        )

    def controlling_branches(self, loop: NaturalLoop) -> list[dict[str, Any]]:
        rows = []
        for block_id in loop.blocks:
            inside = self.successors[block_id] & set(loop.blocks)
            outside = self.successors[block_id] - set(loop.blocks)
            if not inside or not outside:
                continue
            rows.extend(
                op
                for op in self.ops_by_block.get(block_id, [])
                if str(op.get("mnemonic", "")) == "CBRANCH"
            )
        return rows

    def strip_transparent(self, node: dict[str, Any], *, limit: int = 48) -> dict[str, Any]:
        current = dict(node)
        seen: set[str] = set()
        for _ in range(limit):
            value_id = node_value_id(current)
            if not value_id or value_id in seen:
                break
            seen.add(value_id)
            op = self.definitions.get(value_id)
            if not op or str(op.get("mnemonic", "")) not in VALUE_PRESERVING_OPS:
                break
            inputs = [
                dict(item)
                for item in list(op.get("inputs", []) or [])
                if not bool(item.get("is_constant"))
            ]
            if len(inputs) != 1:
                break
            current = inputs[0]
        return current

    def flows_unchanged(
        self, node: dict[str, Any], target_value_id: str, *, limit: int = 64
    ) -> bool:
        current = dict(node)
        seen: set[str] = set()
        for _ in range(limit):
            value_id = node_value_id(current)
            if value_id == target_value_id:
                return True
            if not value_id or value_id in seen:
                return False
            seen.add(value_id)
            op = self.definitions.get(value_id)
            if not op or str(op.get("mnemonic", "")) not in VALUE_PRESERVING_OPS:
                return False
            inputs = [
                dict(item)
                for item in list(op.get("inputs", []) or [])
                if not bool(item.get("is_constant"))
            ]
            if len(inputs) != 1:
                return False
            current = inputs[0]
        return False

    def unique_load_origin(
        self, node: dict[str, Any], *, limit: int = 64
    ) -> dict[str, Any] | None:
        current = dict(node)
        seen: set[str] = set()
        for _ in range(limit):
            value_id = node_value_id(current)
            if not value_id or value_id in seen:
                return None
            seen.add(value_id)
            op = self.definitions.get(value_id)
            if not op:
                return None
            mnemonic = str(op.get("mnemonic", ""))
            if mnemonic == "LOAD":
                return op
            if mnemonic not in VALUE_PRESERVING_OPS:
                return None
            inputs = [
                dict(item)
                for item in list(op.get("inputs", []) or [])
                if not bool(item.get("is_constant"))
            ]
            if len(inputs) != 1:
                return None
            current = inputs[0]
        return None

    def depends_on(
        self,
        node: dict[str, Any],
        target_value_id: str,
        *,
        allowed_ops: set[str] | None = None,
        limit: int = 128,
    ) -> bool:
        queue = deque([dict(node)])
        seen: set[str] = set()
        steps = 0
        while queue and steps < limit:
            current = queue.popleft()
            steps += 1
            value_id = node_value_id(current)
            if value_id == target_value_id:
                return True
            if not value_id or value_id in seen:
                continue
            seen.add(value_id)
            op = self.definitions.get(value_id)
            if not op:
                continue
            if allowed_ops is not None and str(op.get("mnemonic", "")) not in allowed_ops:
                continue
            queue.extend(dict(item) for item in list(op.get("inputs", []) or []))
        return False

    def loop_invariant(self, node: dict[str, Any], loop: NaturalLoop) -> bool:
        queue = deque([dict(node)])
        seen: set[str] = set()
        while queue:
            current = queue.popleft()
            value_id = node_value_id(current)
            if not value_id or value_id in seen:
                continue
            seen.add(value_id)
            op = self.definitions.get(value_id)
            if not op:
                continue
            if self.op_block(op) in loop.blocks:
                return False
            queue.extend(dict(item) for item in list(op.get("inputs", []) or []))
        return True

    def recurrences(self, loop: NaturalLoop) -> list[Recurrence]:
        rows: list[Recurrence] = []
        for phi in self.ops_by_block.get(loop.header, []):
            if str(phi.get("mnemonic", "")) != "MULTIEQUAL":
                continue
            output_id = node_value_id(dict(phi.get("output", {}) or {}))
            if not output_id:
                continue
            update_candidates: list[tuple[dict[str, Any], int]] = []
            initial_candidates: list[dict[str, Any]] = []
            for raw_input in list(phi.get("inputs", []) or []):
                item = dict(raw_input)
                update = self.definitions.get(node_value_id(item))
                step = self._recurrence_step(update, output_id) if update else None
                if (
                    update
                    and step not in (None, 0)
                    and self.op_block(update) in loop.blocks
                ):
                    update_candidates.append((update, int(step)))
                else:
                    initial_candidates.append(item)
            if len(update_candidates) != 1 or len(initial_candidates) != 1:
                continue
            update, step = update_candidates[0]
            rows.append(
                Recurrence(
                    phi_value_id=output_id,
                    phi_site_id=str(phi.get("site_id", "")),
                    header_block_id=loop.header,
                    initial_node=initial_candidates[0],
                    update_value_id=node_value_id(dict(update.get("output", {}) or {})),
                    update_site_id=str(update.get("site_id", "")),
                    update_block_id=self.op_block(update),
                    step=step,
                )
            )
        return rows

    def _recurrence_step(
        self, op: dict[str, Any] | None, phi_value_id: str
    ) -> int | None:
        if not op:
            return None
        mnemonic = str(op.get("mnemonic", ""))
        inputs = [dict(item) for item in list(op.get("inputs", []) or [])]
        if mnemonic == "INT_ADD" and len(inputs) == 2:
            if self.flows_unchanged(inputs[0], phi_value_id):
                return node_constant(inputs[1])
            if self.flows_unchanged(inputs[1], phi_value_id):
                return node_constant(inputs[0])
        if mnemonic == "INT_SUB" and len(inputs) == 2:
            if self.flows_unchanged(inputs[0], phi_value_id):
                value = node_constant(inputs[1])
                return -value if value is not None else None
        if mnemonic == "PTRADD" and len(inputs) >= 3:
            if not self.flows_unchanged(inputs[0], phi_value_id):
                return None
            index = node_signed_constant(inputs[1])
            scale = node_constant(inputs[2])
            if index is not None and scale is not None:
                return index * scale
        return None

    def address_progression(
        self,
        node: dict[str, Any],
        loop: NaturalLoop,
        recurrences: Iterable[Recurrence],
    ) -> AddressProgression | None:
        recurrences_by_id = {row.phi_value_id: row for row in recurrences}
        recurrences_by_update_id = {
            row.update_value_id: row for row in recurrences
        }
        current = self.strip_transparent(node)
        current_id = node_value_id(current)
        if current_id in recurrences_by_id:
            recurrence = recurrences_by_id[current_id]
            return AddressProgression(
                base_node=recurrence.initial_node,
                recurrence=recurrence,
                stride=recurrence.step,
                address_value_id=current_id,
                address_site_id=recurrence.phi_site_id,
            )
        if current_id in recurrences_by_update_id:
            recurrence = recurrences_by_update_id[current_id]
            return AddressProgression(
                base_node=recurrence.initial_node,
                recurrence=recurrence,
                stride=recurrence.step,
                address_value_id=current_id,
                address_site_id=recurrence.update_site_id,
            )

        op = self.definitions.get(current_id)
        if not op or str(op.get("mnemonic", "")) not in ADDRESS_OPS:
            return None
        inputs = [dict(item) for item in list(op.get("inputs", []) or [])]
        if len(inputs) < 2:
            return None
        mnemonic = str(op.get("mnemonic", ""))
        scale = 1
        if mnemonic == "PTRADD":
            if len(inputs) < 3:
                return None
            scale_value = node_constant(inputs[2])
            if scale_value is None:
                return None
            scale = scale_value
        for position in (0, 1):
            candidate = self.strip_transparent(inputs[position])
            recurrence = recurrences_by_id.get(node_value_id(candidate))
            if recurrence is None:
                continue
            if mnemonic == "INT_SUB" and position == 1:
                return None
            base_position = 1 - position
            return AddressProgression(
                base_node=inputs[base_position],
                recurrence=recurrence,
                stride=recurrence.step * scale,
                address_value_id=current_id,
                address_site_id=str(op.get("site_id", "")),
            )
        return None

    def loop_bounds(
        self, loop: NaturalLoop, recurrences: Iterable[Recurrence]
    ) -> list[LoopBound]:
        rows: list[LoopBound] = []
        for branch in self.controlling_branches(loop):
            branch_inputs = [dict(item) for item in list(branch.get("inputs", []) or [])]
            if not branch_inputs:
                continue
            condition = self.strip_transparent(branch_inputs[-1])
            comparison = self.definitions.get(node_value_id(condition))
            if not comparison or str(comparison.get("mnemonic", "")) not in COMPARISON_OPS:
                continue
            parts = [dict(item) for item in list(comparison.get("inputs", []) or [])]
            if len(parts) != 2:
                continue
            for recurrence in recurrences:
                lineage_ops = VALUE_PRESERVING_OPS | {
                    "INT_ADD",
                    "INT_SUB",
                    "PTRADD",
                    "PTRSUB",
                }
                left = self.depends_on(
                    parts[0], recurrence.phi_value_id, allowed_ops=lineage_ops
                )
                right = self.depends_on(
                    parts[1], recurrence.phi_value_id, allowed_ops=lineage_ops
                )
                if left == right:
                    continue
                bound = parts[1] if left else parts[0]
                rows.append(
                    LoopBound(
                        recurrence=recurrence,
                        bound_node=bound,
                        comparison=str(comparison.get("mnemonic", "")),
                        comparison_site_id=str(comparison.get("site_id", "")),
                        branch_site_id=str(branch.get("site_id", "")),
                        branch_block_id=self.op_block(branch),
                    )
                )
        return rows

    def formal_access(
        self, node: dict[str, Any], *, limit: int = 64
    ) -> tuple[int, tuple[int, ...]] | None:
        memo: dict[str, tuple[int, tuple[int, ...]] | None] = {}
        active: set[str] = set()

        def visit(
            current: dict[str, Any], depth: int
        ) -> tuple[int, tuple[int, ...]] | None:
            if depth > limit:
                return None
            slot = current.get("parameter_slot")
            if isinstance(slot, int):
                return slot, ()
            object_id = node_object_id(current)
            if object_id.startswith("param:"):
                try:
                    return int(object_id.rsplit(":", 1)[1]), ()
                except ValueError:
                    return None
            value_id = node_value_id(current)
            if not value_id or value_id in active:
                return None
            if value_id in memo:
                return memo[value_id]
            active.add(value_id)
            op = self.definitions.get(value_id)
            result: tuple[int, tuple[int, ...]] | None = None
            if op:
                mnemonic = str(op.get("mnemonic", ""))
                inputs = [dict(item) for item in list(op.get("inputs", []) or [])]
                if mnemonic in VALUE_PRESERVING_OPS:
                    candidates = {
                        candidate
                        for candidate in (visit(item, depth + 1) for item in inputs)
                        if candidate is not None
                    }
                    if len(candidates) == 1:
                        result = next(iter(candidates))
                elif mnemonic in {"PTRSUB", "INT_ADD"} and len(inputs) >= 2:
                    base = visit(inputs[0], depth + 1)
                    offset = node_signed_constant(inputs[1])
                    if base is not None and offset is not None:
                        result = (base[0], base[1] + (int(offset),))
                elif mnemonic == "PTRADD" and len(inputs) >= 3:
                    base = visit(inputs[0], depth + 1)
                    index = node_signed_constant(inputs[1])
                    scale = node_constant(inputs[2])
                    if base is not None and index is not None and scale is not None:
                        result = (base[0], base[1] + (int(index * scale),))
            active.remove(value_id)
            memo[value_id] = result
            return result

        return visit(dict(node), 0)


def comparison_for_branch(
    cfg: FunctionCFG, branch: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
    inputs = [dict(item) for item in list(branch.get("inputs", []) or [])]
    if not inputs:
        return None
    condition = cfg.strip_transparent(inputs[-1])
    comparison = cfg.definitions.get(node_value_id(condition))
    if not comparison or str(comparison.get("mnemonic", "")) not in COMPARISON_OPS:
        return None
    parts = [dict(item) for item in list(comparison.get("inputs", []) or [])]
    return (comparison, parts) if len(parts) == 2 else None
