#!/usr/bin/env python3
"""Deterministic software-interface Source summaries over Ghidra High P-code.

The engine separates two facts that name-only source lists often conflate:

* an API/body summary states *which output* receives external data;
* a call binding states *which ValueId/ObjectId* is that output at this site.

Only summaries with an audited contract or a body-proved hardware provenance
are instantiated.  Token/name heuristics are deliberately outside this file.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


TRANSPARENT_OPS = {
    "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "INDIRECT",
    "PTRSUB", "PTRADD", "INT_ADD",
}


def stable_id(prefix: str, *parts: Any) -> str:
    payload = "\x1f".join(str(part or "") for part in parts).encode("utf-8", "replace")
    return f"{prefix}:{hashlib.sha256(payload).hexdigest()[:20]}"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def node_value_id(node: dict[str, Any] | None) -> str:
    return str((node or {}).get("value_id", ""))


def node_object_id(node: dict[str, Any] | None) -> str:
    return str((node or {}).get("object_id", ""))


def node_name(node: dict[str, Any] | None) -> str:
    return str((node or {}).get("high_name", ""))


def parse_int(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def parameter_slot(node: dict[str, Any], definitions: dict[str, dict[str, Any]]) -> int | None:
    seen: set[str] = set()
    queue: deque[dict[str, Any]] = deque([node])
    while queue:
        current = queue.popleft()
        value_id = node_value_id(current)
        if value_id and value_id in seen:
            continue
        if value_id:
            seen.add(value_id)
        slot = current.get("parameter_slot")
        if isinstance(slot, int):
            return slot
        object_id = node_object_id(current)
        if object_id.startswith("param:"):
            try:
                return int(object_id.rsplit(":", 1)[1])
            except ValueError:
                pass
        op = definitions.get(value_id)
        if not op or str(op.get("mnemonic", "")) not in TRANSPARENT_OPS:
            continue
        for item in list(op.get("inputs", []) or []):
            if not bool(item.get("is_constant")):
                queue.append(dict(item))
    return None


def depends_on_value(
    node: dict[str, Any], target_value_id: str, definitions: dict[str, dict[str, Any]], *, limit: int = 128
) -> bool:
    queue: deque[dict[str, Any]] = deque([node])
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
        op = definitions.get(value_id)
        if not op:
            continue
        for item in list(op.get("inputs", []) or []):
            if not bool(item.get("is_constant")):
                queue.append(dict(item))
    return False


def _normalized_type(value: Any) -> str:
    text = str(value or "")
    text = text.replace("*", " ")
    for token in ("const", "volatile", "restrict", "struct", "typedef"):
        text = re.sub(rf"\b{token}\b", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _constant_node_value(node: dict[str, Any]) -> int | None:
    if not bool(node.get("is_constant")):
        return None
    return parse_int(node.get("offset"))


def field_signature(
    pointer: dict[str, Any], definitions: dict[str, dict[str, Any]]
) -> tuple[str, int] | None:
    """Return a typed state-field identity for one exact address expression."""

    op = definitions.get(node_value_id(pointer))
    if not op or str(op.get("mnemonic", "")) not in {"PTRSUB", "PTRADD", "INT_ADD"}:
        return None
    inputs = list(op.get("inputs", []) or [])
    if len(inputs) < 2:
        return None
    base = dict(inputs[0])
    if str(op.get("mnemonic", "")) == "PTRADD" and len(inputs) >= 3:
        index = _constant_node_value(dict(inputs[1]))
        scale = _constant_node_value(dict(inputs[2]))
        offset = index * scale if index is not None and scale is not None else None
    else:
        offset = _constant_node_value(dict(inputs[1]))
    base_type = _normalized_type(base.get("high_data_type", ""))
    if offset is None or not base_type or base_type in {
        "void", "undefined", "undefined4", "int", "uint", "char", "byte",
    }:
        return None
    return base_type, int(offset)


def formal_access_path(
    node: dict[str, Any],
    definitions: dict[str, dict[str, Any]],
    *,
    limit: int = 96,
) -> tuple[int, tuple[int, ...]] | None:
    """Recover ``formal -> exact dereference offsets`` from High P-code."""

    memo: dict[str, tuple[int, tuple[int, ...]] | None] = {}
    active: set[str] = set()

    def visit(current: dict[str, Any], depth: int) -> tuple[int, tuple[int, ...]] | None:
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
        op = definitions.get(value_id)
        result: tuple[int, tuple[int, ...]] | None = None
        if op:
            mnemonic = str(op.get("mnemonic", ""))
            inputs = [dict(item) for item in list(op.get("inputs", []) or [])]
            if mnemonic in TRANSPARENT_OPS | {"MULTIEQUAL"}:
                candidates = {
                    candidate for candidate in (visit(item, depth + 1) for item in inputs)
                    if candidate is not None
                }
                if len(candidates) == 1:
                    result = next(iter(candidates))
            elif mnemonic == "LOAD" and len(inputs) >= 2:
                address = inputs[1]
                address_op = definitions.get(node_value_id(address))
                if address_op and str(address_op.get("mnemonic", "")) in {
                    "PTRSUB", "PTRADD", "INT_ADD",
                }:
                    parts = [dict(item) for item in list(address_op.get("inputs", []) or [])]
                    base = visit(parts[0], depth + 1) if parts else None
                    offset: int | None = None
                    if str(address_op.get("mnemonic", "")) == "PTRADD" and len(parts) >= 3:
                        index = _constant_node_value(parts[1])
                        scale = _constant_node_value(parts[2])
                        if index is not None and scale is not None:
                            offset = index * scale
                    elif len(parts) >= 2:
                        offset = _constant_node_value(parts[1])
                    if base is not None and offset is not None:
                        result = (base[0], base[1] + (int(offset),))
        active.remove(value_id)
        memo[value_id] = result
        return result

    return visit(node, 0)


def upstream_state_fields(
    node: dict[str, Any], definitions: dict[str, dict[str, Any]], *, limit: int = 192
) -> set[tuple[str, int]]:
    """Find typed state fields from which a destination pointer was loaded."""

    queue: deque[dict[str, Any]] = deque([node])
    seen: set[str] = set()
    result: set[tuple[str, int]] = set()
    steps = 0
    while queue and steps < limit:
        current = queue.popleft()
        steps += 1
        value_id = node_value_id(current)
        if not value_id or value_id in seen:
            continue
        seen.add(value_id)
        op = definitions.get(value_id)
        if not op:
            continue
        mnemonic = str(op.get("mnemonic", ""))
        inputs = [dict(item) for item in list(op.get("inputs", []) or [])]
        if mnemonic == "LOAD" and len(inputs) >= 2:
            signature = field_signature(inputs[1], definitions)
            if signature:
                result.add(signature)
            continue
        if mnemonic in TRANSPARENT_OPS | {"MULTIEQUAL"}:
            queue.extend(item for item in inputs if not bool(item.get("is_constant")))
    return result


@dataclass(frozen=True)
class OutputSpec:
    role: str
    binding_kind: str
    parameter_slot: int | None = None
    size_parameter_slot: int | None = None
    access_path: tuple[int, ...] = ()
    extent_for_role: str = ""


@dataclass
class FunctionSummary:
    summary_id: str
    function_names: tuple[str, ...]
    channel: str
    outputs: tuple[OutputSpec, ...]
    proof_kind: str
    min_args: int = 0
    max_args: int | None = None
    descriptor_parameter_slot: int | None = None
    descriptor_required: bool = False
    compatibility_scope: str = "standard_abi"
    function_id: str = ""
    provenance: list[dict[str, Any]] = field(default_factory=list)

    def accepts_arity(self, arity: int) -> bool:
        return arity >= self.min_args and (self.max_args is None or arity <= self.max_args)


def _summary_rows(pack: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("summaries", "api_summaries", "source_summaries"):
        value = pack.get(key)
        if isinstance(value, list):
            return [dict(row) for row in value]
    return []


def parse_summary_pack(
    pack: dict[str, Any], *, include_compatibility_specific: bool = False
) -> list[FunctionSummary]:
    summaries: list[FunctionSummary] = []
    for row in _summary_rows(pack):
        if row.get("summary_kind") and row.get("summary_kind") != "source":
            continue
        if (
            (row.get("compatibility_specific") or row.get("core_eligible") is False)
            and not include_compatibility_specific
        ):
            continue
        match = dict(row.get("match", {}) or {})
        names = (
            row.get("function_names")
            or row.get("names")
            or match.get("symbol_names")
            or ([row.get("name")] if row.get("name") else [])
            or ([row.get("function_name")] if row.get("function_name") else [])
        )
        outputs = []
        for output in list(row.get("outputs", []) or []):
            extent_for_role = str(output.get("extent_for_role", ""))
            if (
                "external_data" in output
                and not bool(output.get("external_data"))
                and not extent_for_role
            ):
                continue
            slot = output.get(
                "parameter_slot",
                output.get("arg_index", output.get("argument_index")),
            )
            size_slot = output.get("size_parameter_slot", output.get("size_arg_index"))
            carrier = str(output.get("carrier", ""))
            binding_kind = str(output.get("binding_kind", output.get("kind", "")))
            if not binding_kind:
                binding_kind = {
                    "argument_pointee": "formal_pointee",
                    "return": "return_value",
                    "return_pointee": "return_pointer",
                }.get(carrier, carrier or "formal_pointee")
            outputs.append(OutputSpec(
                role=str(output.get("role", "output_buffer")),
                binding_kind=binding_kind,
                parameter_slot=int(slot) if isinstance(slot, int) else None,
                size_parameter_slot=int(size_slot) if isinstance(size_slot, int) else None,
                access_path=tuple(
                    int(item, 0) if isinstance(item, str) else int(item)
                    for item in list(output.get("access_path", []) or [])
                ),
                extent_for_role=extent_for_role,
            ))
        available_extent = dict(row.get("available_extent", {}) or {})
        extent_carrier = str(available_extent.get("carrier", ""))
        extent_for_role = str(
            available_extent.get("extent_for_role", "output_buffer")
        )
        if extent_carrier in {"return", "return_value"}:
            outputs.append(
                OutputSpec(
                    role="available_length",
                    binding_kind="return_value",
                    extent_for_role=extent_for_role,
                )
            )
        elif extent_carrier in {"argument", "argument_value"}:
            extent_slot = available_extent.get(
                "argument_index", available_extent.get("parameter_slot")
            )
            if isinstance(extent_slot, int):
                outputs.append(
                    OutputSpec(
                        role="available_length",
                        binding_kind="formal_value",
                        parameter_slot=extent_slot,
                        extent_for_role=extent_for_role,
                    )
                )
        if not names or not outputs:
            continue
        descriptor = dict(row.get("descriptor", {}) or {})
        handle_provenance = dict(row.get("handle_provenance", {}) or {})
        if "consumes_argument" in handle_provenance:
            descriptor.setdefault("parameter_slot", handle_provenance.get("consumes_argument"))
            # Mango records unknown handles. CopperTrace's generalized core
            # requires provenance only for generic descriptor APIs such as
            # read; recv/recvfrom already establish a network boundary.
            descriptor.setdefault("provenance_required", str(row.get("name", "")) == "read")
        descriptor_slot = descriptor.get("parameter_slot", descriptor.get("arg_index"))
        calling = dict(row.get("calling_convention", {}) or {})
        declared_count = calling.get("declared_argument_count")
        if isinstance(declared_count, int):
            match.setdefault("min_args", declared_count)
            match.setdefault("max_args", declared_count)
        max_args = match.get("max_args", row.get("max_args"))
        channel_row = row.get("source_channel", {})
        channel = (
            str(channel_row.get("kind", ""))
            if isinstance(channel_row, dict)
            else str(channel_row or "")
        )
        summaries.append(FunctionSummary(
            summary_id=str(row.get("summary_id", row.get("id", ""))) or stable_id("summary", names),
            function_names=tuple(str(name) for name in names if name),
            channel=str(row.get("channel", channel or "external_input")),
            outputs=tuple(outputs),
            proof_kind=str(row.get("proof_kind", row.get("confirmation", "trusted_api_contract"))),
            min_args=int(match.get("min_args", row.get("min_args", 0)) or 0),
            max_args=int(max_args) if isinstance(max_args, int) else None,
            descriptor_parameter_slot=(int(descriptor_slot) if isinstance(descriptor_slot, int) else None),
            descriptor_required=bool(descriptor.get("provenance_required", row.get("descriptor_required", False))),
            compatibility_scope=str(
                row.get("compatibility_scope", match.get("scope", "standard_abi"))
            ),
            provenance=list(row.get("provenance", []) or []),
        ))
    return summaries


class ProgramIndex:
    def __init__(self, facts: dict[str, Any]):
        self.facts = facts
        self.functions = list(facts.get("functions", []) or [])
        self.by_id = {str(f.get("function_id", "")): f for f in self.functions if f.get("function_id")}
        self.by_entry: dict[int, dict[str, Any]] = {}
        self.by_name: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.symbols_by_address: dict[int, list[dict[str, Any]]] = defaultdict(list)
        for symbol in list(facts.get("symbols", []) or []):
            address = parse_int(symbol.get("address"))
            if address is not None:
                self.symbols_by_address[address].append(dict(symbol))
        resolved_dispatches = list(
            (facts.get("device_dispatch_resolution", {}) or {}).get("resolved", []) or []
        )
        self.resolved_indirect_targets: dict[str, str] = {
            str((row.get("callsite") or {}).get("site_id", "")):
                str((row.get("target") or {}).get("function_id", ""))
            for row in resolved_dispatches
            if str((row.get("callsite") or {}).get("site_id", ""))
            and str((row.get("target") or {}).get("function_id", ""))
        }
        self.resolved_indirect_identity_bindings: dict[str, list[dict[str, Any]]] = {
            str((row.get("callsite") or {}).get("site_id", "")):
                [dict(binding) for binding in list(row.get("formal_identity_bindings", []) or [])]
            for row in resolved_dispatches
            if str((row.get("callsite") or {}).get("site_id", ""))
            and list(row.get("formal_identity_bindings", []) or [])
        }
        self.definitions_by_function: dict[str, dict[str, dict[str, Any]]] = {}
        self.returns_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.stores_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.readonly_pointer_words = {
            int(str(address), 0): int(str(value), 0)
            for address, value in dict(facts.get("elf_readonly_pointer_words", {}) or {}).items()
        }
        self.calls: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for function in self.functions:
            function_id = str(function.get("function_id", ""))
            entry = parse_int(function.get("entry"))
            if entry is not None:
                self.by_entry[entry & ~1] = function
            self.by_name[str(function.get("name", ""))].append(function)
            definitions: dict[str, dict[str, Any]] = {}
            for op in list(function.get("pcode_ops", []) or []):
                output = dict(op.get("output", {}) or {})
                if node_value_id(output):
                    definitions[node_value_id(output)] = op
                mnemonic = str(op.get("mnemonic", ""))
                if mnemonic == "RETURN":
                    self.returns_by_function[function_id].append(op)
                if mnemonic == "STORE":
                    self.stores_by_function[function_id].append(op)
                if mnemonic in {"CALL", "CALLIND"}:
                    self.calls.append((function, op))
            self.definitions_by_function[function_id] = definitions
        self.function_pointer_targets_by_location: dict[int, set[int]] = defaultdict(set)
        for function in self.functions:
            function_id = str(function.get("function_id", ""))
            for op in list(function.get("pcode_ops", []) or []):
                if str(op.get("mnemonic", "")) != "STORE":
                    continue
                inputs = list(op.get("inputs", []) or [])
                if len(inputs) < 3:
                    continue
                location = self.resolve_constant(function_id, dict(inputs[-2]))
                target = self.resolve_constant(function_id, dict(inputs[-1]))
                if location is not None and target is not None and (target & ~1) in self.by_entry:
                    self.function_pointer_targets_by_location[location].add(target & ~1)

    def exact_named_function(self, name: str) -> dict[str, Any] | None:
        rows = self.by_name.get(name, [])
        return rows[0] if len(rows) == 1 else None

    def concrete_object_binding(
        self, function_id: str, node: dict[str, Any]
    ) -> dict[str, Any] | None:
        address = self.resolve_constant(function_id, node)
        if address is None:
            return None
        symbols = [
            row for row in self.symbols_by_address.get(address, [])
            if str(row.get("type", "")).lower() != "function"
        ]
        if len(symbols) == 1:
            symbol = symbols[0]
            return {
                "expression": str(symbol.get("name", "")) or f"RAM@0x{address:x}",
                "object_id": str(symbol.get("object_id", "")) or f"global:{address:08x}",
                "address": address,
                "symbol": str(symbol.get("name", "")),
            }
        return {
            "expression": f"RAM@0x{address:x}",
            "object_id": f"global:{address:08x}:unknown",
            "address": address,
            "symbol": "",
        }

    def resolve_constant(self, function_id: str, node: dict[str, Any], *, limit: int = 64) -> int | None:
        definitions = self.definitions_by_function.get(function_id, {})
        queue: deque[dict[str, Any]] = deque([node])
        seen: set[str] = set()
        steps = 0
        values: set[int] = set()
        while queue and steps < limit:
            current = queue.popleft()
            steps += 1
            value_id = node_value_id(current)
            if value_id and value_id in seen:
                continue
            if value_id:
                seen.add(value_id)
            if bool(current.get("is_constant")):
                value = parse_int(current.get("offset"))
                if value is not None:
                    values.add(value)
                continue
            if bool(current.get("is_address")):
                value = parse_int(current.get("offset"))
                if value is not None and (value & ~1) in self.by_entry:
                    values.add(value)
                    continue
            initial = parse_int(current.get("initial_memory_value"))
            if initial is not None:
                values.add(initial)
                continue
            op = definitions.get(value_id)
            if not op:
                continue
            mnemonic = str(op.get("mnemonic", ""))
            inputs = list(op.get("inputs", []) or [])
            if mnemonic in {"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "INDIRECT"}:
                queue.extend(dict(item) for item in inputs if not bool(item.get("is_constant")))
            elif mnemonic in {"PTRADD", "PTRSUB", "INT_ADD"}:
                parts = [self.resolve_constant(function_id, dict(item), limit=16) for item in inputs]
                if parts and all(part is not None for part in parts):
                    if mnemonic == "PTRADD" and len(parts) >= 3:
                        values.add(int(parts[0]) + int(parts[1]) * int(parts[2]))
                    else:
                        values.add(sum(int(part) for part in parts if part is not None))
            elif mnemonic == "LOAD" and len(inputs) >= 2:
                address = self.resolve_constant(function_id, dict(inputs[1]), limit=16)
                if address is not None:
                    # Literal enrichment is authoritative only when attached to
                    # the address node by the ELF reader.
                    initial = parse_int(inputs[1].get("initial_memory_value"))
                    if initial is not None:
                        values.add(initial)
        return next(iter(values)) if len(values) == 1 else None

    def resolve_call_target(self, function: dict[str, Any], op: dict[str, Any]) -> dict[str, Any] | None:
        call = dict(op.get("call", {}) or {})
        target_id = str(call.get("target_function_id", ""))
        if target_id and target_id in self.by_id:
            return self.by_id[target_id]
        if str(op.get("mnemonic", "")) != "CALLIND":
            return None
        resolved_id = self.resolved_indirect_targets.get(str(op.get("site_id", "")), "")
        if resolved_id in self.by_id:
            return self.by_id[resolved_id]
        inputs = list(op.get("inputs", []) or [])
        if not inputs:
            return None
        function_id = str(function.get("function_id", ""))
        address = self.resolve_constant(function_id, dict(inputs[0]))
        if address is not None and (address & ~1) in self.by_entry:
            return self.by_entry[address & ~1]
        definitions = self.definitions_by_function.get(function_id, {})
        target_def = definitions.get(node_value_id(dict(inputs[0])))
        if target_def and str(target_def.get("mnemonic", "")) == "LOAD":
            load_inputs = list(target_def.get("inputs", []) or [])
            if len(load_inputs) >= 2:
                location = self.resolve_constant(function_id, dict(load_inputs[1]))
                candidates = self.function_pointer_targets_by_location.get(location or -1, set())
                if len(candidates) == 1:
                    return self.by_entry[next(iter(candidates))]
        return None

    def call_actuals(
        self, function: dict[str, Any], op: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Return explicit CALL actuals or exact ABI-preserving dispatch actuals."""

        explicit = [dict(item) for item in list(op.get("inputs", []) or [])[1:]]
        if explicit:
            return explicit
        bindings = self.resolved_indirect_identity_bindings.get(
            str(op.get("site_id", "")), []
        )
        if not bindings:
            return []
        input_nodes: dict[int, dict[str, Any]] = {}
        for candidate_op in list(function.get("pcode_ops", []) or []):
            nodes = list(candidate_op.get("inputs", []) or [])
            if candidate_op.get("output"):
                nodes.append(candidate_op["output"])
            for node in nodes:
                slot = node.get("parameter_slot")
                if isinstance(slot, int) and slot not in input_nodes:
                    input_nodes[slot] = dict(node)
        parameters = {
            int(parameter.get("index")): dict(parameter)
            for parameter in list(function.get("parameters", []) or [])
            if isinstance(parameter.get("index"), int)
        }
        by_target: dict[int, dict[str, Any]] = {}
        for binding in bindings:
            caller_slot = binding.get("caller_parameter_slot")
            target_slot = binding.get("target_parameter_slot")
            if not isinstance(caller_slot, int) or not isinstance(target_slot, int):
                return []
            node = input_nodes.get(caller_slot)
            if node is None:
                parameter = parameters.get(caller_slot)
                if parameter is None:
                    return []
                object_id = str(parameter.get("object_id", ""))
                node = {
                    "object_id": object_id,
                    "value_id": f"value:{function.get('entry', '')}:{object_id}:input",
                    "high_name": str(parameter.get("name", "")),
                    "high_data_type": str(parameter.get("data_type", "")),
                    "is_parameter": True,
                    "parameter_slot": caller_slot,
                    "is_constant": False,
                }
            by_target[target_slot] = node
        if not by_target or sorted(by_target) != list(range(max(by_target) + 1)):
            return []
        return [by_target[slot] for slot in range(max(by_target) + 1)]

    @staticmethod
    def _position(op: dict[str, Any]) -> tuple[int, int]:
        return (
            parse_int(op.get("instruction_address")) or -1,
            int(op.get("op_order", -1) or -1),
        )

    def _last_exact_store(
        self,
        function_id: str,
        address: int,
        before_op: dict[str, Any],
    ) -> dict[str, Any] | None:
        before = self._position(before_op)
        candidates: list[dict[str, Any]] = []
        for store in self.stores_by_function.get(function_id, []):
            if self._position(store) >= before:
                continue
            inputs = list(store.get("inputs", []) or [])
            if len(inputs) < 3:
                continue
            destination = self.resolve_constant(function_id, dict(inputs[-2]))
            if destination == address:
                candidates.append(store)
        if not candidates:
            return None
        # Multiple control-flow definitions require dominance/path analysis.
        # A single exact writer is the deterministic subset used here.
        return candidates[0] if len(candidates) == 1 else None

    @staticmethod
    def _signed_node_constant(node: dict[str, Any]) -> int | None:
        if not bool(node.get("is_constant")):
            return None
        value = parse_int(node.get("offset"))
        size = int(node.get("size", 0) or 0)
        if value is None:
            return None
        if size > 0:
            bits = size * 8
            value &= (1 << bits) - 1
            if value & (1 << (bits - 1)):
                value -= 1 << bits
        return value

    def symbolic_address_form(
        self,
        function_id: str,
        node: dict[str, Any],
        *,
        limit: int = 48,
    ) -> tuple[str, int] | None:
        """Normalize a local address to ``(root ValueId/ObjectId, offset)``."""

        definitions = self.definitions_by_function.get(function_id, {})
        seen: set[str] = set()

        def visit(current: dict[str, Any], depth: int) -> tuple[str, int] | None:
            if depth > limit:
                return None
            value_id = node_value_id(current)
            if value_id and value_id in seen:
                return None
            if value_id:
                seen.add(value_id)
            op = definitions.get(value_id)
            if op is None:
                root = value_id or node_object_id(current)
                return (root, 0) if root and not bool(current.get("is_constant")) else None
            mnemonic = str(op.get("mnemonic", ""))
            inputs = [dict(item) for item in list(op.get("inputs", []) or [])]
            if mnemonic in {"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "INDIRECT"}:
                variable = [item for item in inputs if not bool(item.get("is_constant"))]
                return visit(variable[0], depth + 1) if len(variable) == 1 else None
            if mnemonic == "PTRADD" and len(inputs) >= 3:
                index = self._signed_node_constant(inputs[1])
                scale = self._signed_node_constant(inputs[2])
                base = visit(inputs[0], depth + 1)
                if base is not None and index is not None and scale is not None:
                    return base[0], base[1] + index * scale
                return None
            if mnemonic in {"PTRSUB", "INT_ADD", "INT_SUB"} and len(inputs) >= 2:
                left_constant = self._signed_node_constant(inputs[0])
                right_constant = self._signed_node_constant(inputs[1])
                if right_constant is not None:
                    base = visit(inputs[0], depth + 1)
                    if base is not None:
                        delta = -right_constant if mnemonic == "INT_SUB" else right_constant
                        return base[0], base[1] + delta
                if left_constant is not None and mnemonic == "INT_ADD":
                    base = visit(inputs[1], depth + 1)
                    if base is not None:
                        return base[0], base[1] + left_constant
            return None

        return visit(node, 0)

    def _last_symbolic_store(
        self,
        function_id: str,
        address_form: tuple[str, int],
        before_op: dict[str, Any],
    ) -> dict[str, Any] | None:
        before = self._position(before_op)
        candidates: list[dict[str, Any]] = []
        for store in self.stores_by_function.get(function_id, []):
            if self._position(store) >= before:
                continue
            inputs = list(store.get("inputs", []) or [])
            if len(inputs) < 3:
                continue
            if self.symbolic_address_form(function_id, dict(inputs[-2])) == address_form:
                candidates.append(store)
        # High P-code promotes stack fields to SSA variables.  At a CALL it
        # emits INDIRECT(value, call-op-order) snapshots instead of explicit
        # STOREs.  Match those stack-object definitions by their exact stack
        # offset and require the INDIRECT to name this exact call operation.
        target_offset = int(address_form[1])
        call_address = parse_int(before_op.get("instruction_address"))
        call_order = int(before_op.get("op_order", -1) or -1)
        for op in list(self.by_id.get(function_id, {}).get("pcode_ops", []) or []):
            output = dict(op.get("output", {}) or {})
            object_id = node_object_id(output)
            match = re.fullmatch(rf"stack:{re.escape(function_id.removeprefix('fn:'))}:(-[0-9a-f]+|[0-9a-f]+):\d+", object_id)
            if not match:
                continue
            raw_offset = match.group(1)
            sign = -1 if raw_offset.startswith("-") else 1
            stack_offset = sign * int(raw_offset.lstrip("-"), 16)
            if stack_offset != target_offset:
                continue
            mnemonic = str(op.get("mnemonic", ""))
            position_before = self._position(op) < self._position(before_op)
            indirect_for_call = False
            inputs = list(op.get("inputs", []) or [])
            if mnemonic == "INDIRECT" and len(inputs) >= 2:
                cause = self._signed_node_constant(dict(inputs[1]))
                indirect_for_call = (
                    parse_int(op.get("instruction_address")) == call_address
                    and cause == call_order
                )
            if position_before or indirect_for_call:
                candidates.append(op)
        return candidates[0] if len(candidates) == 1 else None

    def resolve_actual_access(
        self,
        function: dict[str, Any],
        actual: dict[str, Any],
        access_path: tuple[int, ...],
        before_op: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Resolve an exact descriptor path to a caller formal or address."""

        function_id = str(function.get("function_id", ""))
        definitions = self.definitions_by_function.get(function_id, {})
        direct_formal = formal_access_path(actual, definitions)
        concrete = self.resolve_constant(function_id, actual)
        if concrete is not None:
            origin: dict[str, Any] = {"kind": "address", "address": concrete}
        elif direct_formal is not None:
            origin = {
                "kind": "formal",
                "parameter_slot": direct_formal[0],
                "access_path": direct_formal[1],
            }
        else:
            symbolic = self.symbolic_address_form(function_id, actual)
            if symbolic is None:
                return None
            origin = {
                "kind": "symbolic",
                "root": symbolic[0],
                "offset": symbolic[1],
                "node": dict(actual),
            }

        evidence: list[dict[str, Any]] = []
        remaining = list(access_path)
        while remaining:
            offset = remaining.pop(0)
            if origin["kind"] == "formal":
                origin["access_path"] = tuple(origin.get("access_path", ())) + (
                    int(offset), *remaining,
                )
                remaining.clear()
                break
            if origin["kind"] == "address":
                address = int(origin["address"]) + int(offset)
                store = self._last_exact_store(function_id, address, before_op)
                evidence_address = f"0x{address:x}"
            else:
                symbolic_address = (
                    str(origin["root"]), int(origin.get("offset", 0)) + int(offset)
                )
                store = self._last_symbolic_store(
                    function_id, symbolic_address, before_op
                )
                evidence_address = f"{symbolic_address[0]}{symbolic_address[1]:+d}"
            if store is not None:
                store_inputs = list(store.get("inputs", []) or [])
                rhs = dict(
                    store_inputs[-1]
                    if str(store.get("mnemonic", "")) == "STORE"
                    else store_inputs[0]
                )
                rhs_formal = formal_access_path(rhs, definitions)
                rhs_constant = self.resolve_constant(function_id, rhs)
                evidence.append({
                    "kind": "single_exact_store_before_call",
                    "address": evidence_address,
                    "store_site_id": str(store.get("site_id", "")),
                })
                if rhs_formal is not None:
                    origin = {
                        "kind": "formal",
                        "parameter_slot": rhs_formal[0],
                        "access_path": rhs_formal[1],
                    }
                    continue
                if rhs_constant is not None:
                    origin = {"kind": "address", "address": rhs_constant}
                    continue
                rhs_symbolic = self.symbolic_address_form(function_id, rhs)
                if rhs_symbolic is not None:
                    origin = {
                        "kind": "symbolic",
                        "root": rhs_symbolic[0],
                        "offset": rhs_symbolic[1],
                        "node": rhs,
                    }
                    continue
                return None
            if origin["kind"] != "address":
                return None
            value = self.readonly_pointer_words.get(address)
            if value is None:
                return None
            evidence.append({
                "kind": "elf_readonly_pointer_word",
                "address": f"0x{address:x}",
                "value": f"0x{value:x}",
            })
            origin = {"kind": "address", "address": value}
        if origin["kind"] == "symbolic":
            return None
        origin["evidence"] = evidence
        return origin


def _summary_key(
    summary: FunctionSummary,
) -> tuple[str, tuple[tuple[str, str, int | None, tuple[int, ...], str], ...], str]:
    return (
        summary.function_id or "|".join(summary.function_names),
        tuple(
            (
                output.role,
                output.binding_kind,
                output.parameter_slot,
                output.access_path,
                output.extent_for_role,
            )
            for output in summary.outputs
        ),
        summary.channel,
    )


def summaries_from_seed_sources(seed_sources: Iterable[dict[str, Any]]) -> list[FunctionSummary]:
    rows: list[FunctionSummary] = []
    for source in seed_sources:
        if str(source.get("decision", "")) != "ACCEPT_DETERMINISTIC":
            continue
        function_id = str(source.get("function_id", ""))
        proof = dict(source.get("proof", {}) or {})
        object_id = str(source.get("source_object_id", ""))
        slot = None
        access_path: tuple[int, ...] = ()
        formal_access = dict(proof.get("source_buffer_formal_access", {}) or {})
        if isinstance(formal_access.get("parameter_slot"), int):
            slot = int(formal_access["parameter_slot"])
            access_path = tuple(int(item) for item in list(formal_access.get("access_path", []) or []))
        if object_id.startswith("param:"):
            try:
                slot = slot if slot is not None else int(object_id.rsplit(":", 1)[1])
            except ValueError:
                slot = None
        if slot is None:
            binding = proof.get("callee_output_bindings")
            if isinstance(binding, list) and binding and isinstance(binding[0].get("parameter_slot"), int):
                slot = int(binding[0]["parameter_slot"])
        if not function_id or slot is None:
            continue
        rows.append(FunctionSummary(
            summary_id=stable_id("body-summary", function_id, slot, source.get("site_id")),
            function_names=(str(source.get("function", "")),),
            function_id=function_id,
            channel=str(source.get("source_kind", "peripheral_input")),
            outputs=(OutputSpec(
                "output_buffer",
                "formal_access_path" if access_path else "formal_pointee",
                slot,
                access_path=access_path,
            ),),
            proof_kind="body_proved_hardware_provenance",
            min_args=slot + 1,
            provenance=[{
                "kind": "underlying_source",
                "source_id": str(source.get("id", "")),
                "site_id": str(source.get("site_id", "")),
            }],
        ))
    return rows


def stateful_summaries_from_seed_sources(
    index: ProgramIndex, seed_sources: Iterable[dict[str, Any]]
) -> list[FunctionSummary]:
    """Derive MCU driver summaries through an exact typed state field.

    The admitted pattern is deliberately narrow:

    1. a deterministic hardware Source writes through a pointer loaded from
       one unique typed state field; and
    2. another function writes a value with one exact formal access path into
       that same typed field.

    No function, framework, or CVE names participate in the decision.
    """

    source_fields: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for source in seed_sources:
        if str(source.get("decision", "")) != "ACCEPT_DETERMINISTIC":
            continue
        function_id = str(source.get("function_id", ""))
        proof = dict(source.get("proof", {}) or {})
        pointer_value_id = str(proof.get("destination_pointer_value_id", ""))
        function = index.by_id.get(function_id)
        definitions = index.definitions_by_function.get(function_id, {})
        if not function or not pointer_value_id:
            continue
        pointer_def = definitions.get(pointer_value_id)
        pointer = dict((pointer_def or {}).get("output", {}) or {})
        if not pointer:
            continue
        signatures = upstream_state_fields(pointer, definitions)
        if len(signatures) != 1:
            continue
        source_fields[next(iter(signatures))].append(source)

    summaries: list[FunctionSummary] = []
    seen: set[tuple[str, int, tuple[int, ...], tuple[str, int]]] = set()
    for function in index.functions:
        function_id = str(function.get("function_id", ""))
        definitions = index.definitions_by_function.get(function_id, {})
        for store in index.stores_by_function.get(function_id, []):
            inputs = [dict(item) for item in list(store.get("inputs", []) or [])]
            if len(inputs) < 3:
                continue
            signature = field_signature(inputs[-2], definitions)
            if signature not in source_fields:
                continue
            access = formal_access_path(inputs[-1], definitions)
            if access is None:
                continue
            slot, path = access
            key = (function_id, slot, path, signature)
            if key in seen:
                continue
            seen.add(key)
            underlying = source_fields[signature]
            summaries.append(FunctionSummary(
                summary_id=stable_id(
                    "state-summary", function_id, slot, path, signature, store.get("site_id")
                ),
                function_names=(str(function.get("name", "")),),
                function_id=function_id,
                channel=str(underlying[0].get("source_kind", "peripheral_input")),
                outputs=(OutputSpec(
                    "output_buffer",
                    "formal_pointee" if not path else "formal_access_path",
                    slot,
                    access_path=path,
                ),),
                proof_kind="body_proved_typed_state_field_provenance",
                min_args=len(list(function.get("parameters", []) or [])),
                max_args=len(list(function.get("parameters", []) or [])),
                provenance=[{
                    "kind": "typed_state_field_bridge",
                    "state_field": {
                        "base_type": signature[0],
                        "field_offset": f"0x{signature[1]:x}",
                    },
                    "field_store_site_id": str(store.get("site_id", "")),
                    "formal_parameter_slot": slot,
                    "formal_access_path": [f"0x{offset:x}" for offset in path],
                    "underlying_source_ids": [str(row.get("id", "")) for row in underlying],
                    "underlying_source_sites": [str(row.get("site_id", "")) for row in underlying],
                }],
            ))
    return summaries


def callback_summaries(
    index: ProgramIndex, pack: dict[str, Any]
) -> tuple[list[FunctionSummary], list[dict[str, Any]]]:
    """Bind framework registration calls to exact callback functions.

    A callback is accepted only when the registration target is a trusted
    framework contract and the callback argument resolves to exactly one code
    address. Merely naming a function ``*_rx_cb`` is never evidence.
    """

    specs = list(pack.get("callback_registrations", []) or [])
    summaries: list[FunctionSummary] = []
    unresolved: list[dict[str, Any]] = []
    by_registration: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for spec in specs:
        match = dict(spec.get("match", {}) or {})
        names = spec.get("registration_names") or match.get("symbol_names") or []
        for name in names:
            by_registration[str(name)].append(dict(spec))
    for caller, op in index.calls:
        target = index.resolve_call_target(caller, op)
        if not target:
            continue
        target_name = str(target.get("name", ""))
        if target_name not in by_registration:
            continue
        actuals = index.call_actuals(caller, op)
        caller_id = str(caller.get("function_id", ""))
        for spec in by_registration[target_name]:
            callback_slot = spec.get("callback_arg_index")
            if not isinstance(callback_slot, int) or callback_slot >= len(actuals):
                continue
            address = index.resolve_constant(caller_id, actuals[callback_slot])
            callback = index.by_entry.get((address or -1) & ~1)
            if callback is None:
                unresolved.append({
                    "site_id": str(op.get("site_id", "")),
                    "function_id": caller_id,
                    "function": str(caller.get("name", "")),
                    "reason": "callback_target_not_uniquely_resolved",
                    "registration": target_name,
                })
                continue
            outputs = []
            for output in list(spec.get("callback_outputs", []) or []):
                slot = output.get("parameter_slot")
                if not isinstance(slot, int):
                    continue
                outputs.append(OutputSpec(
                    role=str(output.get("role", "callback_input")),
                    binding_kind=str(output.get("binding_kind", "formal_pointee")),
                    parameter_slot=slot,
                ))
            if not outputs:
                continue
            summaries.append(FunctionSummary(
                summary_id=stable_id("callback-summary", op.get("site_id"), callback.get("function_id")),
                function_names=(str(callback.get("name", "")),),
                function_id=str(callback.get("function_id", "")),
                channel=str(spec.get("channel", "callback_external_input")),
                outputs=tuple(outputs),
                proof_kind="trusted_registration_contract_exact_callback_target",
                min_args=len(list(callback.get("parameters", []) or [])),
                max_args=len(list(callback.get("parameters", []) or [])),
                provenance=[{
                    "kind": "callback_registration",
                    "site_id": str(op.get("site_id", "")),
                    "registration_function": target_name,
                    "callback_function_id": str(callback.get("function_id", "")),
                }],
            ))
    return summaries, unresolved


def _function_matches_summary(
    index: ProgramIndex, target: dict[str, Any], summary: FunctionSummary, arity: int
) -> bool:
    if not summary.accepts_arity(arity):
        return False
    name = str(target.get("name", ""))
    if summary.function_id:
        return str(target.get("function_id", "")) == summary.function_id
    if name not in summary.function_names:
        return False
    # A standard ABI contract may bind an internal implementation only when
    # the recovered parameter count agrees. This prevents Contiki's two-arg
    # radio read() from being mistaken for POSIX read(fd, buf, count).
    parameters = list(target.get("parameters", []) or [])
    if parameters and not summary.accepts_arity(len(parameters)):
        return False
    parameters_by_slot = {
        int(parameter["index"]): dict(parameter)
        for parameter in parameters
        if isinstance(parameter.get("index"), int)
    }
    for output in summary.outputs:
        if output.binding_kind not in {"formal_pointee", "formal_access_path"}:
            continue
        if output.parameter_slot is None:
            continue
        parameter = parameters_by_slot.get(output.parameter_slot, {})
        data_type = str(
            parameter.get("data_type", parameter.get("high_data_type", ""))
        ).strip()
        if data_type and not _is_unknown_type(data_type) and not _is_pointer_type(data_type):
            return False
    return summary.compatibility_scope not in {"compatibility_specific", "sample_specific"}


def _is_unknown_type(data_type: str) -> bool:
    normalized = re.sub(r"\s+", " ", data_type.strip().lower())
    return not normalized or normalized in {
        "unknown", "undefined", "undefined1", "undefined2", "undefined4",
        "undefined8",
    }


def _is_pointer_type(data_type: str) -> bool:
    return "*" in data_type or "[" in data_type or "]" in data_type


def _output_actuals_are_compatible(
    index: ProgramIndex,
    caller: dict[str, Any],
    summary: FunctionSummary,
    actuals: list[dict[str, Any]],
) -> bool:
    caller_id = str(caller.get("function_id", ""))
    for output in summary.outputs:
        if output.binding_kind not in {"formal_pointee", "formal_access_path"}:
            continue
        if output.parameter_slot is None or output.parameter_slot >= len(actuals):
            return False
        actual = actuals[output.parameter_slot]
        if index.resolve_constant(caller_id, actual) == 0:
            return False
        data_type = str(actual.get("high_data_type", "")).strip()
        if data_type and not _is_unknown_type(data_type) and not _is_pointer_type(data_type):
            return False
    return True


def _return_depends_on(
    index: ProgramIndex, function_id: str, call_output_value: str
) -> bool:
    definitions = index.definitions_by_function.get(function_id, {})
    for ret in index.returns_by_function.get(function_id, []):
        for node in list(ret.get("inputs", []) or [])[1:]:
            if depends_on_value(dict(node), call_output_value, definitions):
                return True
    return False


def propagate_direct_wrappers(
    index: ProgramIndex, summaries: list[FunctionSummary], *, max_depth: int = 5
) -> list[FunctionSummary]:
    all_summaries = list(summaries)
    for _ in range(max_depth):
        changed = False
        by_target_id: dict[str, list[FunctionSummary]] = defaultdict(list)
        by_name: dict[str, list[FunctionSummary]] = defaultdict(list)
        for summary in all_summaries:
            if summary.function_id:
                by_target_id[summary.function_id].append(summary)
            for name in summary.function_names:
                by_name[name].append(summary)
        existing = {_summary_key(summary) for summary in all_summaries}
        for caller, op in index.calls:
            target = index.resolve_call_target(caller, op)
            if not target:
                continue
            target_id = str(target.get("function_id", ""))
            candidates = by_target_id.get(target_id, []) or by_name.get(str(target.get("name", "")), [])
            actuals = index.call_actuals(caller, op)
            caller_id = str(caller.get("function_id", ""))
            definitions = index.definitions_by_function.get(caller_id, {})
            for callee_summary in candidates:
                if not _function_matches_summary(
                    index, target, callee_summary, len(actuals)
                ):
                    continue
                if not _output_actuals_are_compatible(
                    index, caller, callee_summary, actuals
                ):
                    continue
                descriptor_slot: int | None = None
                descriptor_required = False
                if callee_summary.descriptor_parameter_slot is not None:
                    callee_descriptor_slot = callee_summary.descriptor_parameter_slot
                    if callee_descriptor_slot >= len(actuals):
                        continue
                    descriptor_actual = actuals[callee_descriptor_slot]
                    descriptor_slot = parameter_slot(descriptor_actual, definitions)
                    descriptor_constant = index.resolve_constant(
                        caller_id, descriptor_actual
                    )
                    if descriptor_slot is not None:
                        descriptor_required = callee_summary.descriptor_required
                    elif descriptor_constant == 0:
                        descriptor_required = False
                    elif callee_summary.descriptor_required:
                        continue
                outputs: list[OutputSpec] = []
                for output in callee_summary.outputs:
                    if output.binding_kind in {
                        "formal_pointee", "formal_value", "formal_access_path"
                    } and output.parameter_slot is not None:
                        if output.parameter_slot >= len(actuals):
                            continue
                        actual = actuals[output.parameter_slot]
                        if output.binding_kind == "formal_access_path":
                            origin = index.resolve_actual_access(
                                caller, actual, output.access_path, op
                            )
                            if origin and origin.get("kind") == "formal":
                                remaining_path = tuple(origin.get("access_path", ()) or ())
                                outputs.append(OutputSpec(
                                    output.role,
                                    "formal_access_path" if remaining_path else "formal_pointee",
                                    int(origin["parameter_slot"]),
                                    access_path=remaining_path,
                                    extent_for_role=output.extent_for_role,
                                ))
                        else:
                            slot = parameter_slot(actual, definitions)
                            if slot is not None:
                                outputs.append(OutputSpec(
                                    output.role,
                                    output.binding_kind,
                                    slot,
                                    access_path=output.access_path,
                                    extent_for_role=output.extent_for_role,
                                ))
                    elif output.binding_kind in {"return_value", "return_pointer"}:
                        call_output = node_value_id(dict(op.get("output", {}) or {}))
                        if call_output and _return_depends_on(index, caller_id, call_output):
                            outputs.append(
                                OutputSpec(
                                    output.role,
                                    output.binding_kind,
                                    extent_for_role=output.extent_for_role,
                                )
                            )
                if not outputs:
                    continue
                summary = FunctionSummary(
                    summary_id=stable_id("wrapper-summary", caller_id, op.get("site_id"), callee_summary.summary_id),
                    function_names=(str(caller.get("name", "")),),
                    function_id=caller_id,
                    channel=callee_summary.channel,
                    outputs=tuple(outputs),
                    proof_kind="direct_wrapper_actual_formal_return_binding",
                    min_args=len(list(caller.get("parameters", []) or [])),
                    max_args=len(list(caller.get("parameters", []) or [])),
                    descriptor_parameter_slot=descriptor_slot,
                    descriptor_required=descriptor_required,
                    provenance=callee_summary.provenance + [{
                        "kind": "direct_wrapper_call",
                        "site_id": str(op.get("site_id", "")),
                        "callee_function_id": target_id,
                        "callee_summary_id": callee_summary.summary_id,
                    }],
                )
                key = _summary_key(summary)
                if key not in existing:
                    existing.add(key)
                    all_summaries.append(summary)
                    changed = True
        if not changed:
            break
    return all_summaries


def descriptor_provenance(
    index: ProgramIndex, pack: dict[str, Any] | None = None
) -> dict[str, dict[str, Any]]:
    """Track exact descriptor-producing calls and transparent aliases.

    This is deliberately a contract layer parallel to Mango's fd tracker. It
    does not infer channels from variable names.
    """

    creators: dict[str, tuple[str, int | None]] = {
        "socket": ("network_socket", None),
        "accept": ("accepted_socket", 0),
        "accept4": ("accepted_socket", 0),
        "open": ("external_file", None),
        "openat": ("external_file", None),
        "fopen": ("external_file_stream", None),
        "fdopen": ("external_file_stream", 0),
        "popen": ("process_stream", None),
    }
    for row in _summary_rows(pack or {}):
        if row.get("summary_kind") != "handle_producer":
            continue
        if row.get("compatibility_specific") or row.get("core_eligible") is False:
            continue
        handle = dict(row.get("handle_provenance", {}) or {})
        if not bool(handle.get("produces_return_handle")):
            continue
        channel_row = row.get("source_channel", {})
        channel = str(channel_row.get("kind", "descriptor")) if isinstance(channel_row, dict) else str(channel_row)
        parent = handle.get("parent_argument")
        creators[str(row.get("name", ""))] = (
            channel or "descriptor",
            int(parent) if isinstance(parent, int) else None,
        )
    out: dict[str, dict[str, Any]] = {}
    for function, op in index.calls:
        target = index.resolve_call_target(function, op)
        if not target:
            continue
        name = str(target.get("name", ""))
        if name not in creators or not op.get("output"):
            continue
        kind, parent_slot = creators[name]
        actuals = index.call_actuals(function, op)
        parent_value = node_value_id(actuals[parent_slot]) if parent_slot is not None and parent_slot < len(actuals) else ""
        output_value = node_value_id(dict(op.get("output", {}) or {}))
        if output_value:
            out[output_value] = {
                "kind": kind,
                "creator": name,
                "site_id": str(op.get("site_id", "")),
                "parent_value_id": parent_value,
            }
    # Propagate across transparent SSA definitions.
    changed = True
    while changed:
        changed = False
        for function_id, definitions in index.definitions_by_function.items():
            for value_id, op in definitions.items():
                if value_id in out or str(op.get("mnemonic", "")) not in TRANSPARENT_OPS:
                    continue
                parents = [out[node_value_id(dict(item))] for item in list(op.get("inputs", []) or []) if node_value_id(dict(item)) in out]
                if len(parents) == 1:
                    out[value_id] = {**parents[0], "alias_site_id": str(op.get("site_id", ""))}
                    changed = True
    return out


def _descriptor_proof(
    summary: FunctionSummary,
    actuals: list[dict[str, Any]],
    provenance: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    slot = summary.descriptor_parameter_slot
    if slot is None:
        return {"required": False}
    if slot >= len(actuals):
        return None
    node = actuals[slot]
    value_id = node_value_id(node)
    constant = parse_int(node.get("offset")) if bool(node.get("is_constant")) else None
    if constant == 0:
        return {"required": summary.descriptor_required, "kind": "stdin", "value_id": value_id}
    row = provenance.get(value_id)
    if row:
        return {"required": summary.descriptor_required, "value_id": value_id, **row}
    return None if summary.descriptor_required else {"required": False, "value_id": value_id, "kind": "api_implied"}


def instantiate_summaries(
    index: ProgramIndex,
    summaries: list[FunctionSummary],
    descriptor_facts: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    by_id: dict[str, list[FunctionSummary]] = defaultdict(list)
    by_name: dict[str, list[FunctionSummary]] = defaultdict(list)
    for summary in summaries:
        if summary.function_id:
            by_id[summary.function_id].append(summary)
        for name in summary.function_names:
            by_name[name].append(summary)
    for caller, op in index.calls:
        target = index.resolve_call_target(caller, op)
        if not target:
            if str(op.get("mnemonic", "")) == "CALLIND":
                unresolved.append({
                    "site_id": str(op.get("site_id", "")),
                    "function_id": str(caller.get("function_id", "")),
                    "function": str(caller.get("name", "")),
                    "reason": "indirect_target_not_uniquely_resolved",
                })
            continue
        actuals = index.call_actuals(caller, op)
        target_id = str(target.get("function_id", ""))
        candidates = by_id.get(target_id, []) + by_name.get(str(target.get("name", "")), [])
        seen_summaries: set[str] = set()
        for summary in candidates:
            if summary.summary_id in seen_summaries or not _function_matches_summary(index, target, summary, len(actuals)):
                continue
            if not _output_actuals_are_compatible(index, caller, summary, actuals):
                continue
            seen_summaries.add(summary.summary_id)
            descriptor = _descriptor_proof(summary, actuals, descriptor_facts)
            if summary.descriptor_required and descriptor is None:
                continue
            outputs: list[dict[str, Any]] = []
            for output in summary.outputs:
                if output.binding_kind == "formal_pointee" and output.parameter_slot is not None:
                    if output.parameter_slot >= len(actuals):
                        continue
                    actual = actuals[output.parameter_slot]
                    value_id = node_value_id(actual)
                    concrete = index.concrete_object_binding(
                        str(caller.get("function_id", "")), actual
                    )
                    outputs.append({
                        "role": output.role,
                        "kind": "memory_object",
                        "expression": (
                            str(concrete.get("expression", "")) if concrete
                            else node_name(actual) or node_object_id(actual)
                        ),
                        "object_id": (
                            str(concrete.get("object_id", "")) if concrete
                            else f"pointee:{value_id}" if value_id else node_object_id(actual)
                        ),
                        "value_id": value_id,
                        "binding_status": "exact_call_actual",
                        "parameter_slot": output.parameter_slot,
                        "extent_for_role": output.extent_for_role,
                        "concrete_address": (
                            f"0x{int(concrete['address']):x}" if concrete else ""
                        ),
                    })
                elif output.binding_kind == "formal_access_path" and output.parameter_slot is not None:
                    if output.parameter_slot >= len(actuals):
                        continue
                    actual = actuals[output.parameter_slot]
                    origin = index.resolve_actual_access(
                        caller, actual, output.access_path, op
                    )
                    if not origin:
                        continue
                    if origin.get("kind") == "formal":
                        caller_slot = int(origin["parameter_slot"])
                        parameter = next(
                            (
                                dict(row) for row in list(caller.get("parameters", []) or [])
                                if row.get("index") == caller_slot
                            ),
                            {},
                        )
                        expression = (
                            str(parameter.get("name", "")) or f"param[{caller_slot}]"
                        ) + "".join(
                            f"->+0x{offset:x}" for offset in origin.get("access_path", ())
                        )
                        object_id = str(parameter.get("object_id", "")) or (
                            f"param:{str(caller.get('function_id', '')).removeprefix('fn:')}:{caller_slot}"
                        )
                        value_id = ""
                    else:
                        expression = f"RAM@0x{int(origin['address']):x}"
                        object_id = f"global:{int(origin['address']):08x}:unknown"
                        value_id = ""
                    outputs.append({
                        "role": output.role,
                        "kind": "memory_object",
                        "expression": expression,
                        "object_id": object_id,
                        "value_id": value_id,
                        "binding_status": "exact_descriptor_access_path",
                        "parameter_slot": output.parameter_slot,
                        "access_path": [f"0x{offset:x}" for offset in output.access_path],
                        "resolution_evidence": list(origin.get("evidence", []) or []),
                        "extent_for_role": output.extent_for_role,
                    })
                elif output.binding_kind == "formal_value" and output.parameter_slot is not None:
                    if output.parameter_slot >= len(actuals):
                        continue
                    actual = actuals[output.parameter_slot]
                    outputs.append({
                        "role": output.role,
                        "kind": "scalar_value",
                        "expression": node_name(actual) or node_object_id(actual),
                        "object_id": node_object_id(actual),
                        "value_id": node_value_id(actual),
                        "binding_status": "exact_call_actual",
                        "parameter_slot": output.parameter_slot,
                        "extent_for_role": output.extent_for_role,
                    })
                elif output.binding_kind in {"return_value", "return_pointer"}:
                    result = dict(op.get("output", {}) or {})
                    if not result:
                        continue
                    outputs.append({
                        "role": output.role,
                        "kind": "memory_object" if output.binding_kind == "return_pointer" else "scalar_value",
                        "expression": node_name(result) or node_object_id(result),
                        "object_id": (f"pointee:{node_value_id(result)}" if output.binding_kind == "return_pointer" else ""),
                        "value_id": node_value_id(result),
                        "binding_status": "exact_call_return",
                        "extent_for_role": output.extent_for_role,
                    })
            if not outputs:
                continue
            binding_text = ", ".join(
                f"{item.get('role', 'output')}={item.get('expression', '')}"
                for item in outputs
            )
            rows.append({
                "detection_kind": "software_summary_callsite",
                "confirmation_source": summary.proof_kind,
                "label": "BYTE_STREAM_INGRESS",
                "source_kind": summary.channel,
                "function": str(caller.get("name", "")),
                "function_id": str(caller.get("function_id", "")),
                "callee": str(target.get("name", "")),
                "plain_line": 0,
                "source_site": (
                    f"{op.get('mnemonic')} {target.get('name', '')} [{binding_text}]"
                ),
                "source_buffer": next((str(item.get("expression", "")) for item in outputs if item.get("kind") == "memory_object"), ""),
                "site_id": str(op.get("site_id", "")),
                "source_object_id": str(outputs[0].get("object_id", "")),
                "source_value_id": str(outputs[0].get("value_id", "")),
                "source_output": outputs[0],
                "source_outputs": outputs,
                "proof": {
                    "kind": "software_interface_summary_instantiation",
                    "summary_id": summary.summary_id,
                    "summary_proof_kind": summary.proof_kind,
                    "call_site_id": str(op.get("site_id", "")),
                    "callee_function_id": target_id,
                    "descriptor_provenance": descriptor,
                    "provenance": summary.provenance,
                },
                "decision": "ACCEPT_DETERMINISTIC",
                "evidence_level": "DETERMINISTIC_SOURCE_SEMANTICS",
                "taint_status": "source_semantics_confirmed",
                "vulnerability_status": "not_evaluated",
                "chain_ready": True,
            })
    return rows, unresolved


def source_definitions(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    definitions: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source in rows:
        decision = str(source.get("decision", ""))
        if decision not in {"ACCEPT_DETERMINISTIC", "ACCEPT_HEURISTIC"}:
            continue
        outputs = list(source.get("source_outputs", []) or [])
        if not outputs and source.get("source_output"):
            outputs = [dict(source["source_output"])]
        outputs = [dict(output) for output in outputs if output.get("value_id") or output.get("object_id")]
        if not outputs:
            continue
        definition_id = stable_id(
            "source-definition",
            source.get("site_id"),
            source.get("id"),
            json.dumps(outputs, sort_keys=True),
        )
        if definition_id in seen:
            continue
        seen.add(definition_id)
        definitions.append({
            "source_definition_id": definition_id,
            "source_id": str(source.get("id", "")),
            "site_id": str(source.get("site_id", "")),
            "function_id": str(source.get("function_id", "")),
            "function": str(source.get("function", "")),
            "channel": str(source.get("source_kind", "")),
            "outputs": outputs,
            "proof": dict(source.get("proof", {}) or {}),
            "decision": decision,
            "evidence_level": str(source.get("evidence_level", "")),
        })
    return definitions


def analyze(
    program_facts: dict[str, Any],
    summary_pack: dict[str, Any],
    *,
    seed_sources: Iterable[dict[str, Any]] = (),
    include_compatibility_specific: bool = False,
) -> dict[str, Any]:
    index = ProgramIndex(program_facts)
    seed_rows = list(seed_sources)
    summaries = parse_summary_pack(
        summary_pack,
        include_compatibility_specific=include_compatibility_specific,
    )
    summaries.extend(summaries_from_seed_sources(seed_rows))
    summaries.extend(stateful_summaries_from_seed_sources(index, seed_rows))
    callback_rows, callback_unresolved = callback_summaries(index, summary_pack)
    summaries.extend(callback_rows)
    summaries = propagate_direct_wrappers(index, summaries)
    descriptors = descriptor_provenance(index, summary_pack)
    rows, unresolved = instantiate_summaries(index, summaries, descriptors)
    existing_bindings: set[tuple[str, str, str, str]] = set()
    for source in seed_rows:
        for output in list(source.get("source_outputs", []) or []):
            existing_bindings.add((
                str(source.get("site_id", "")),
                str(output.get("role", "")),
                str(output.get("object_id", "")),
                str(output.get("value_id", "")),
            ))
    rows = [
        row for row in rows
        if any(
            (
                str(row.get("site_id", "")),
                str(output.get("role", "")),
                str(output.get("object_id", "")),
                str(output.get("value_id", "")),
            ) not in existing_bindings
            for output in list(row.get("source_outputs", []) or [])
        )
    ]
    unresolved.extend(callback_unresolved)
    return {
        "schema_version": "ct-mini-software-source-analysis-v1",
        "confirmed_sources": rows,
        "source_definitions": source_definitions(seed_rows + rows),
        "function_summaries": [
            {
                "summary_id": summary.summary_id,
                "function_id": summary.function_id,
                "function_names": list(summary.function_names),
                "channel": summary.channel,
                "proof_kind": summary.proof_kind,
                "outputs": [output.__dict__ for output in summary.outputs],
                "provenance": summary.provenance,
            }
            for summary in summaries
        ],
        "descriptor_provenance": descriptors,
        "unresolved_indirect_calls": unresolved,
        "counts": {
            "confirmed_software_sources": len(rows),
            "source_definitions": len(source_definitions(seed_rows + rows)),
            "function_summaries": len(summaries),
            "descriptor_provenance_values": len(descriptors),
            "unresolved_indirect_calls": len(unresolved),
        },
    }
