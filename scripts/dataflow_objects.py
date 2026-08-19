#!/usr/bin/env python3
"""Context-sensitive object identities derived from High P-code.

The module is intentionally independent of framework/API names.  It recovers
stack locals, formal pointer objects, and pointer-valued call results, then
propagates those identities through transparent pointer operations.  The
result is an alias aid for RDA, not proof that two runtime allocations are the
same concrete address.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any, Callable


TRANSPARENT_POINTER_OPS = {
    "COPY",
    "CAST",
    "INDIRECT",
    "INT_ZEXT",
    "INT_SEXT",
    "SUBPIECE",
}
POINTER_ARITHMETIC_OPS = {"PTRADD", "PTRSUB", "INT_ADD"}


def identity(node: dict[str, Any]) -> str:
    return str(node.get("value_id", "") or node.get("object_id", ""))


def is_pointer(node: dict[str, Any]) -> bool:
    data_type = str(node.get("high_data_type", ""))
    return int(node.get("size", 0) or 0) in {4, 8} and (
        "*" in data_type or bool(node.get("is_address"))
    )


def signed_constant(node: dict[str, Any]) -> int | None:
    if not bool(node.get("is_constant")):
        return None
    raw = str(node.get("offset", "")).strip()
    if not raw:
        return None
    try:
        value = int(raw, 16)
    except ValueError:
        return None
    width = max(1, int(node.get("size", 4) or 4)) * 8
    mask = (1 << width) - 1
    value &= mask
    sign = 1 << (width - 1)
    return value - (1 << width) if value & sign else value


def stable_child_id(parent: str, path: tuple[str, ...]) -> str:
    token = hashlib.sha256((parent + "|" + "|".join(path)).encode()).hexdigest()[:20]
    return f"obj:access-path:{token}"


class RuntimeObjectIndex:
    def __init__(
        self,
        program_facts: dict[str, Any],
        *,
        static_object: Callable[[dict[str, Any]], tuple[str, dict[str, Any], str] | None],
        stack_descriptor: Callable[[dict[str, Any], str], tuple[int, int] | None],
        stack_object_id: Callable[[str, int], str],
    ) -> None:
        self.static_object = static_object
        self.stack_descriptor = stack_descriptor
        self.stack_object_id = stack_object_id
        self.functions = {
            str(function.get("function_id", "")): function
            for function in list(program_facts.get("functions", []) or [])
            if str(function.get("function_id", ""))
        }
        self.ops_by_site: dict[str, tuple[str, dict[str, Any]]] = {}
        self.uses_by_atom: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        self.pointer_store_ops: list[tuple[str, dict[str, Any]]] = []
        for function_id, function in self.functions.items():
            for op in list(function.get("pcode_ops", []) or []):
                site_id = str(op.get("site_id", ""))
                if site_id:
                    self.ops_by_site[site_id] = (function_id, op)
                for raw in list(op.get("inputs", []) or []):
                    atom = identity(dict(raw or {}))
                    if atom:
                        self.uses_by_atom[atom].append((function_id, op))
                if str(op.get("mnemonic", "")) == "STORE":
                    self.pointer_store_ops.append((function_id, op))
        self.cache: dict[tuple[str, str], dict[str, Any] | None] = {}
        self.pointer_slot_alias_cache: dict[
            tuple[str, tuple[str, ...]], dict[str, Any] | None
        ] = {}
        self.pointer_slot_alias_in_progress: set[tuple[str, tuple[str, ...]]] = set()

    @staticmethod
    def _slot_key(binding: dict[str, Any]) -> tuple[str, tuple[str, ...]]:
        return (
            str(binding.get("root_object_id", binding.get("object_id", ""))),
            tuple(str(item) for item in list(binding.get("access_path", []) or [])),
        )

    def _resolve_pointer_slot_alias(
        self,
        parent: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Resolve one exact pointer slot from its whole-program STORE facts.

        This is deliberately flow-insensitive.  It succeeds only when every
        resolvable pointer STORE to the exact Region names the same contextual
        object.  Competing object identities leave the slot unresolved.
        """

        slot_key = self._slot_key(parent)
        if not slot_key[0]:
            return None
        if slot_key in self.pointer_slot_alias_cache:
            return self.pointer_slot_alias_cache[slot_key]
        if slot_key in self.pointer_slot_alias_in_progress:
            return None
        self.pointer_slot_alias_in_progress.add(slot_key)
        candidates: list[dict[str, Any]] = []
        try:
            for store_function_id, op in self.pointer_store_ops:
                inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
                if len(inputs) < 2:
                    continue
                address, stored = inputs[-2], inputs[-1]
                if not is_pointer(stored):
                    continue
                address_binding = self.resolve(address, store_function_id)
                if not address_binding or self._slot_key(address_binding) != slot_key:
                    continue
                candidates.extend(
                    self._resolve_pointer_candidates(stored, store_function_id)
                )
        finally:
            self.pointer_slot_alias_in_progress.discard(slot_key)

        object_ids = {
            str(candidate.get("object_id", ""))
            for candidate in candidates
            if str(candidate.get("object_id", ""))
        }
        if len(object_ids) == 1:
            result = dict(candidates[0])
        elif (
            1 < len(object_ids) <= 8
            and all(
                str(candidate.get("storage_kind", "")) == "CALL_RESULT_OBJECT"
                for candidate in candidates
            )
        ):
            token = hashlib.sha256(
                (slot_key[0] + "|" + "|".join(slot_key[1])).encode()
            ).hexdigest()[:20]
            object_id = f"obj:pointer-slot-target-set:{token}"
            result = {
                "object_id": object_id,
                "root_object_id": object_id,
                "storage_kind": "POINTER_SLOT_TARGET_SET",
                "identity_kind": "FINITE_CALL_RESULT_TARGET_SET",
                "access_path": [],
                "member_object_ids": sorted(object_ids),
            }
        else:
            self.pointer_slot_alias_cache[slot_key] = None
            return None
        result["precision"] = "MAY"
        result["provenance"] = "HIGH_PCODE_UNIQUE_POINTER_SLOT_STORE_LOAD"
        result["pointer_slot"] = {
            "root_object_id": slot_key[0],
            "access_path": list(slot_key[1]),
            "candidate_store_count": len(candidates),
        }
        self.pointer_slot_alias_cache[slot_key] = result
        return result

    def _resolve_pointer_candidates(
        self,
        node: dict[str, Any],
        function_id: str,
        *,
        depth: int = 0,
        seen: frozenset[str] = frozenset(),
    ) -> list[dict[str, Any]]:
        """Enumerate a small finite set hidden behind an SSA merge."""

        atom = identity(node)
        if depth > 16 or not atom or atom in seen:
            return []
        binding = self.resolve(node, function_id)
        if binding:
            return [binding]
        entry = self.ops_by_site.get(str(node.get("def_site_id", "")))
        if not entry:
            return []
        op_function_id, op = entry
        if str(op.get("mnemonic", "")) != "MULTIEQUAL":
            return []
        rows: list[dict[str, Any]] = []
        for raw in list(op.get("inputs", []) or []):
            item = dict(raw or {})
            if bool(item.get("is_constant")):
                continue
            rows.extend(
                self._resolve_pointer_candidates(
                    item,
                    op_function_id,
                    depth=depth + 1,
                    seen=seen | {atom},
                )
            )
            if len(rows) > 8:
                return []
        unique = {
            str(row.get("object_id", "")): row
            for row in rows
            if str(row.get("object_id", ""))
        }
        return [unique[key] for key in sorted(unique)]

    def resolve(
        self,
        node: dict[str, Any],
        function_id: str,
        *,
        depth: int = 0,
        seen: set[str] | None = None,
    ) -> dict[str, Any] | None:
        if depth > 16:
            return None
        atom = identity(node)
        key = (function_id, atom)
        if atom and key in self.cache:
            return self.cache[key]
        seen = set(seen or set())
        if atom and atom in seen:
            return None
        if atom:
            seen.add(atom)

        static = self.static_object(node)
        if static:
            result = {
                "object_id": static[0],
                "root_object_id": static[0],
                "storage_kind": str(static[1].get("storage_kind", "STATIC_WRITABLE_DATA")),
                "identity_kind": str(static[1].get("identity_kind", "STATIC_OBJECT")),
                "access_path": [],
                "precision": "EXACT",
                "provenance": static[2],
            }
            if atom:
                self.cache[key] = result
            return result

        stack = self.stack_descriptor(node, function_id)
        if stack is not None:
            root, relative = stack
            object_id = self.stack_object_id(function_id, root)
            result = {
                "object_id": object_id,
                "root_object_id": object_id,
                "storage_kind": "STACK_LOCAL",
                "identity_kind": "HIGH_PCODE_STACK_LOCAL",
                "access_path": ([f"byte_offset:{relative}"] if relative else []),
                "precision": "EXACT",
                "provenance": "HIGH_PCODE_STACK_PTRSUB",
            }
            if atom:
                self.cache[key] = result
            return result

        if bool(node.get("is_parameter")) and is_pointer(node):
            slot = node.get("parameter_slot")
            object_id = f"obj:formal:{function_id}:{slot}"
            result = {
                "object_id": object_id,
                "root_object_id": object_id,
                "storage_kind": "FORMAL_POINTER",
                "identity_kind": "FORMAL_POINTER_OBJECT",
                "access_path": [],
                "precision": "CONTEXTUAL",
                "provenance": "HIGH_PCODE_FORMAL",
            }
            if atom:
                self.cache[key] = result
            return result

        entry = self.ops_by_site.get(str(node.get("def_site_id", "")))
        if not entry:
            if atom:
                self.cache[key] = None
            return None
        op_function_id, op = entry
        mnemonic = str(op.get("mnemonic", ""))
        inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]

        if mnemonic in {"CALL", "CALLIND"} and is_pointer(node):
            # The identity is context-sensitive to the callsite.  Freshness is
            # deliberately UNKNOWN until a body summary proves allocation.
            site_id = str(op.get("site_id", ""))
            object_id = f"obj:call-result:{site_id}"
            result = {
                "object_id": object_id,
                "root_object_id": object_id,
                "storage_kind": "CALL_RESULT_OBJECT",
                "identity_kind": "CALLSITE_CONTEXT_OBJECT",
                "access_path": [],
                "precision": "CONTEXTUAL",
                "freshness": "UNKNOWN",
                "provenance": "HIGH_PCODE_POINTER_CALL_RESULT",
            }
            if atom:
                self.cache[key] = result
            return result

        if mnemonic in TRANSPARENT_POINTER_OPS:
            candidates = [
                self.resolve(
                    item,
                    op_function_id,
                    depth=depth + 1,
                    seen=seen,
                )
                for item in inputs
                if not bool(item.get("is_constant"))
            ]
            candidates = [candidate for candidate in candidates if candidate]
            object_ids = {str(candidate.get("object_id", "")) for candidate in candidates}
            if len(object_ids) == 1:
                result = dict(candidates[0])
                if atom:
                    self.cache[key] = result
                return result

        if mnemonic == "MULTIEQUAL":
            candidates = [
                self.resolve(item, op_function_id, depth=depth + 1, seen=seen)
                for item in inputs
                if not bool(item.get("is_constant"))
            ]
            candidates = [candidate for candidate in candidates if candidate]
            roots = {str(candidate.get("root_object_id", "")) for candidate in candidates}
            if candidates and len(roots) == 1:
                result = dict(candidates[0])
                result["precision"] = "MAY"
                result["provenance"] = "HIGH_PCODE_PHI_SAME_ROOT"
                if atom:
                    self.cache[key] = result
                return result

        if mnemonic in POINTER_ARITHMETIC_OPS:
            dynamic = [item for item in inputs if not bool(item.get("is_constant"))]
            constants = [
                value
                for item in inputs
                for value in [signed_constant(item)]
                if value is not None
            ]
            for base in dynamic:
                binding = self.resolve(
                    base, op_function_id, depth=depth + 1, seen=seen
                )
                if not binding:
                    continue
                delta = constants[0] if constants else 0
                if mnemonic == "PTRADD" and len(constants) > 1:
                    delta = constants[0] * constants[1]
                path = tuple(list(binding.get("access_path", []) or []) + [f"byte_offset:{delta}"])
                result = dict(binding)
                result["access_path"] = list(path)
                result["provenance"] = f"HIGH_PCODE_{mnemonic}"
                if atom:
                    self.cache[key] = result
                return result

        if mnemonic == "LOAD":
            address = next(
                (item for item in reversed(inputs) if not bool(item.get("is_constant"))),
                None,
            )
            if address:
                parent = self.resolve(
                    address, op_function_id, depth=depth + 1, seen=seen
                )
                if parent:
                    pointer_alias = self._resolve_pointer_slot_alias(parent)
                    if pointer_alias:
                        if atom:
                            self.cache[key] = pointer_alias
                        return pointer_alias
                    if not is_pointer(node):
                        if atom:
                            self.cache[key] = None
                        return None
                    path = tuple(list(parent.get("access_path", []) or []) + ["deref"])
                    object_id = stable_child_id(str(parent["root_object_id"]), path)
                    result = {
                        "object_id": object_id,
                        "root_object_id": str(parent["root_object_id"]),
                        "storage_kind": "FIELD_POINTEE",
                        "identity_kind": "HIGH_PCODE_ACCESS_PATH",
                        "access_path": list(path),
                        "precision": str(parent.get("precision", "CONTEXTUAL")),
                        "provenance": "HIGH_PCODE_LOAD_POINTER_FIELD",
                    }
                    if atom:
                        self.cache[key] = result
                    return result

        if atom:
            self.cache[key] = None
        return None

    def export(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        bindings: dict[tuple[str, str], dict[str, Any]] = {}
        objects: dict[str, dict[str, Any]] = {}
        for function_id, function in self.functions.items():
            nodes = list(function.get("parameters", []) or [])
            for op in list(function.get("pcode_ops", []) or []):
                nodes.append(dict(op.get("output", {}) or {}))
                nodes.extend(dict(item or {}) for item in list(op.get("inputs", []) or []))
            for raw in nodes:
                node = dict(raw or {})
                atom = identity(node)
                if not atom or bool(node.get("is_constant")):
                    continue
                binding = self.resolve(node, function_id)
                if not binding:
                    continue
                object_id = str(binding.get("object_id", ""))
                if not object_id:
                    continue
                bindings[(atom, object_id)] = {
                    "atom_id": atom,
                    "value_id": str(node.get("value_id", "")),
                    "value_object_id": str(node.get("object_id", "")),
                    "object_id": object_id,
                    "root_object_id": str(binding.get("root_object_id", object_id)),
                    "function_id": function_id,
                    "def_site_id": str(node.get("def_site_id", "")),
                    "identity_kind": str(binding.get("identity_kind", "")),
                    "storage_kind": str(binding.get("storage_kind", "")),
                    "access_path": list(binding.get("access_path", []) or []),
                    "precision": str(binding.get("precision", "")),
                    "freshness": str(binding.get("freshness", "")),
                    "provenance": str(binding.get("provenance", "")),
                    "binding_kind": "HIGH_PCODE_RUNTIME_OBJECT_ALIAS",
                }
                if str(binding.get("storage_kind", "")) in {
                    "STACK_LOCAL",
                    "CALL_RESULT_OBJECT",
                    "POINTER_SLOT_TARGET_SET",
                }:
                    objects.setdefault(
                        object_id,
                        {
                            "node_id": object_id,
                            "object_id": object_id,
                            "base_object_id": object_id,
                            "name": str(node.get("high_name", "")),
                            "identity_kind": str(binding.get("identity_kind", "")),
                            "storage_kind": str(binding.get("storage_kind", "")),
                            "access_path": list(binding.get("access_path", []) or []),
                            "writable": True,
                            "is_stack": str(binding.get("storage_kind", "")) == "STACK_LOCAL",
                            "is_rom": False,
                            "strict_region_eligible": False,
                            "evidence_level": "DETERMINISTIC_OR_CONTEXTUAL_IDENTITY",
                            "source_evidence_ids": [],
                        },
                    )
        by_atom: dict[str, set[str]] = defaultdict(set)
        for atom, object_id in bindings:
            by_atom[atom].add(object_id)
        unique = [
            row
            for (atom, _), row in bindings.items()
            if len(by_atom[atom]) == 1
        ]
        return (
            sorted(unique, key=lambda row: (row["value_id"], row["object_id"])),
            sorted(objects.values(), key=lambda row: row["object_id"]),
        )
