#!/usr/bin/env python3
"""Prototype sink-backward data-flow analysis for CopperTrace Mini.

The analysis starts from every sink vulnerable parameter and traverses High
P-code def-use, actual/formal call bindings, and ChannelGraph object writers.
It is intentionally evidence preserving: incomplete graph recovery is never
reported as a safe/internal-only result.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from function_effect_resolver import FunctionEffectResolver, ResolutionLimits


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def source_rows(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    return list(artifact.get("source_sites", []) or artifact.get("confirmed_sources", []) or [])


def sink_rows(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    return list(
        artifact.get("sinks", [])
        or artifact.get("sink_startpoints", [])
        or artifact.get("confirmed_sink_calls", [])
        or []
    )


def canonical_object_ids(object_id: str) -> set[str]:
    raw = str(object_id or "")
    if not raw:
        return set()
    out = {raw}
    if raw.startswith("obj:"):
        out.add(raw[4:])
    else:
        out.add(f"obj:{raw}")
    if raw.startswith("source-object:"):
        out.add(raw[len("source-object:"):])
    # Source Miner, Ghidra, and the Region resolver retain different readable
    # prefixes for the same ELF-backed address. Preserve those names in output
    # while sharing one internal address identity for exact alias comparison.
    for candidate in list(out):
        normalized = candidate[4:] if candidate.startswith("obj:") else candidate
        match = re.match(r"^(?:symbol|global|ram):([0-9a-fA-F]+)(?::|$)", normalized)
        if match:
            out.add(f"address:{int(match.group(1), 16):x}")
    return out


def _identity(row: dict[str, Any] | None) -> str:
    """Return an internal SSA/backend atom identity without requiring ValueId."""

    row = dict(row or {})
    for key in ("value_id", "atom_id", "backend_atom_id", "binding_id"):
        value = row.get(key)
        if isinstance(value, str) and value:
            return value
    atom = row.get("atom")
    if isinstance(atom, str) and atom:
        return atom
    if isinstance(atom, dict):
        for key in ("id", "atom_id", "binding_id"):
            value = atom.get(key)
            if isinstance(value, str) and value:
                return value
    binding = row.get("backend_binding")
    if isinstance(binding, dict):
        for key in ("atom_id", "id", "binding_id"):
            value = binding.get(key)
            if isinstance(value, str) and value:
                return value
    return ""


def _public_value_id(row: dict[str, Any] | None) -> str:
    value = dict(row or {}).get("value_id")
    return value if isinstance(value, str) else ""


def _parse_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value or "").strip().lower()
    if not text:
        return None
    try:
        return int(text, 16) if text.startswith("0x") else int(text, 16)
    except ValueError:
        return None


def _backend_storage_object(object_id: str) -> bool:
    return str(object_id or "").startswith(("reg:", "unique:", "param:"))


def _access_path_offset(path: list[Any]) -> int | None:
    items = [str(item) for item in path]
    start = max((index + 1 for index, item in enumerate(items) if item == "deref"), default=0)
    total = 0
    for item in items[start:]:
        if item.startswith("byte_offset:") or item.startswith("field_offset:"):
            try:
                total += int(item.split(":", 1)[1], 0)
            except ValueError:
                return None
        elif item != "deref":
            return None
    return total


@dataclass(frozen=True)
class Region:
    """A byte region within one shared object."""

    object_id: str
    start: int | None = None
    end: int | None = None
    relative: bool = False
    precision: str = "OBJECT_WIDE"

    def to_json(self) -> dict[str, Any]:
        return {
            "object_id": self.object_id,
            "start": hex(self.start) if self.start is not None else "",
            "end": hex(self.end) if self.end is not None else "",
            "relative": self.relative,
            "precision": self.precision,
        }


def _call_argument_nodes(op: dict[str, Any]) -> list[dict[str, Any]]:
    inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
    if not inputs:
        return []
    call = dict(op.get("call", {}) or {})
    declared = list(call.get("argument_value_ids", []) or [])
    if declared and len(inputs) == len(declared):
        return inputs
    # High P-code CALL/CALLIND input zero is the target varnode.
    return inputs[1:]


def _channel_kind(raw_kind: str) -> str:
    return {
        "OBJECT_READ": "CHANNEL_READ",
        "OBJECT_WRITE": "CHANNEL_WRITE",
        "CHANNEL_READ": "CHANNEL_READ",
        "CHANNEL_WRITE": "CHANNEL_WRITE",
    }.get(raw_kind, "")


def _heuristic_channel_edge(edge: dict[str, Any], object_node: dict[str, Any]) -> bool:
    if edge.get("deterministic") is False or edge.get("strict_admissible") is False:
        return True
    fields = (
        edge.get("edge_id", ""),
        edge.get("object_id", ""),
        edge.get("evidence_level", ""),
        edge.get("provenance", ""),
        edge.get("address_provenance", ""),
        edge.get("resolution", ""),
        object_node.get("identity_kind", ""),
        object_node.get("evidence_level", ""),
    )
    joined = " ".join(str(value).upper() for value in fields)
    return any(
        marker in joined
        for marker in ("HEURISTIC", "LEGACY", "FALLBACK", "CLUSTER", "MAY_ALIAS", "APPROX")
    )


_BLOCKER_RELATION_PRIORITY = (
    (
        "SINK_PARAMETER_BINDING",
        ("sink_parameter", "backend_atom_binding", "site_atom"),
    ),
    (
        "CALL_TARGET_RESOLUTION",
        (
            "indirect_call_target",
            "ambiguous_call_target",
            "call_target",
            "finite_table",
        ),
    ),
    (
        "CALL_ACTUAL_FORMAL_OR_RETURN",
        (
            "call_binding",
            "call_return",
            "formal_parameter",
            "output_actual",
            "output_stored_value",
        ),
    ),
    (
        "OBJECT_OR_REGION_IDENTITY",
        (
            "object_definition",
            "shared_region",
            "overlapping_channel",
            "region",
        ),
    ),
    (
        "CHANNELGRAPH_RELATION",
        ("channel_write", "channel_edge", "channel_depth"),
    ),
    (
        "SOURCE_ASSOCIATION",
        ("source_association", "source_memory_output", "source_definition"),
    ),
    (
        "ANALYSIS_BUDGET",
        ("budget", "depth_exhausted", "alternative_exhausted"),
    ),
    ("LOCAL_DATA_FLOW_EFFECT", ("unmodeled_origin",)),
)


def first_missing_relation(
    blockers: set[str] | list[str],
) -> dict[str, Any] | None:
    """Classify an unresolved path while retaining its precise blockers."""

    normalized = sorted({str(item) for item in blockers if str(item)})
    for relation, markers in _BLOCKER_RELATION_PRIORITY:
        matches = [
            blocker
            for blocker in normalized
            if any(marker in blocker for marker in markers)
        ]
        if matches:
            return {"relation": relation, "blockers": matches}
    if normalized:
        return {"relation": "UNCLASSIFIED_RELATION", "blockers": normalized}
    return None


class UnifiedGraph:
    """One typed graph used by both candidate discovery and backward RDA."""

    EDGE_KINDS = {"CALL", "CALLIND", "CHANNEL_WRITE", "CHANNEL_READ"}

    def __init__(
        self,
        program_facts: dict[str, Any],
        graph_artifact: dict[str, Any],
        *,
        strict: bool = False,
        allow_may_channel: bool = False,
        graph_mode: str = "unified",
    ) -> None:
        self.strict = strict
        self.allow_may_channel = allow_may_channel
        if graph_mode not in {"unified", "callgraph-only"}:
            raise ValueError(f"unsupported graph mode: {graph_mode}")
        self.graph_mode = graph_mode
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []
        self.rejected_channel_edges: list[dict[str, Any]] = []
        self.incoming: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.outgoing: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.calls_to: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.calls_by_site: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.reads_by_site: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.reads_by_value_atom: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.writes_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.rejected_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.ops_by_site: dict[str, tuple[str, dict[str, Any]]] = {}
        self.object_nodes: dict[str, dict[str, Any]] = {}
        self.resolved_object_by_atom: dict[str, str] = {}

        self.functions = {
            str(function.get("function_id", "")): function
            for function in list(program_facts.get("functions", []) or [])
            if str(function.get("function_id", ""))
        }
        for function_id, function in self.functions.items():
            self._add_node(
                {
                    "node_id": function_id,
                    "node_kind": "FUNCTION",
                    "name": str(function.get("name", "")),
                    "entry": str(function.get("entry", "")),
                }
            )
            for op in list(function.get("pcode_ops", []) or []):
                site_id = str(op.get("site_id", ""))
                if site_id:
                    self.ops_by_site[site_id] = (function_id, op)

        canonical_nodes = graph_artifact.get("nodes")
        if isinstance(canonical_nodes, list):
            for raw_node in canonical_nodes:
                node = dict(raw_node or {})
                node_kind = str(node.get("node_kind", ""))
                if node_kind == "FUNCTION":
                    function_id = str(node.get("node_id", ""))
                    if function_id:
                        self._add_node(node)
                elif node_kind == "SHARED_OBJECT":
                    object_id = str(node.get("object_id", "") or node.get("node_id", ""))
                    if not object_id:
                        continue
                    normalized = {**node, "node_id": object_id, "object_id": object_id}
                    self.object_nodes[object_id] = normalized
                    self._add_node(normalized)
        else:
            # Compatibility with pre-unified ChannelGraph artifacts.
            for node in list(graph_artifact.get("function_nodes", []) or []):
                function_id = str(node.get("node_id", ""))
                if function_id:
                    self._add_node({**dict(node), "node_kind": "FUNCTION"})
            for node in list(graph_artifact.get("object_nodes", []) or []):
                object_id = str(node.get("object_id", "") or node.get("node_id", ""))
                if not object_id:
                    continue
                normalized = {**dict(node), "node_id": object_id, "object_id": object_id}
                normalized["node_kind"] = "SHARED_OBJECT"
                self.object_nodes[object_id] = normalized
                self._add_node(normalized)

        bindings = list(graph_artifact.get("value_object_bindings", []) or [])
        bindings.extend(list(program_facts.get("value_object_bindings", []) or []))
        alias_objects_by_atom: dict[str, set[str]] = defaultdict(set)
        for binding in bindings:
            binding = dict(binding or {})
            atom_id = _identity(binding)
            object_id = str(binding.get("object_id", ""))
            if atom_id and object_id:
                alias_objects_by_atom[atom_id].add(object_id)
        for atom_id, object_ids in alias_objects_by_atom.items():
            if len(object_ids) == 1:
                self.resolved_object_by_atom[atom_id] = next(iter(object_ids))

        canonical_edges = graph_artifact.get("edges")
        if isinstance(canonical_edges, list):
            raw_call_edges = [
                dict(edge or {})
                for edge in canonical_edges
                if str(dict(edge or {}).get("edge_kind", "")) in {"CALL", "CALLIND"}
            ]
            raw_channel_edges = [
                dict(edge or {})
                for edge in canonical_edges
                if str(dict(edge or {}).get("edge_kind", ""))
                in {"CHANNEL_READ", "CHANNEL_WRITE"}
            ]
        else:
            raw_call_edges = [
                dict(edge or {})
                for edge in list(graph_artifact.get("call_edges", []) or [])
            ]
            raw_channel_edges = [
                dict(edge or {})
                for edge in list(graph_artifact.get("channel_edges", []) or [])
            ]

        for raw_edge in raw_call_edges:
            self._add_call_edge(raw_edge)
        call_sites = {
            str(edge.get("site_id", ""))
            for edge in self.edges
            if str(edge.get("edge_kind", "")) in {"CALL", "CALLIND"}
        }
        for site_id, (_function_id, op) in self.ops_by_site.items():
            if str(op.get("mnemonic", "")) not in {"CALL", "CALLIND"} or site_id in call_sites:
                continue
            self._add_call_edge(self._call_edge_from_op(site_id, op))

        if self.graph_mode == "unified":
            for raw_edge in raw_channel_edges:
                self._add_channel_edge(raw_edge)
        # Strict mode consumes the builder's admitted CHANNEL edges verbatim.
        # Reconstructing arbitrary LOAD/STORE edges here would bypass the
        # SourceDefinition, Region-overlap, and cross-context proof policy.
        if (
            self.graph_mode == "unified"
            and not self.strict
            and not isinstance(canonical_edges, list)
        ):
            self._add_backend_channel_edges()
        self._index_edges()

    def _add_node(self, node: dict[str, Any]) -> None:
        node_id = str(node.get("node_id", ""))
        if not node_id:
            return
        existing = self.nodes.get(node_id, {})
        self.nodes[node_id] = {**existing, **node}

    def _ensure_object_node(self, object_id: str) -> None:
        if not object_id:
            return
        if object_id not in self.object_nodes:
            node = {
                "node_id": object_id,
                "object_id": object_id,
                "node_kind": "SHARED_OBJECT",
                "address_range": [],
                "identity_kind": "BACKEND_OBJECT_BINDING",
            }
            self.object_nodes[object_id] = node
            self._add_node(node)

    def aliases(self, object_id: str) -> set[str]:
        aliases = canonical_object_ids(object_id)
        node = self.object_nodes.get(object_id, {})
        for key in ("object_id", "node_id", "source_object_id", "legacy_object_id"):
            aliases.update(canonical_object_ids(str(node.get(key, ""))))
        return aliases

    def same_object(self, left: str, right: str) -> bool:
        return bool(self.aliases(left) & self.aliases(right))

    def _node_interval(self, object_id: str) -> tuple[int, int] | None:
        raw = list(self.object_nodes.get(object_id, {}).get("address_range", []) or [])
        if len(raw) < 2:
            return None
        start, end = _parse_int(raw[0]), _parse_int(raw[1])
        if start is None or end is None or end < start:
            return None
        return start, end

    def _region_from_edge(
        self,
        edge: dict[str, Any],
        *,
        op: dict[str, Any] | None = None,
        kind: str,
    ) -> Region:
        object_id = str(edge.get("object_id", ""))
        raw_region = edge.get("region")
        start: int | None = None
        end: int | None = None
        relative = False
        if isinstance(raw_region, (list, tuple)) and len(raw_region) >= 2:
            start, end = _parse_int(raw_region[0]), _parse_int(raw_region[1])
        elif isinstance(raw_region, dict):
            object_id = str(raw_region.get("object_id", "") or object_id)
            if "offset" in raw_region:
                start = _parse_int(raw_region.get("offset"))
                relative = True
            else:
                start = _parse_int(raw_region.get("start", raw_region.get("address")))
            size = _parse_int(
                raw_region.get(
                    "size", raw_region.get("extent", raw_region.get("width"))
                )
            )
            # Builder regions may retain an absolute ``end`` for human
            # evidence while ``offset`` is object-relative. Prefer the extent
            # whenever an offset is present so coordinate systems are not
            # mixed during overlap tests.
            end = (
                None
                if relative and size
                else _parse_int(raw_region.get("end"))
            )
            if end is None and start is not None and size:
                end = start + max(1, size) - 1
        if start is None:
            start = _parse_int(edge.get("region_start", edge.get("address")))
            end = _parse_int(edge.get("region_end"))
        if start is None and op:
            inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
            address_node: dict[str, Any] = {}
            value_node: dict[str, Any] = {}
            if kind == "CHANNEL_READ" and inputs:
                address_node = inputs[-1]
                value_node = dict(op.get("output", {}) or {})
            elif kind == "CHANNEL_WRITE" and len(inputs) >= 2:
                address_node = inputs[-2]
                value_node = inputs[-1]
            if str(address_node.get("space", "")) == "ram" or bool(address_node.get("is_address")):
                start = _parse_int(address_node.get("offset"))
                width = int(edge.get("access_width", 0) or value_node.get("size", 0) or 0)
                if start is not None:
                    end = start + max(1, width) - 1
        if start is not None:
            if end is None:
                width = int(edge.get("access_width", 0) or 0)
                end = start + max(1, width) - 1
            return Region(object_id, start, end, relative, "EXACT_ACCESS_RANGE")
        interval = self._node_interval(object_id)
        if interval:
            return Region(object_id, interval[0], interval[1], False, "OBJECT_ADDRESS_RANGE")
        return Region(object_id)

    def regions_overlap(self, left: Region, right: Region) -> bool:
        if not self.same_object(left.object_id, right.object_id):
            return False
        if left.start is None or left.end is None or right.start is None or right.end is None:
            return True
        left_start, left_end = left.start, left.end
        right_start, right_end = right.start, right.end
        if left.relative != right.relative:
            interval = self._node_interval(left.object_id) or self._node_interval(right.object_id)
            if interval:
                base = interval[0]
                if left.relative:
                    left_start, left_end = base + left_start, base + left_end
                if right.relative:
                    right_start, right_end = base + right_start, base + right_end
            else:
                return True
        return max(left_start, right_start) <= min(left_end, right_end)

    def _call_edge_from_op(self, site_id: str, op: dict[str, Any]) -> dict[str, Any]:
        function_id = self.ops_by_site.get(site_id, ("", {}))[0]
        mnemonic = str(op.get("mnemonic", ""))
        call = dict(op.get("call", {}) or {})
        target_id = str(call.get("target_function_id", ""))
        if not target_id:
            target_id = f"unknown-call-target:{site_id}"
        return {
            "edge_id": f"call:{site_id}",
            "src_node_id": function_id,
            "dst_node_id": target_id,
            "site_id": site_id,
            "edge_kind": mnemonic,
            "resolution": "DIRECT" if mnemonic == "CALL" and not target_id.startswith("unknown-") else "UNRESOLVED_INDIRECT",
        }

    def _add_call_edge(self, raw: dict[str, Any]) -> None:
        kind = str(raw.get("edge_kind", ""))
        if kind not in {"CALL", "CALLIND"}:
            return
        site_id = str(raw.get("site_id", ""))
        src = str(raw.get("src_node_id", ""))
        dst = str(raw.get("dst_node_id", ""))
        if not src or not dst:
            return
        op = self.ops_by_site.get(site_id, ("", {}))[1]
        nodes = _call_argument_nodes(op)
        raw_bindings = list(raw.get("argument_bindings", []) or [])
        value_ids = list(raw.get("argument_value_ids", []) or [])
        atom_ids = list(raw.get("argument_atom_ids", []) or [])
        object_ids = list(raw.get("argument_object_ids", []) or [])
        resolved_ids = list(raw.get("resolved_argument_object_ids", []) or [])
        count = max(len(nodes), len(raw_bindings), len(value_ids), len(atom_ids), len(object_ids), len(resolved_ids))
        arguments: list[dict[str, Any]] = []
        for slot in range(count):
            node = nodes[slot] if slot < len(nodes) else {}
            binding = dict(raw_bindings[slot] or {}) if slot < len(raw_bindings) else {}
            value_id = str(binding.get("value_id", ""))
            if not value_id and slot < len(value_ids):
                value_id = str(value_ids[slot])
            if not value_id:
                value_id = _public_value_id(node)
            atom_id = _identity(binding)
            if not atom_id and slot < len(atom_ids):
                atom_id = str(atom_ids[slot])
            if not atom_id:
                atom_id = _identity(node) or value_id
            object_id = str(binding.get("object_id", ""))
            if not object_id and slot < len(resolved_ids) and resolved_ids[slot]:
                object_id = str(resolved_ids[slot])
            if not object_id and slot < len(object_ids):
                object_id = str(object_ids[slot])
            if not object_id:
                object_id = str(node.get("object_id", ""))
            arguments.append(
                {
                    "slot": slot,
                    "atom_id": atom_id,
                    "value_id": value_id,
                    "object_id": object_id,
                }
            )
        edge = {
            **raw,
            "edge_id": str(raw.get("edge_id", "") or f"call:{site_id}:{dst}"),
            "src_node_id": src,
            "dst_node_id": dst,
            "site_id": site_id,
            "edge_kind": kind,
            "argument_bindings": arguments,
            "analysis_precision": str(raw.get("analysis_precision", "EXACT")),
            "recognition": str(raw.get("recognition", "deterministic")),
            "evidence": {
                "resolution": str(raw.get("resolution", "")),
                "provenance": str(raw.get("provenance", "")),
                "analysis_precision": str(raw.get("analysis_precision", "EXACT")),
            },
        }
        self._append_edge(edge)

    def _append_edge(self, edge: dict[str, Any]) -> None:
        edge_id = str(edge.get("edge_id", ""))
        if not edge_id or any(str(item.get("edge_id", "")) == edge_id for item in self.edges):
            return
        self.edges.append(edge)
        self._add_node({"node_id": str(edge.get("src_node_id", ""))})
        self._add_node({"node_id": str(edge.get("dst_node_id", ""))})

    def _binding_for_access(
        self, raw: dict[str, Any], op: dict[str, Any], kind: str
    ) -> tuple[str, str, str]:
        value_id = str(raw.get("value_id", ""))
        atom_id = str(raw.get("value_atom_id", "")) or _identity(raw)
        object_id = str(raw.get("value_object_id", ""))
        inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
        node: dict[str, Any] = {}
        if kind == "CHANNEL_READ":
            node = dict(op.get("output", {}) or {})
        elif kind == "CHANNEL_WRITE" and inputs:
            node = inputs[-1]
        if not value_id:
            value_id = _public_value_id(node)
        if not atom_id:
            atom_id = _identity(node) or value_id
        if not object_id:
            object_id = str(node.get("object_id", ""))
        return atom_id, value_id, object_id

    def _add_channel_edge(self, raw: dict[str, Any]) -> None:
        kind = _channel_kind(str(raw.get("edge_kind", "")))
        if not kind:
            return
        object_id = str(raw.get("object_id", ""))
        if not object_id:
            object_id = str(raw.get("src_node_id" if kind == "CHANNEL_READ" else "dst_node_id", ""))
        if not object_id:
            return
        self._ensure_object_node(object_id)
        object_node = self.object_nodes.get(object_id, {})
        if (
            self.strict
            and _heuristic_channel_edge(raw, object_node)
            and not (
                self.allow_may_channel
                and bool(raw.get("strict_admissible"))
                and str(raw.get("analysis_precision", "")) == "MAY"
            )
        ):
            rejected = {
                **raw,
                "edge_kind": kind,
                "object_id": object_id,
                "rejection_reason": "strict_mode_rejected_heuristic_or_legacy_channel_edge",
            }
            self.rejected_channel_edges.append(rejected)
            return
        site_id = str(raw.get("site_id", ""))
        function_id, op = self.ops_by_site.get(site_id, ("", {}))
        src = str(raw.get("src_node_id", ""))
        dst = str(raw.get("dst_node_id", ""))
        if kind == "CHANNEL_READ":
            src = object_id
            dst = dst or function_id
        else:
            src = src or function_id
            dst = object_id
        if not (dst if kind == "CHANNEL_READ" else src):
            function_node_id = f"unknown-function:{site_id or raw.get('edge_id', '')}"
            self._add_node(
                {
                    "node_id": function_node_id,
                    "node_kind": "FUNCTION",
                    "name": "",
                    "synthetic": True,
                }
            )
            if kind == "CHANNEL_READ":
                dst = function_node_id
            else:
                src = function_node_id
        if not src or not dst:
            return
        atom_id, value_id, value_object_id = self._binding_for_access(raw, op, kind)
        region = self._region_from_edge(raw, op=op, kind=kind)
        edge = {
            **raw,
            "edge_id": str(raw.get("edge_id", "") or f"channel:{kind.lower()}:{site_id}:{object_id}"),
            "src_node_id": src,
            "dst_node_id": dst,
            "site_id": site_id,
            "edge_kind": kind,
            "input_edge_kind": str(raw.get("edge_kind", "")),
            "object_id": object_id,
            "value_atom_id": atom_id,
            "value_id": value_id,
            "value_object_id": value_object_id,
            "region": region.to_json(),
            "_region": region,
            "evidence": {
                "evidence_level": str(raw.get("evidence_level", "")),
                "address_provenance": str(raw.get("address_provenance", "")),
                "context_ids": list(raw.get("context_ids", []) or []),
                "source_id": str(raw.get("source_id", "")),
                "analysis_precision": str(raw.get("analysis_precision", "EXACT")),
                "assumptions": list(raw.get("assumptions", []) or []),
            },
        }
        self._append_edge(edge)

    def _stable_backend_object(self, node: dict[str, Any]) -> str:
        atom_id = _identity(node)
        resolved = self.resolved_object_by_atom.get(atom_id, "")
        if resolved:
            return resolved
        object_id = str(node.get("object_id", ""))
        if object_id.startswith(("obj:", "global:", "source-object:")):
            return object_id
        return ""

    def _add_backend_channel_edges(self) -> None:
        accepted_sites = {
            (str(edge.get("site_id", "")), str(edge.get("edge_kind", "")))
            for edge in self.edges
            if str(edge.get("edge_kind", "")).startswith("CHANNEL_")
        }
        for site_id, (function_id, op) in self.ops_by_site.items():
            mnemonic = str(op.get("mnemonic", ""))
            inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
            if mnemonic == "LOAD" and inputs:
                kind = "CHANNEL_READ"
                address_node = inputs[-1]
                value_node = dict(op.get("output", {}) or {})
            elif mnemonic == "STORE" and len(inputs) >= 2:
                kind = "CHANNEL_WRITE"
                address_node = inputs[-2]
                value_node = inputs[-1]
            else:
                continue
            if (site_id, kind) in accepted_sites:
                continue
            object_id = self._stable_backend_object(address_node)
            if not object_id:
                continue
            raw = {
                "edge_id": f"backend:{kind.lower()}:{site_id}:{object_id}",
                "src_node_id": object_id if kind == "CHANNEL_READ" else function_id,
                "dst_node_id": function_id if kind == "CHANNEL_READ" else object_id,
                "site_id": site_id,
                "edge_kind": kind,
                "object_id": object_id,
                "value_atom_id": _identity(value_node),
                "value_id": _public_value_id(value_node),
                "value_object_id": str(value_node.get("object_id", "")),
                "access_width": int(value_node.get("size", 0) or 0),
                "evidence_level": "DETERMINISTIC_BACKEND_HIGH_PCODE_ACCESS",
                "address_provenance": "BACKEND_ATOM_BINDING",
            }
            self._add_channel_edge(raw)

    def _index_edges(self) -> None:
        for edge in self.edges:
            src = str(edge.get("src_node_id", ""))
            dst = str(edge.get("dst_node_id", ""))
            self.outgoing[src].append(edge)
            self.incoming[dst].append(edge)
            kind = str(edge.get("edge_kind", ""))
            if kind in {"CALL", "CALLIND"}:
                self.calls_to[dst].append(edge)
                self.calls_by_site[str(edge.get("site_id", ""))].append(edge)
            elif kind == "CHANNEL_READ":
                self.reads_by_site[str(edge.get("site_id", ""))].append(edge)
                value_atom = str(edge.get("value_atom_id", ""))
                if value_atom:
                    self.reads_by_value_atom[value_atom].append(edge)
            elif kind == "CHANNEL_WRITE":
                for alias in self.aliases(str(edge.get("object_id", ""))):
                    self.writes_by_object[alias].append(edge)
        for edge in self.rejected_channel_edges:
            for alias in self.aliases(str(edge.get("object_id", ""))):
                self.rejected_by_object[alias].append(edge)

    def writers_for(self, region: Region) -> tuple[list[dict[str, Any]], bool]:
        candidates: list[dict[str, Any]] = []
        seen: set[str] = set()
        for alias in self.aliases(region.object_id):
            for edge in self.writes_by_object.get(alias, []):
                edge_id = str(edge.get("edge_id", ""))
                if edge_id in seen:
                    continue
                seen.add(edge_id)
                candidates.append(edge)
        overlapping = [
            edge for edge in candidates if self.regions_overlap(region, edge["_region"])
        ]
        return overlapping, bool(candidates and not overlapping)

    def rejected_for(self, object_id: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        seen: set[str] = set()
        for alias in self.aliases(object_id):
            for edge in self.rejected_by_object.get(alias, []):
                edge_id = str(edge.get("edge_id", ""))
                if edge_id not in seen:
                    seen.add(edge_id)
                    rows.append(edge)
        return rows

    def reverse_bfs(
        self,
        start_node_id: str,
        *,
        max_steps: int,
        max_trace_witnesses: int = 64,
    ) -> dict[str, Any]:
        """Run the single mixed CALL+CHANNEL candidate traversal for one sink."""

        if not start_node_id or start_node_id not in self.nodes:
            return {
                "status": "GRAPH_INCOMPLETE",
                "start_node_id": start_node_id,
                "candidate_traces": [],
                "allowed_edge_ids": [],
                "allowed_node_ids": [],
                "visited_nodes": 0,
                "steps": 0,
                "frontier": [],
                "blockers": ["sink_function_not_in_unified_graph"],
            }
        # The same function may legitimately appear on both sides of a
        # persistent-region handoff (write in one event invocation, read in a
        # later invocation). Track Channelgraph depth in the BFS state instead
        # of globally suppressing that re-entry.
        queue = deque([(start_node_id, [start_node_id], [], 0)])
        visited: set[tuple[str, int]] = set()
        traversed_edges: set[str] = set()
        traces: list[dict[str, Any]] = []
        trace_count = 0
        mixed_trace_count = 0
        steps = 0
        max_channel_hops = 8
        while queue and steps < max_steps:
            node_id, node_path, edge_path, channel_hops = queue.popleft()
            state_key = (node_id, channel_hops)
            if state_key in visited:
                continue
            visited.add(state_key)
            steps += 1
            if (
                self.nodes.get(node_id, {}).get("node_kind") == "FUNCTION"
                and (node_id != start_node_id or bool(edge_path))
            ):
                kinds = [str(edge.get("edge_kind", "")) for edge in edge_path]
                mixed = bool(
                    any(kind in {"CALL", "CALLIND"} for kind in kinds)
                    and any(kind.startswith("CHANNEL_") for kind in kinds)
                )
                trace_count += 1
                mixed_trace_count += int(mixed)
                witness = {
                    "trace_id": f"trace:{start_node_id}:{trace_count}",
                    "start_node_id": start_node_id,
                    "end_node_id": node_id,
                    "node_ids": node_path,
                    "edge_ids": [str(edge.get("edge_id", "")) for edge in edge_path],
                    "edge_kinds": kinds,
                    "mixed": mixed,
                    "edges": [self._public_edge(edge) for edge in edge_path],
                }
                witness_limit = max(0, int(max_trace_witnesses))
                if len(traces) < witness_limit:
                    traces.append(witness)
                elif mixed and traces and not any(
                    bool(trace.get("mixed")) for trace in traces
                ):
                    # Keep at least one Channelgraph-assisted witness when the
                    # early reverse-Callgraph prefixes filled the audit budget.
                    traces[-1] = witness
            neighbors: list[tuple[dict[str, Any], str, str]] = []
            for edge in self.incoming.get(node_id, []):
                neighbors.append((edge, str(edge.get("src_node_id", "")), "REVERSE"))
            # Reverse BFS follows Callgraph predecessors only. Direct callees of
            # a visited function are admitted as local RDA summary edges, but
            # are not enqueued; otherwise one sink expands through every call
            # made by every caller and quickly becomes a whole-program walk.
            for edge in self.outgoing.get(node_id, []):
                if str(edge.get("edge_kind", "")) in {"CALL", "CALLIND"}:
                    traversed_edges.add(str(edge.get("edge_id", "")))
            for edge, predecessor, transfer in neighbors:
                edge_id = str(edge.get("edge_id", ""))
                traversed_edges.add(edge_id)
                if not predecessor or any(
                    str(prior.get("edge_id", "")) == edge_id for prior in edge_path
                ):
                    continue
                next_channel_hops = channel_hops + (
                    1
                    if str(edge.get("edge_kind", ""))
                    in {"CHANNEL_READ", "CHANNEL_WRITE"}
                    else 0
                )
                if next_channel_hops > max_channel_hops:
                    continue
                step = {**edge, "backward_transfer": transfer}
                queue.append(
                    (
                        predecessor,
                        node_path + [predecessor],
                        edge_path + [step],
                        next_channel_hops,
                    )
                )
        frontier = [node_id for node_id, _nodes, _edges, _hops in list(queue)[:16]]
        status = "ANALYSIS_BUDGET_EXHAUSTED" if queue else "COMPLETE"
        return {
            "status": status,
            "start_node_id": start_node_id,
            "candidate_traces": traces,
            "candidate_trace_count": trace_count,
            "mixed_candidate_trace_count": mixed_trace_count,
            "candidate_traces_truncated": trace_count > len(traces),
            "max_trace_witnesses": max(0, int(max_trace_witnesses)),
            "allowed_edge_ids": sorted(traversed_edges),
            "allowed_node_ids": sorted({node_id for node_id, _hops in visited}),
            "visited_nodes": len(visited),
            "steps": steps,
            "frontier": frontier,
            "blockers": ["analysis_budget_exhausted"] if queue else [],
        }

    def _public_edge(self, edge: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in edge.items()
            if key
            in {
                "edge_id",
                "src_node_id",
                "dst_node_id",
                "site_id",
                "edge_kind",
                "object_id",
                "region",
                "evidence",
                "backward_transfer",
                "source_id",
            }
        }

    def to_artifact(self) -> dict[str, Any]:
        return {
            "node_model": "FUNCTION_PLUS_SHARED_OBJECT",
            "edge_kinds": sorted(self.EDGE_KINDS),
            "strict_mode": self.strict,
            "allow_may_channel": self.allow_may_channel,
            "nodes": [dict(node) for node in self.nodes.values()],
            "edges": [self._public_edge(edge) for edge in self.edges],
            "rejected_channel_edges": [
                {
                    "edge_id": str(edge.get("edge_id", "")),
                    "site_id": str(edge.get("site_id", "")),
                    "edge_kind": str(edge.get("edge_kind", "")),
                    "object_id": str(edge.get("object_id", "")),
                    "evidence_level": str(edge.get("evidence_level", "")),
                    "rejection_reason": str(edge.get("rejection_reason", "")),
                }
                for edge in self.rejected_channel_edges
            ],
            "counts": {
                "nodes": len(self.nodes),
                "function_nodes": sum(
                    node.get("node_kind") == "FUNCTION" for node in self.nodes.values()
                ),
                "shared_object_nodes": sum(
                    node.get("node_kind") == "SHARED_OBJECT" for node in self.nodes.values()
                ),
                "edges": len(self.edges),
                "rejected_channel_edges": len(self.rejected_channel_edges),
            },
        }


class ProgramIndex:
    def __init__(
        self,
        program_facts: dict[str, Any],
        channel_graph: dict[str, Any],
        *,
        strict: bool = False,
        allow_may_channel: bool = False,
        graph_mode: str = "unified",
        max_function_depth: int = 3,
        max_summary_ops: int = 256,
        max_summary_alternatives: int = 8,
    ):
        self.strict = strict
        self.allow_may_channel = allow_may_channel
        self.graph = UnifiedGraph(
            program_facts,
            channel_graph,
            strict=strict,
            allow_may_channel=allow_may_channel,
            graph_mode=graph_mode,
        )
        self.functions = {
            str(function.get("function_id", "")): function
            for function in list(program_facts.get("functions", []) or [])
            if str(function.get("function_id", ""))
        }
        self.ops_by_site: dict[str, tuple[str, dict[str, Any]]] = {}
        self.defs_by_atom: dict[str, tuple[str, dict[str, Any]]] = {}
        self.varnodes_by_atom: dict[str, tuple[str, dict[str, Any]]] = {}
        # Compatibility aliases retained for callers that still name ValueId.
        self.defs_by_value = self.defs_by_atom
        self.varnodes_by_value = self.varnodes_by_atom
        self.calls_to = self.graph.calls_to
        self.returns_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.writers_by_object = self.graph.writes_by_object
        self.resolved_object_by_atom = dict(self.graph.resolved_object_by_atom)
        self.resolved_object_by_value = self.resolved_object_by_atom
        self.public_value_by_atom: dict[str, str] = {}
        self.backend_bindings_by_site_slot: dict[tuple[str, int], dict[str, Any]] = {}
        self.op_position_by_site: dict[str, int] = {}
        self.store_objects_by_function: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
        self.primitive_effects_by_output_atom: dict[
            str, list[dict[str, Any]]
        ] = defaultdict(list)
        self.primitive_effects_by_destination_object: dict[
            str, list[dict[str, Any]]
        ] = defaultdict(list)
        self.call_output_effects_by_destination_object: dict[
            str, list[dict[str, Any]]
        ] = defaultdict(list)
        self.container_aliases_by_atom: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.object_region_by_atom: dict[str, tuple[str, int]] = {}

        raw_object_bindings: list[dict[str, Any]] = []
        raw_object_bindings.extend(
            dict(row or {})
            for row in list(program_facts.get("value_object_bindings", []) or [])
        )
        raw_object_bindings.extend(
            dict(row or {})
            for row in list(channel_graph.get("value_object_bindings", []) or [])
        )
        region_candidates: dict[str, set[tuple[str, int]]] = defaultdict(set)
        for binding in raw_object_bindings:
            atom_id = _identity(binding)
            object_id = str(binding.get("object_id", ""))
            offset = _access_path_offset(list(binding.get("access_path", []) or []))
            if atom_id and object_id and offset is not None:
                region_candidates[atom_id].add((object_id, offset))
        self.object_region_by_atom = {
            atom_id: next(iter(candidates))
            for atom_id, candidates in region_candidates.items()
            if len(candidates) == 1
        }

        for function_id, function in self.functions.items():
            for parameter in list(function.get("parameters", []) or []):
                parameter = dict(parameter or {})
                slot = parameter.get("index")
                if isinstance(slot, int):
                    parameter.setdefault("parameter_slot", slot)
                    parameter.setdefault("is_parameter", True)
                atom_id = _identity(parameter) or str(parameter.get("object_id", ""))
                if atom_id:
                    self.varnodes_by_atom[atom_id] = (function_id, parameter)
                    self.public_value_by_atom[atom_id] = _public_value_id(parameter)
            for op_position, op in enumerate(list(function.get("pcode_ops", []) or [])):
                if str(op.get("mnemonic", "")) == "RETURN":
                    self.returns_by_function[function_id].append(op)
                site_id = str(op.get("site_id", ""))
                if site_id:
                    self.ops_by_site[site_id] = (function_id, op)
                    self.op_position_by_site[site_id] = op_position
                output = dict(op.get("output", {}) or {})
                atom_id = _identity(output)
                if atom_id:
                    self.defs_by_atom[atom_id] = (function_id, op)
                    self.varnodes_by_atom[atom_id] = (function_id, output)
                    self.public_value_by_atom[atom_id] = _public_value_id(output)
                for node in list(op.get("inputs", []) or []):
                    node = dict(node or {})
                    node_atom = _identity(node)
                    if node_atom and node_atom not in self.varnodes_by_atom:
                        self.varnodes_by_atom[node_atom] = (function_id, node)
                        self.public_value_by_atom[node_atom] = _public_value_id(node)
                if str(op.get("mnemonic", "")) == "STORE":
                    inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
                    if len(inputs) >= 2:
                        address_node = inputs[-2]
                        address_atom = _identity(address_node)
                        store_object = str(address_node.get("object_id", ""))
                        store_object = self.resolved_object_by_atom.get(
                            address_atom, store_object
                        )
                        if store_object and site_id:
                            self.store_objects_by_function[function_id].append(
                                (op_position, site_id, store_object)
                            )

        for edge in self.graph.edges:
            kind = str(edge.get("edge_kind", ""))
            if kind in {"CALL", "CALLIND"}:
                for binding in list(edge.get("argument_bindings", []) or []):
                    atom_id = str(binding.get("atom_id", ""))
                    object_id = str(binding.get("object_id", ""))
                    if atom_id and object_id:
                        existing = self.resolved_object_by_atom.get(atom_id, "")
                        if not existing or (
                            _backend_storage_object(existing)
                            and not _backend_storage_object(object_id)
                        ):
                            self.resolved_object_by_atom[atom_id] = object_id
            elif kind == "CHANNEL_READ":
                atom_id = str(edge.get("value_atom_id", ""))
                object_id = str(edge.get("object_id", ""))
                if atom_id and object_id:
                    self.resolved_object_by_atom[atom_id] = object_id

        for effect in list(channel_graph.get("primitive_memory_effects", []) or []):
            effect = dict(effect or {})
            for atom_id in list(effect.get("memory_definition_atom_ids", []) or []):
                atom_id = str(atom_id)
                if atom_id:
                    self.primitive_effects_by_output_atom[atom_id].append(effect)
            destination = dict(effect.get("destination", {}) or {})
            for object_id in {
                str(destination.get("object_id", "")),
                str(destination.get("base_object_id", "")),
                str(effect.get("destination_object_id", "")),
            } - {""}:
                self.primitive_effects_by_destination_object[object_id].append(effect)

        for effect in list(channel_graph.get("call_output_effects", []) or []):
            effect = dict(effect or {})
            destination = dict(effect.get("destination", {}) or {})
            for object_id in {
                str(destination.get("object_id", "")),
                str(destination.get("base_object_id", "")),
            } - {""}:
                self.call_output_effects_by_destination_object[object_id].append(
                    effect
                )

        for alias in list(channel_graph.get("bounded_container_aliases", []) or []):
            alias = dict(alias or {})
            loop_atom = str(alias.get("loop_atom_id", ""))
            if loop_atom:
                self.container_aliases_by_atom[loop_atom].append(alias)

        raw_backend_bindings: list[Any] = []
        for artifact in (program_facts, channel_graph):
            for key in ("backend_atom_bindings", "atom_bindings"):
                value = artifact.get(key, [])
                if isinstance(value, list):
                    raw_backend_bindings.extend(value)
        for binding in raw_backend_bindings:
            if not isinstance(binding, dict):
                continue
            site_id = str(binding.get("site_id", ""))
            slot = binding.get("argument_index", binding.get("parameter_index", binding.get("index")))
            if site_id and isinstance(slot, int):
                self.backend_bindings_by_site_slot[(site_id, slot)] = dict(binding)

        self.effect_resolver = FunctionEffectResolver(
            functions=self.functions,
            calls_by_site=self.graph.calls_by_site,
            calls_to=self.calls_to,
            resolved_object_by_atom=self.resolved_object_by_atom,
            identity=_identity,
            public_value=_public_value_id,
            same_object=self.graph.same_object,
            limits=ResolutionLimits(
                max_call_depth=max(0, max_function_depth),
                max_ops_per_summary=max(1, max_summary_ops),
                max_alternatives=max(1, max_summary_alternatives),
            ),
        )

    def sink_function_id(self, sink: dict[str, Any]) -> str:
        function_id = str(sink.get("function_id", ""))
        if function_id:
            return function_id
        site_id = str(sink.get("site_id", ""))
        if site_id in self.graph.ops_by_site:
            return self.graph.ops_by_site[site_id][0]
        name = str(sink.get("function", ""))
        return next(
            (
                candidate_id
                for candidate_id, function in self.functions.items()
                if str(function.get("name", "")) == name
            ),
            "",
        )

    def local_source_memory_definition(
        self,
        source: dict[str, Any],
        function_id: str,
        object_id: str,
        path: list[dict[str, Any]],
        use_site_hint: str = "",
    ) -> dict[str, Any] | None:
        """Prove that a modeled Source call is the local reaching memory definition."""

        if (
            str(source.get("decision", "")) != "ACCEPT_DETERMINISTIC"
            and not self.allow_may_channel
        ):
            return None
        definition = dict(source.get("_source_definition", {}) or {})
        if not definition or str(definition.get("function_id", "")) != function_id:
            return None
        outputs = [
            dict(output or {})
            for output in list(definition.get("outputs", []) or [])
            if str(dict(output or {}).get("kind", "")) == "memory_object"
        ]
        matching_outputs = []
        for output in outputs:
            output_atom = _identity(output)
            resolved_output = self.resolved_object_by_atom.get(output_atom, "")
            aliases = canonical_object_ids(str(output.get("object_id", "")))
            aliases.update(canonical_object_ids(resolved_output))
            if aliases & canonical_object_ids(object_id):
                matching_outputs.append(output)
        if not matching_outputs:
            return None
        proof = dict(definition.get("proof", {}) or {})
        proof_kind = str(proof.get("kind", ""))
        if proof_kind not in {
            "high_pcode_def_use",
            "high_pcode_profile_dma_binding",
            "high_pcode_function_summary",
            "software_interface_summary_instantiation",
        }:
            return None
        definition_site = str(
            proof.get(
                "memory_store_site_id",
                proof.get("destination_store_site_id", ""),
            )
            if proof_kind in {
                "high_pcode_def_use",
                "high_pcode_profile_dma_binding",
            }
            else proof.get("call_site_id", definition.get("site_id", ""))
        )
        definition_entry = self.ops_by_site.get(definition_site)
        if not definition_entry or definition_entry[0] != function_id:
            return None
        definition_position = self.op_position_by_site.get(definition_site)
        use_site = next(
            (
                str(step.get(key, ""))
                for step in reversed(path)
                for key in ("site_id", "call_site_id", "return_site_id")
                if str(step.get(key, "")) in self.ops_by_site
                and self.ops_by_site[str(step.get(key, ""))][0] == function_id
            ),
            "",
        )
        if (
            not use_site
            and use_site_hint in self.ops_by_site
            and self.ops_by_site[use_site_hint][0] == function_id
        ):
            use_site = use_site_hint
        use_position = self.op_position_by_site.get(use_site)
        if (
            definition_position is None
            or use_position is None
            or definition_position >= use_position
        ):
            return None
        source_store_site = str(proof.get("memory_store_site_id", ""))
        for store_position, store_site, store_object in self.store_objects_by_function.get(
            function_id, []
        ):
            if store_site == source_store_site:
                continue
            if not (definition_position < store_position < use_position):
                continue
            if canonical_object_ids(store_object) & canonical_object_ids(object_id):
                return None
        output = matching_outputs[0]
        return {
            "kind": "SOURCE_MEMORY_DEFINITION",
            "source_id": str(source.get("id", "")),
            "source_definition_id": str(definition.get("source_definition_id", "")),
            "site_id": definition_site,
            "use_site_id": use_site,
            "object_id": str(output.get("object_id", "")),
            "proof_kind": proof_kind,
        }

    def exact_source_memory_effect(
        self, source: dict[str, Any], object_id: str
    ) -> dict[str, Any] | None:
        """Validate a SourceDefinition as an exact write to an object.

        Unlike the local reaching-definition check, this relation may cross an
        execution context.  It therefore requires an explicit, body-proved
        SourceDefinition output and an exact output-value-to-object binding.
        """

        if (
            str(source.get("decision", "")) != "ACCEPT_DETERMINISTIC"
            and not self.allow_may_channel
        ):
            return None
        definition = dict(source.get("_source_definition", {}) or {})
        proof = dict(definition.get("proof", {}) or {})
        proof_kind = str(proof.get("kind", ""))
        if proof_kind not in {
            "high_pcode_def_use",
            "high_pcode_profile_dma_binding",
            "high_pcode_function_summary",
            "software_interface_summary_instantiation",
        }:
            return None
        for output in list(definition.get("outputs", []) or []):
            output = dict(output or {})
            if str(output.get("kind", "")) != "memory_object":
                continue
            output_atom = _identity(output)
            resolved_object = self.resolved_object_by_atom.get(output_atom, "")
            if not resolved_object:
                continue
            if not self.graph.same_object(resolved_object, object_id):
                continue
            site_id = str(
                proof.get(
                    "call_site_id",
                    proof.get("memory_store_site_id", definition.get("site_id", "")),
                )
            )
            op_entry = self.ops_by_site.get(site_id)
            if not op_entry:
                continue
            if proof_kind in {
                "high_pcode_function_summary",
                "software_interface_summary_instantiation",
            } and str(op_entry[1].get("mnemonic", "")) not in {"CALL", "CALLIND"}:
                continue
            return {
                "kind": "SOURCE_WRITE",
                "source_id": str(source.get("id", "")),
                "source_definition_id": str(definition.get("source_definition_id", "")),
                "site_id": site_id,
                "object_id": resolved_object,
                "proof_kind": proof_kind,
                "binding_status": str(output.get("binding_status", "")),
            }
        return None

    def bind_parameter(
        self, parameter: dict[str, Any], sink: dict[str, Any] | None
    ) -> tuple[str, str, dict[str, Any]]:
        atom_id = _identity(parameter)
        object_id = str(parameter.get("object_id", ""))
        if atom_id or object_id:
            return atom_id, object_id, {
                "kind": "PUBLIC_VALUE_ID" if _public_value_id(parameter) else "PUBLIC_OBJECT_OR_ATOM",
                "site_id": str((sink or {}).get("site_id", "")),
            }
        sink = sink or {}
        site_id = str(sink.get("site_id", ""))
        slot = parameter.get("index")
        role_binding = dict(dict(sink.get("role_bindings", {}) or {}).get(str(parameter.get("role", "")), {}) or {})
        if role_binding:
            return _identity(role_binding), str(role_binding.get("object_id", "")), {
                "kind": "BACKEND_ROLE_BINDING",
                "site_id": site_id,
            }
        if isinstance(slot, int):
            binding = self.backend_bindings_by_site_slot.get((site_id, slot), {})
            if binding:
                return _identity(binding), str(binding.get("object_id", "")), {
                    "kind": "BACKEND_ATOM_BINDING",
                    "site_id": site_id,
                    "parameter_index": slot,
                }
            call_edges = self.graph.calls_by_site.get(site_id, [])
            for edge in call_edges:
                arguments = list(edge.get("argument_bindings", []) or [])
                if 0 <= slot < len(arguments):
                    argument = dict(arguments[slot] or {})
                    return str(argument.get("atom_id", "")), str(argument.get("object_id", "")), {
                        "kind": "CALLSITE_BACKEND_ARGUMENT",
                        "site_id": site_id,
                        "parameter_index": slot,
                        "graph_edge_id": str(edge.get("edge_id", "")),
                    }
        function_op = self.graph.ops_by_site.get(site_id)
        if function_op:
            op = function_op[1]
            mnemonic = str(op.get("mnemonic", ""))
            inputs = [dict(item or {}) for item in list(op.get("inputs", []) or [])]
            node: dict[str, Any] = {}
            if mnemonic in {"CALL", "CALLIND"} and isinstance(slot, int):
                arguments = _call_argument_nodes(op)
                if 0 <= slot < len(arguments):
                    node = arguments[slot]
            elif mnemonic == "STORE":
                role = str(parameter.get("role", ""))
                if role in {"src", "value", "len"} and inputs:
                    node = inputs[-1]
                elif role == "dst" and len(inputs) >= 2:
                    node = inputs[-2]
            if node:
                return _identity(node), str(node.get("object_id", "")), {
                    "kind": "BACKEND_SITE_ATOM",
                    "site_id": site_id,
                    "parameter_index": slot,
                }
        return "", "", {"kind": "UNRESOLVED", "site_id": site_id}

    def parameter_predecessors(
        self,
        function_id: str,
        node: dict[str, Any],
        *,
        allowed_edge_ids: set[str] | None = None,
        preferred_edge_id: str = "",
    ) -> list[dict[str, Any]]:
        slot = node.get("parameter_slot")
        if not isinstance(slot, int):
            object_id = str(node.get("object_id", ""))
            match = re.search(r"param:[^:]+:(\d+)$", object_id)
            if match:
                slot = int(match.group(1))
        if not isinstance(slot, int):
            return []
        out = []
        for call in self.calls_to.get(function_id, []):
            edge_id = str(call.get("edge_id", ""))
            if preferred_edge_id and edge_id != preferred_edge_id:
                continue
            if (
                allowed_edge_ids is not None
                and edge_id not in allowed_edge_ids
                and edge_id != preferred_edge_id
            ):
                continue
            bindings = list(call.get("argument_bindings", []) or [])
            if slot >= len(bindings):
                continue
            binding = dict(bindings[slot] or {})
            out.append(
                {
                    "atom_id": str(binding.get("atom_id", "")),
                    "value_id": str(binding.get("value_id", "")),
                    "object_id": str(binding.get("object_id", "")),
                    "edge": {
                        "kind": "ACTUAL_FORMAL",
                        "graph_edge_id": edge_id,
                        "graph_edge_kind": str(call.get("edge_kind", "")),
                        "site_id": str(call.get("site_id", "")),
                        "from_function_id": str(call.get("src_node_id", "")),
                        "to_function_id": function_id,
                        "parameter_slot": slot,
                        "analysis_precision": str(
                            call.get("analysis_precision", "EXACT")
                        ),
                    },
                }
            )
        return out

    def call_return_predecessors(
        self,
        caller_function_id: str,
        op: dict[str, Any],
        *,
        allowed_edge_ids: set[str] | None = None,
        call_depth: int = 0,
    ) -> tuple[list[dict[str, Any]], str]:
        return self.effect_resolver.return_predecessors(
            caller_function_id,
            op,
            call_depth=call_depth,
            allowed_edge_ids=allowed_edge_ids,
        )

    def exact_store_predecessors(
        self,
        object_id: str,
        *,
        allowed_edge_ids: set[str] | None,
        allowed_node_ids: set[str] | None,
        exclude_function_id: str = "",
    ) -> list[dict[str, Any]]:
        return self.effect_resolver.exact_store_predecessors(
            object_id,
            allowed_edge_ids=allowed_edge_ids,
            allowed_node_ids=allowed_node_ids,
            exclude_function_id=exclude_function_id,
        )

    def call_output_predecessors(
        self,
        object_id: str,
        *,
        offset: int | None = None,
        extent: int | None = None,
        allowed_edge_ids: set[str] | None,
        allowed_node_ids: set[str] | None,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        candidates: dict[str, dict[str, Any]] = {}
        for indexed_object, effects in (
            self.call_output_effects_by_destination_object.items()
        ):
            if not self.graph.same_object(indexed_object, object_id):
                continue
            for effect in effects:
                effect_id = str(effect.get("effect_id", ""))
                if effect_id:
                    candidates[effect_id] = effect
        predecessors: list[dict[str, Any]] = []
        for effect in candidates.values():
            caller_id = str(effect.get("caller_function_id", ""))
            edge_id = str(effect.get("call_edge_id", ""))
            admitted = (
                allowed_edge_ids is None
                or edge_id in allowed_edge_ids
                or allowed_node_ids is not None
                and caller_id in allowed_node_ids
            )
            if not admitted:
                continue
            destination = dict(effect.get("destination", {}) or {})
            if offset is not None:
                destination_offset = int(destination.get("offset", 0) or 0)
                destination_extent = max(
                    1, int(destination.get("extent", 1) or 1)
                )
                requested_extent = max(1, int(extent or 1))
                if not (
                    destination_offset <= offset
                    and offset + requested_extent
                    <= destination_offset + destination_extent
                ):
                    continue
            stored = dict(effect.get("stored_value", {}) or {})
            atom_id = str(stored.get("atom_id", ""))
            value_id = str(stored.get("value_id", ""))
            stored_object_id = str(stored.get("object_id", ""))
            if not atom_id and not value_id and not stored_object_id:
                continue
            predecessors.append(
                {
                    "atom_id": atom_id,
                    "value_id": value_id,
                    "object_id": stored_object_id,
                    "call_context_edge_id": edge_id,
                    "edge": dict(effect.get("edge", {}) or {}),
                    "effect": effect,
                }
            )
        if predecessors or self.call_output_effects_by_destination_object:
            return predecessors, []
        return self.effect_resolver.call_output_predecessors(
            object_id,
            offset=offset,
            allowed_edge_ids=allowed_edge_ids,
            allowed_node_ids=allowed_node_ids,
        )

    def object_region_for_atom(
        self, atom_id: str, fallback_object_id: str, extent: int = 1
    ) -> Region:
        object_id, offset = self.object_region_by_atom.get(
            atom_id, (fallback_object_id, 0)
        )
        if object_id and atom_id in self.object_region_by_atom:
            width = max(1, int(extent or 1))
            return Region(
                object_id,
                start=offset,
                end=offset + width - 1,
                relative=True,
                precision="EXACT_ACCESS_RANGE",
            )
        return Region(object_id or fallback_object_id)


def source_definition_outputs(definition: dict[str, Any]) -> list[dict[str, str]]:
    """Return only exact, typed outputs from a SourceDefinition."""

    raw_outputs = definition.get("outputs")
    if not isinstance(raw_outputs, list):
        return []

    outputs: list[dict[str, str]] = []
    for raw_output in raw_outputs:
        if not isinstance(raw_output, dict):
            continue
        kind = raw_output.get("kind")
        if kind == "scalar_value":
            atom_id = _identity(raw_output)
            if not atom_id:
                continue
            outputs.append(
                {
                    "kind": kind,
                    "atom_id": atom_id,
                    "value_id": _public_value_id(raw_output),
                    "object_id": "",
                }
            )
        elif kind == "memory_object":
            object_id = raw_output.get("object_id")
            if not isinstance(object_id, str) or not object_id:
                continue
            # The accompanying ValueId is the pointer naming this object. It is
            # not a definition of the bytes written into the object.
            outputs.append(
                {
                    "kind": kind,
                    "atom_id": _identity(raw_output),
                    "value_id": _public_value_id(raw_output),
                    "object_id": object_id,
                }
            )
    return outputs


def source_index(
    sources: dict[str, Any],
    channel_graph: dict[str, Any] | None = None,
    *,
    index: ProgramIndex | None = None,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    # The first index is atom-keyed. Existing ValueId is itself a valid atom key.
    by_value: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rows = source_rows(sources)
    if index is not None and index.strict and not index.allow_may_channel:
        rows = [
            source
            for source in rows
            if str(source.get("decision", "")) == "ACCEPT_DETERMINISTIC"
        ]
    rows_by_id = {str(source.get("id", "")): source for source in rows}

    def add_unique(index: dict[str, list[dict[str, Any]]], key: str, source: dict[str, Any]) -> None:
        if not key:
            return
        source_id = str(source.get("id", ""))
        if not any(str(row.get("id", "")) == source_id for row in index[key]):
            index[key].append(source)

    exact_source_ids: set[str] = set()
    raw_definitions = sources.get("source_definitions", [])
    definitions = raw_definitions if isinstance(raw_definitions, list) else []
    for definition in definitions:
        if not isinstance(definition, dict):
            continue
        source_id = definition.get("source_id")
        if not isinstance(source_id, str) or not source_id:
            continue
        source = rows_by_id.get(source_id)
        if source is None:
            continue
        outputs = source_definition_outputs(definition)
        if not outputs:
            continue
        exact_source_ids.add(source_id)
        for output in outputs:
            indexed_source = {
                **source,
                "_source_definition": dict(definition),
                "_source_definition_output": dict(output),
            }
            if output["kind"] == "scalar_value":
                add_unique(by_value, output["atom_id"], indexed_source)
            else:
                object_ids = canonical_object_ids(output["object_id"])
                if index is not None:
                    object_ids.update(
                        canonical_object_ids(
                            index.resolved_object_by_atom.get(output["atom_id"], "")
                        )
                    )
                for object_id in object_ids:
                    add_unique(by_object, object_id, indexed_source)

    for source in rows:
        if str(source.get("id", "")) in exact_source_ids:
            continue
        outputs: list[dict[str, Any]] = []
        raw_outputs = source.get("source_outputs", [])
        if isinstance(raw_outputs, list):
            outputs.extend(dict(output or {}) for output in raw_outputs)
        single_output = source.get("source_output")
        if isinstance(single_output, dict):
            outputs.append(dict(single_output))
        # Compatibility with the original single-output Source row.
        outputs.append(
            {
                "value_id": source.get("source_value_id", ""),
                "atom_id": source.get("source_atom_id", ""),
                "object_id": source.get("source_object_id", ""),
            }
        )
        for output in outputs:
            atom_id = _identity(output)
            output_kind = str(output.get("kind", "") or source.get("source_output_kind", ""))
            raw_object_id = str(
                output.get("object_id", "") or output.get("source_object_id", "")
            )
            # A memory-output ValueId commonly denotes the buffer pointer, not
            # bytes produced by the external call. It may terminate only after
            # an explicit producer/write edge. Scalar return/MMIO values can be
            # exact Source definitions and remain direct ValueId endpoints.
            if output_kind != "memory_object":
                add_unique(by_value, atom_id, source)
            if output_kind != "scalar_value":
                for object_id in canonical_object_ids(raw_object_id):
                    add_unique(by_object, object_id, source)
        if index is not None and not any(
            str(source.get("id", "")) == str(row.get("id", ""))
            for rows in by_value.values()
            for row in rows
        ):
            site_id = str(source.get("site_id", ""))
            op_entry = index.ops_by_site.get(site_id)
            if op_entry:
                output = dict(op_entry[1].get("output", {}) or {})
                output_kind = str(source.get("source_output_kind", ""))
                if output_kind != "memory_object":
                    add_unique(by_value, _identity(output), source)
            for edge in index.graph.edges:
                if (
                    str(edge.get("source_id", "")) == str(source.get("id", ""))
                    and str(edge.get("edge_kind", "")) == "CHANNEL_WRITE"
                ):
                    add_unique(by_value, str(edge.get("value_atom_id", "")), source)
                    for object_id in canonical_object_ids(str(edge.get("object_id", ""))):
                        add_unique(by_object, object_id, source)
    for node in list((channel_graph or {}).get("object_nodes", []) or []):
        object_id = str(node.get("object_id", ""))
        for source_id in list(node.get("source_evidence_ids", []) or []):
            source = rows_by_id.get(str(source_id))
            if source and object_id and str(source_id) not in exact_source_ids:
                add_unique(by_object, object_id, source)

    # Source Association is the explicit forward data-dependency closure built
    # from a SourceDefinition.  Only source-side (channel_depth == 0)
    # associations are valid RDA endpoints here.  Associations produced after
    # a CHANNEL_READ are deliberately excluded: accepting them would let a
    # sink terminate at a precomputed result without traversing the
    # CHANNEL_READ/CHANNEL_WRITE relation that justifies the cross-context
    # flow.
    for association in list((channel_graph or {}).get("source_associations", []) or []):
        if not isinstance(association, dict):
            continue
        try:
            channel_depth = int(association.get("channel_depth", 0) or 0)
        except (TypeError, ValueError):
            continue
        if channel_depth != 0:
            continue
        source_id = str(association.get("source_id", ""))
        source = rows_by_id.get(source_id)
        if source is None:
            continue
        atom_id = str(association.get("atom_id", ""))
        state_kind = str(association.get("state_kind", ""))
        if atom_id and state_kind in {"VALUE", "OBJECT_REFERENCE", "MEMORY_CONTENT"}:
            indexed_source = {
                **source,
                "_source_association": dict(association),
            }
            add_unique(by_value, atom_id, indexed_source)
            if state_kind == "MEMORY_CONTENT":
                raw_object_id = str(
                    association.get("object_id", "")
                    or dict(association.get("region", {}) or {}).get("object_id", "")
                )
                for object_id in canonical_object_ids(raw_object_id):
                    add_unique(by_object, object_id, indexed_source)
    return by_value, by_object


def nonconstant_inputs(op: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for node in list(op.get("inputs", []) or []):
        node = dict(node or {})
        if bool(node.get("is_constant")):
            continue
        if str(node.get("space", "")) == "const":
            continue
        out.append(node)
    return out


_EXPLICIT_SOURCE_PATH_EDGES = {
    "ACTUAL_FORMAL",
    "CALL_RETURN",
    "CHANNEL_WRITE_PREDECESSOR",
    "FUNCTION_SUMMARY",
    "LOAD_ADDRESS",
    "LOCAL_DEF_USE",
    "OBJECT_WRITE",
    "SOURCE_WRITE",
}


def object_source_ids_from_path(path: list[dict[str, Any]]) -> set[str]:
    """Return producers explicitly traversed on the current object path."""

    return {
        str(edge.get("source_id", ""))
        for edge in path
        if str(edge.get("kind", "")) in {
            "CHANNEL_WRITE_PREDECESSOR",
            "SOURCE_WRITE",
        }
        and str(edge.get("source_id", ""))
    }


def deduplicate_sources(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        key = str(row.get("id", "")) or json.dumps(row, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def trace_parameter(
    parameter: dict[str, Any],
    index: ProgramIndex,
    sources_by_value: dict[str, list[dict[str, Any]]],
    sources_by_object: dict[str, list[dict[str, Any]]],
    *,
    max_steps: int,
    sink: dict[str, Any] | None = None,
    graph_search: dict[str, Any] | None = None,
) -> dict[str, Any]:
    start_atom, start_object, binding_evidence = index.bind_parameter(parameter, sink)
    start_value = _public_value_id(parameter)
    if not start_atom and not start_object:
        return {
            "role": str(parameter.get("role", "")),
            "status": "GRAPH_INCOMPLETE",
            "reason": "sink_parameter_has_no_public_or_backend_atom_binding",
            "paths": [],
            "blockers": ["missing_sink_parameter_binding"],
            "binding_evidence": binding_evidence,
        }

    graph = index.graph
    allowed_edge_ids = (
        set(str(edge_id) for edge_id in list(graph_search.get("allowed_edge_ids", []) or []))
        if graph_search is not None
        else None
    )
    allowed_node_ids = (
        set(str(node_id) for node_id in list(graph_search.get("allowed_node_ids", []) or []))
        if graph_search is not None
        else None
    )
    start_object = index.resolved_object_by_atom.get(start_atom, start_object)
    start_region = graph._region_from_edge(
        {"object_id": start_object, "region": parameter.get("region")},
        kind="CHANNEL_READ",
    ) if start_object else None
    # Worklist state: atom, object, region, evidence path, data-flow depth,
    # nested callee depth, and exact call edges used to enter nested callees.
    queue = deque([(start_atom, start_object, start_region, [], 0, 0, ())])
    visited: set[
        tuple[str, str, int | None, int | None, bool, int, tuple[str, ...]]
    ] = set()
    found: list[dict[str, Any]] = []
    blockers: set[str] = set()
    rejected_evidence: list[dict[str, Any]] = []
    internal_leaves = 0
    steps = 0

    if graph_search is not None:
        graph_status = str(graph_search.get("status", ""))
        if graph_status == "GRAPH_INCOMPLETE":
            blockers.add("candidate_graph_incomplete")
        elif graph_status == "ANALYSIS_BUDGET_EXHAUSTED":
            blockers.add("analysis_budget_exhausted")

    def edge_allowed(edge: dict[str, Any]) -> bool:
        return allowed_edge_ids is None or str(edge.get("edge_id", "")) in allowed_edge_ids

    def append_rejected(edge: dict[str, Any], reason: str) -> None:
        evidence = {
            "edge_id": str(edge.get("edge_id", "")),
            "site_id": str(edge.get("site_id", "")),
            "edge_kind": str(edge.get("edge_kind", "")),
            "object_id": str(edge.get("object_id", "")),
            "evidence_level": str(edge.get("evidence_level", "")),
            "reason": reason,
        }
        if evidence not in rejected_evidence:
            rejected_evidence.append(evidence)

    def writer_binding(edge: dict[str, Any]) -> tuple[str, str]:
        reference = dict(edge.get("reference_binding", {}) or {})
        atom_id = (
            str(reference.get("producer_atom_id", ""))
            if str(edge.get("transfer_semantics", "")) == "OBJECT_REFERENCE"
            else ""
        )
        atom_id = atom_id or str(edge.get("value_atom_id", "")) or str(
            edge.get("value_id", "")
        )
        object_id = str(edge.get("value_object_id", ""))
        op_entry = index.ops_by_site.get(str(edge.get("site_id", "")))
        if op_entry and str(op_entry[1].get("mnemonic", "")) == "STORE":
            inputs = [dict(item or {}) for item in list(op_entry[1].get("inputs", []) or [])]
            if inputs:
                atom_id = atom_id or _identity(inputs[-1])
                object_id = object_id or str(inputs[-1].get("object_id", ""))
        return atom_id, object_id

    def channel_read_step(edge: dict[str, Any]) -> dict[str, Any]:
        return {
            "kind": "CHANNEL_READ",
            "graph_edge_id": str(edge.get("edge_id", "")),
            "graph_edge_kind": "CHANNEL_READ",
            "site_id": str(edge.get("site_id", "")),
            "object_id": str(edge.get("object_id", "")),
            "region": dict(edge.get("region", {}) or {}),
            "transfer_semantics": str(edge.get("transfer_semantics", "")),
            "reference_binding": dict(edge.get("reference_binding", {}) or {}),
            "evidence": dict(edge.get("evidence", {}) or {}),
        }

    def channel_write_step(edge: dict[str, Any]) -> dict[str, Any]:
        return {
            # Keep the established path label while exposing the unified kind.
            "kind": "CHANNEL_WRITE_PREDECESSOR",
            "graph_edge_id": str(edge.get("edge_id", "")),
            "graph_edge_kind": "CHANNEL_WRITE",
            "edge_id": str(edge.get("edge_id", "")),
            "site_id": str(edge.get("site_id", "")),
            "object_id": str(edge.get("object_id", "")),
            "region": dict(edge.get("region", {}) or {}),
            "transfer_semantics": str(edge.get("transfer_semantics", "")),
            "reference_binding": dict(edge.get("reference_binding", {}) or {}),
            "source_id": str(edge.get("source_id", "")),
            "evidence": dict(edge.get("evidence", {}) or {}),
        }

    def value_binding(atom_id: str, object_id: str) -> dict[str, str]:
        """Serialize the exact backend identity used by this RDA step."""

        return {
            "atom_id": str(atom_id or ""),
            "value_id": str(index.public_value_by_atom.get(atom_id, "")),
            "object_id": str(
                index.resolved_object_by_atom.get(atom_id, object_id) or ""
            ),
        }

    def bind_path_step(
        step: dict[str, Any],
        *,
        consumer_atom: str,
        consumer_object: str,
        predecessor_atom: str,
        predecessor_object: str,
    ) -> dict[str, Any]:
        """Attach the already-selected backward relation without new analysis."""

        result = dict(step)
        result["consumer_binding"] = value_binding(consumer_atom, consumer_object)
        result["predecessor_binding"] = value_binding(
            predecessor_atom, predecessor_object
        )
        return result

    def source_matches_for_path(
        atom_id: str, object_id: str, path: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        matched: list[dict[str, Any]] = []
        if atom_id:
            matched.extend(sources_by_value.get(atom_id, []))
        if matched:
            return deduplicate_sources(matched)
        for step in path:
            source_id = str(step.get("source_id", ""))
            if not source_id or str(step.get("kind", "")) not in {
                "CHANNEL_WRITE_PREDECESSOR",
                "SOURCE_WRITE",
            }:
                continue
            producer_object = str(step.get("object_id", "")) or object_id
            for alias in graph.aliases(producer_object):
                for source in sources_by_object.get(alias, []):
                    if str(source.get("id", "")) == source_id:
                        matched.append(source)
        return deduplicate_sources(matched)

    while queue and steps < max_steps:
        atom_id, object_id, region, path, depth, call_depth, call_context = queue.popleft()
        resolved_object = index.resolved_object_by_atom.get(atom_id, "")
        if resolved_object:
            object_id = resolved_object
            if region is None or not graph.same_object(region.object_id, resolved_object):
                region = Region(resolved_object)
        key = (
            atom_id,
            object_id,
            region.start if region else None,
            region.end if region else None,
            region.relative if region else False,
            call_depth,
            call_context,
        )
        if key in visited:
            continue
        visited.add(key)
        steps += 1

        varnode_entry = index.varnodes_by_atom.get(atom_id) if atom_id else None
        matched_sources = source_matches_for_path(atom_id, object_id, path)
        local_source_steps: dict[str, dict[str, Any]] = {}
        if not matched_sources and varnode_entry and object_id:
            function_id = varnode_entry[0]
            for alias in graph.aliases(object_id):
                for source in sources_by_object.get(alias, []):
                    source_step = index.local_source_memory_definition(
                        source,
                        function_id,
                        object_id,
                        path,
                        str((sink or {}).get("site_id", "")),
                    )
                    if not source_step:
                        continue
                    matched_sources.append(source)
                    local_source_steps[str(source.get("id", ""))] = source_step
            matched_sources = deduplicate_sources(matched_sources)
        if not matched_sources and object_id:
            current_function_id = varnode_entry[0] if varnode_entry else ""
            for alias in graph.aliases(object_id):
                for source in sources_by_object.get(alias, []):
                    definition = dict(source.get("_source_definition", {}) or {})
                    if (
                        current_function_id
                        and str(definition.get("function_id", "")) == current_function_id
                    ):
                        # The flow-sensitive local check above is authoritative
                        # when producer and use are in the same function.
                        continue
                    source_step = index.exact_source_memory_effect(source, object_id)
                    if not source_step:
                        continue
                    matched_sources.append(source)
                    local_source_steps[str(source.get("id", ""))] = source_step
            matched_sources = deduplicate_sources(matched_sources)
        if matched_sources:
            for source in matched_sources:
                decision = str(source.get("decision", ""))
                if (
                    index.strict
                    and not index.allow_may_channel
                    and decision != "ACCEPT_DETERMINISTIC"
                ):
                    blockers.add("strict_mode_rejected_nondeterministic_source")
                    append_rejected(
                        {
                            "edge_id": str(source.get("id", "")),
                            "site_id": str(source.get("site_id", "")),
                            "edge_kind": "SOURCE",
                            "evidence_level": decision,
                        },
                        "strict_mode_rejected_nondeterministic_source",
                    )
                    continue
                completed_path = list(path)
                source_id = str(source.get("id", ""))
                if source_id in local_source_steps:
                    completed_path.append(local_source_steps[source_id])
                association = dict(source.get("_source_association", {}) or {})
                if association:
                    completed_path.append(
                        {
                            "kind": "SOURCE_ASSOCIATION",
                            "source_id": source_id,
                            "association_id": str(
                                association.get("association_id", "")
                            ),
                            "site_id": str(association.get("site_id", "")),
                            "function_id": str(association.get("function_id", "")),
                            "atom_id": str(association.get("atom_id", "")),
                            "state_kind": str(association.get("state_kind", "")),
                            "relation_kind": str(
                                association.get("relation_kind", "")
                            ),
                            "evidence": {
                                "analysis_precision": str(
                                    association.get("precision", "")
                                ),
                                "channel_depth": int(
                                    association.get("channel_depth", 0) or 0
                                ),
                            },
                        }
                    )
                path_is_may = any(
                    str(dict(step.get("evidence", {}) or {}).get(
                        "analysis_precision", ""
                    ))
                    == "MAY"
                    or str(step.get("effect_precision", "")) == "MAY_REGION"
                    for step in completed_path
                )
                found.append(
                    {
                        "source_id": str(source.get("id", "")),
                        "source_lineage_ids": sorted(
                            {
                                str(source.get("id", "")),
                                *(
                                    str(item.get("source_id", ""))
                                    for item in list(
                                        dict(source.get("proof", {}) or {}).get(
                                            "provenance", []
                                        )
                                        or []
                                    )
                                    if str(item.get("source_id", ""))
                                ),
                            }
                        ),
                        "source_label": str(source.get("label", "")),
                        "source_decision": decision,
                        "source_site_id": str(source.get("site_id", "")),
                        "path_precision": "MAY" if path_is_may else "EXACT",
                        "path": completed_path,
                    }
                )
            continue

        progressed = False
        terminal_is_modeled = False
        # Deferred callback/queue channels bind the consumer payload directly
        # to a handler formal rather than to a LOAD instruction.  Consume such
        # a CHANNEL_READ when RDA reaches that exact formal atom.
        for read_edge in graph.reads_by_value_atom.get(atom_id, []):
            if not edge_allowed(read_edge):
                blockers.add("candidate_trace_excludes_channel_read")
                continue
            read_region = read_edge["_region"]
            writer_edges, nonoverlap = graph.writers_for(read_region)
            if nonoverlap:
                blockers.add("no_overlapping_channel_write_region")
            for write_edge in writer_edges:
                if not edge_allowed(write_edge):
                    blockers.add("candidate_trace_excludes_channel_write")
                    continue
                edge_atom, edge_object = writer_binding(write_edge)
                if not edge_atom and not edge_object:
                    blockers.add("missing_channel_store_operand_binding")
                    continue
                progressed = True
                queue.append(
                    (
                        edge_atom,
                        edge_object,
                        None,
                        path
                        + [
                            channel_read_step(read_edge),
                            channel_write_step(write_edge),
                        ],
                        depth + 1,
                        0,
                        (),
                    )
                )
        # A primitive-copy source argument denotes bytes read from memory, not
        # merely the arithmetic used to compute its pointer. When the builder
        # supplied an exact callsite CHANNEL_READ, consume that memory effect
        # before following pointer-definition SSA. Otherwise an input-derived
        # array index can be mistaken for input-derived copied bytes.
        sink_site_id = str((sink or {}).get("site_id", ""))
        explicit_reads = [
            edge
            for edge in graph.reads_by_site.get(sink_site_id, [])
            if edge_allowed(edge)
            and (
                str(edge.get("value_atom_id", "")) == atom_id
                if str(edge.get("value_atom_id", ""))
                else (
                    object_id
                    and graph.same_object(str(edge.get("object_id", "")), object_id)
                )
            )
        ]
        explicit_memory_read = False
        for read_edge in explicit_reads:
            read_region = read_edge["_region"]
            writer_edges, nonoverlap = graph.writers_for(read_region)
            allowed_writers = [edge for edge in writer_edges if edge_allowed(edge)]
            if nonoverlap:
                blockers.add("no_overlapping_channel_write_region")
            for edge in allowed_writers:
                edge_atom, edge_object = writer_binding(edge)
                if not edge_atom and not edge_object:
                    blockers.add("missing_channel_store_operand_binding")
                    continue
                explicit_memory_read = True
                progressed = True
                queue.append(
                    (
                        edge_atom,
                        edge_object,
                        None,
                        path
                        + [channel_read_step(read_edge), channel_write_step(edge)],
                        depth + 1,
                        0,
                        (),
                    )
                )

        if varnode_entry and not explicit_memory_read:
            function_id, varnode = varnode_entry
            all_predecessors = index.parameter_predecessors(function_id, varnode)
            preferred_edge_id = call_context[-1] if call_context else ""
            predecessors = index.parameter_predecessors(
                function_id,
                varnode,
                allowed_edge_ids=allowed_edge_ids,
                preferred_edge_id=preferred_edge_id,
            )
            if all_predecessors and not predecessors:
                blockers.add("candidate_trace_excludes_call_binding")
            for predecessor in predecessors:
                predecessor_atom = str(predecessor.get("atom_id", ""))
                predecessor_object = str(predecessor.get("object_id", ""))
                if not predecessor_atom and not predecessor_object:
                    blockers.add("missing_actual_argument_atom_binding")
                    continue
                progressed = True
                queue.append(
                    (
                        predecessor_atom,
                        predecessor_object,
                        None,
                        path
                        + [
                            bind_path_step(
                                predecessor["edge"],
                                consumer_atom=atom_id,
                                consumer_object=object_id,
                                predecessor_atom=predecessor_atom,
                                predecessor_object=predecessor_object,
                            )
                        ],
                        depth + 1,
                        max(0, call_depth - 1) if preferred_edge_id else call_depth,
                        call_context[:-1] if preferred_edge_id else call_context,
                    )
                )

        primitive_effects: list[dict[str, Any]] = []
        if not explicit_memory_read:
            primitive_effects.extend(
                index.primitive_effects_by_output_atom.get(atom_id, [])
            )
            if object_id:
                primitive_effects.extend(
                    index.primitive_effects_by_destination_object.get(object_id, [])
                )
        seen_effect_ids: set[str] = set()
        used_effect_ids = {
            str(step.get("effect_id", ""))
            for step in path
            if str(step.get("effect_id", ""))
        }
        for effect in primitive_effects:
            effect_id = str(effect.get("effect_id", ""))
            if effect_id in seen_effect_ids or effect_id in used_effect_ids:
                continue
            seen_effect_ids.add(effect_id)
            effect_function_id = str(effect.get("function_id", ""))
            if (
                allowed_node_ids is not None
                and effect_function_id
                and effect_function_id not in allowed_node_ids
            ):
                continue
            source_binding = dict(effect.get("source", {}) or {})
            predecessor_atom = str(source_binding.get("atom_id", ""))
            predecessor_object = str(source_binding.get("object_id", ""))
            if not predecessor_atom and not predecessor_object:
                blockers.add("primitive_memory_effect_source_binding_missing")
                continue
            progressed = True
            queue.append(
                (
                    predecessor_atom,
                    predecessor_object,
                    None,
                    path
                    + [
                        bind_path_step({
                            "kind": "PRIMITIVE_MEMORY_EFFECT",
                            "effect_kind": str(effect.get("effect_kind", "")),
                            "effect_id": str(effect.get("effect_id", "")),
                            "site_id": str(effect.get("site_id", "")),
                            "callee": str(effect.get("callee", "")),
                            "effect_precision": str(
                                effect.get("effect_precision", "")
                            ),
                            "assumptions": list(effect.get("assumptions", []) or []),
                            "destination_object_id": str(
                                dict(effect.get("destination", {}) or {}).get(
                                    "object_id", ""
                                )
                            ),
                            "destination_access_path": list(
                                dict(effect.get("destination", {}) or {}).get(
                                    "access_path", []
                                )
                                or []
                            ),
                        },
                            consumer_atom=atom_id,
                            consumer_object=object_id,
                            predecessor_atom=predecessor_atom,
                            predecessor_object=predecessor_object,
                        )
                    ],
                    depth + 1,
                    call_depth,
                    call_context,
                )
            )

        used_alias_ids = {
            str(step.get("alias_id", ""))
            for step in path
            if str(step.get("alias_id", ""))
        }
        for alias in index.container_aliases_by_atom.get(atom_id, []):
            alias_id = str(alias.get("alias_id", ""))
            if not alias_id or alias_id in used_alias_ids:
                continue
            predecessor_atom = str(alias.get("root_atom_id", ""))
            predecessor_object = str(alias.get("root_object_id", ""))
            if not predecessor_atom and not predecessor_object:
                continue
            progressed = True
            queue.append(
                (
                    predecessor_atom,
                    predecessor_object,
                    None,
                    path
                    + [
                        bind_path_step({
                            "kind": "BOUNDED_CONTAINER_ALIAS",
                            "alias_id": alias_id,
                            "site_id": str(alias.get("phi_site_id", "")),
                            "root_parameter_slot": alias.get("root_parameter_slot"),
                            "max_container_hops": alias.get("max_container_hops", 1),
                            "evidence": {
                                "analysis_precision": "MAY",
                                "initial_load_sites": list(
                                    alias.get("initial_load_sites", []) or []
                                ),
                                "recurrence_load_sites": list(
                                    alias.get("recurrence_load_sites", []) or []
                                ),
                                "assumptions": list(alias.get("assumptions", []) or []),
                            },
                        },
                            consumer_atom=atom_id,
                            consumer_object=object_id,
                            predecessor_atom=predecessor_atom,
                            predecessor_object=predecessor_object,
                        )
                    ],
                    depth + 1,
                    call_depth,
                    call_context,
                )
            )

        definition = (
            index.defs_by_atom.get(atom_id)
            if atom_id and not explicit_memory_read
            else None
        )
        if definition:
            function_id, op = definition
            mnemonic = str(op.get("mnemonic", ""))
            inputs = nonconstant_inputs(op)
            if mnemonic in {"CALL", "CALLIND"}:
                all_predecessors, _all_blocker = index.call_return_predecessors(
                    function_id, op, call_depth=call_depth
                )
                predecessors, blocker = index.call_return_predecessors(
                    function_id,
                    op,
                    allowed_edge_ids=allowed_edge_ids,
                    call_depth=call_depth,
                )
                if all_predecessors and not predecessors and allowed_edge_ids is not None:
                    blocker = "candidate_trace_excludes_call_return"
                for predecessor in predecessors:
                    predecessor_atom = str(predecessor.get("atom_id", ""))
                    predecessor_object = str(predecessor.get("object_id", ""))
                    if not predecessor_atom and not predecessor_object:
                        blockers.add("missing_return_atom_binding")
                        continue
                    progressed = True
                    context_edge = str(predecessor.get("call_context_edge_id", ""))
                    queue.append(
                        (
                            predecessor_atom,
                            predecessor_object,
                            None,
                            path
                            + [
                                bind_path_step(
                                    predecessor["edge"],
                                    consumer_atom=atom_id,
                                    consumer_object=object_id,
                                    predecessor_atom=predecessor_atom,
                                    predecessor_object=predecessor_object,
                                )
                            ],
                            depth + 1,
                            int(predecessor.get("next_call_depth", call_depth + 1)),
                            call_context + ((context_edge,) if context_edge else ()),
                        )
                    )
                if blocker:
                    blockers.add(blocker)
                    terminal_is_modeled = True
                elif not predecessors:
                    internal_leaves += 1
                    terminal_is_modeled = True
            elif mnemonic == "LOAD":
                site_id = str(op.get("site_id", ""))
                all_reads = [
                    edge
                    for edge in graph.reads_by_site.get(site_id, [])
                    if not str(edge.get("value_atom_id", ""))
                    or not atom_id
                    or str(edge.get("value_atom_id", "")) == atom_id
                ]
                reads = [edge for edge in all_reads if edge_allowed(edge)]
                if all_reads and not reads:
                    blockers.add("candidate_trace_excludes_channel_read")
                if not reads:
                    rejected = graph.rejected_for(object_id)
                    if rejected:
                        blockers.add("strict_mode_rejected_channel_edge")
                        for edge in rejected:
                            append_rejected(
                                edge,
                                "strict_mode_rejected_heuristic_or_legacy_channel_edge",
                            )
                    raw_inputs = [
                        dict(item or {})
                        for item in list(op.get("inputs", []) or [])
                    ]
                    address_node = raw_inputs[-1] if raw_inputs else {}
                    address_atom = _identity(address_node)
                    address_object = index.resolved_object_by_atom.get(
                        address_atom, str(address_node.get("object_id", ""))
                    )
                    loaded_width = max(
                        1,
                        int(
                            dict(op.get("output", {}) or {}).get("size", 1)
                            or 1
                        ),
                    )
                    address_region = index.object_region_for_atom(
                        address_atom, address_object, loaded_width
                    )
                    address_object = address_region.object_id or address_object
                    call_output_writers, _call_output_blockers = (
                        index.call_output_predecessors(
                            address_object,
                            offset=(
                                address_region.start
                                if address_region.relative
                                else None
                            ),
                            extent=loaded_width,
                            allowed_edge_ids=allowed_edge_ids,
                            allowed_node_ids=allowed_node_ids,
                        )
                    )
                    for predecessor in call_output_writers:
                        predecessor_atom = str(predecessor.get("atom_id", ""))
                        predecessor_object = str(
                            predecessor.get("object_id", "")
                        )
                        if not predecessor_atom and not predecessor_object:
                            continue
                        progressed = True
                        queue.append(
                            (
                                predecessor_atom,
                                predecessor_object,
                                None,
                                path
                                + [
                                    bind_path_step(
                                        predecessor["edge"],
                                        consumer_atom=atom_id,
                                        consumer_object=object_id,
                                        predecessor_atom=predecessor_atom,
                                        predecessor_object=predecessor_object,
                                    )
                                ],
                                depth + 1,
                                0,
                                (),
                            )
                        )
                    summary_writers = index.exact_store_predecessors(
                        address_object,
                        allowed_edge_ids=allowed_edge_ids,
                        allowed_node_ids=allowed_node_ids,
                        exclude_function_id=function_id,
                    )
                    for predecessor in summary_writers:
                        predecessor_atom = str(predecessor.get("atom_id", ""))
                        predecessor_object = str(predecessor.get("object_id", ""))
                        progressed = True
                        queue.append(
                            (
                                predecessor_atom,
                                predecessor_object,
                                None,
                                path
                                + [
                                    bind_path_step(
                                        predecessor["edge"],
                                        consumer_atom=atom_id,
                                        consumer_object=object_id,
                                        predecessor_atom=predecessor_atom,
                                        predecessor_object=predecessor_object,
                                    )
                                ],
                                depth + 1,
                                0,
                                (),
                            )
                        )
                    if address_atom or address_object:
                        progressed = True
                        queue.append(
                            (
                                address_atom,
                                address_object,
                                None,
                                path
                                + [
                                    bind_path_step({
                                        "kind": "LOAD_ADDRESS",
                                        "site_id": site_id,
                                        "object_id": address_object,
                                    },
                                        consumer_atom=atom_id,
                                        consumer_object=object_id,
                                        predecessor_atom=address_atom,
                                        predecessor_object=address_object,
                                    )
                                ],
                                depth + 1,
                                call_depth,
                                call_context,
                            )
                        )
                    else:
                        blockers.add("unresolved_load_address")
                        terminal_is_modeled = True
                for read_edge in reads:
                    read_region = read_edge["_region"]
                    writer_edges, nonoverlap = graph.writers_for(read_region)
                    allowed_writers = [edge for edge in writer_edges if edge_allowed(edge)]
                    if writer_edges and not allowed_writers:
                        blockers.add("candidate_trace_excludes_channel_write")
                    if nonoverlap:
                        blockers.add("no_overlapping_channel_write_region")
                    if not writer_edges:
                        rejected = graph.rejected_for(read_region.object_id)
                        if rejected:
                            blockers.add("strict_mode_rejected_channel_edge")
                            for edge in rejected:
                                append_rejected(
                                    edge,
                                    "strict_mode_rejected_heuristic_or_legacy_channel_edge",
                                )
                        elif not nonoverlap:
                            blockers.add("unresolved_shared_region_definition")
                    for edge in allowed_writers:
                        edge_atom, edge_object = writer_binding(edge)
                        if not edge_atom and not edge_object:
                            blockers.add(
                                str(edge.get("analysis_blocker", ""))
                                or "missing_channel_store_operand_binding"
                            )
                            continue
                        progressed = True
                        queue.append(
                            (
                                edge_atom,
                                edge_object,
                                None,
                                path
                                + [channel_read_step(read_edge), channel_write_step(edge)],
                                depth + 1,
                                0,
                                (),
                            )
                        )
                terminal_is_modeled = terminal_is_modeled or not progressed
            elif inputs:
                for node in inputs:
                    node_atom = _identity(node)
                    node_object = str(node.get("object_id", ""))
                    if not node_atom and not node_object:
                        blockers.add("missing_backend_atom_binding")
                        continue
                    progressed = True
                    queue.append(
                        (
                            node_atom,
                            node_object,
                            None,
                            path
                            + [
                                bind_path_step(
                                    {
                                        "kind": "LOCAL_DEF_USE",
                                        "mnemonic": mnemonic,
                                        "site_id": str(op.get("site_id", "")),
                                    },
                                    consumer_atom=atom_id,
                                    consumer_object=object_id,
                                    predecessor_atom=node_atom,
                                    predecessor_object=node_object,
                                )
                            ],
                            depth + 1,
                            call_depth,
                            call_context,
                        )
                    )
            else:
                raw_inputs = list(op.get("inputs", []) or [])
                if raw_inputs:
                    internal_leaves += 1
                    terminal_is_modeled = True
                else:
                    blockers.add("unmodeled_origin")
                    terminal_is_modeled = True
        elif atom_id.startswith("const:") or object_id.startswith("const:"):
            internal_leaves += 1
            terminal_is_modeled = True
        elif object_id and not progressed:
            object_region = region or index.object_region_for_atom(
                atom_id, object_id
            )
            writer_edges, nonoverlap = graph.writers_for(object_region)
            allowed_writers = [edge for edge in writer_edges if edge_allowed(edge)]
            if writer_edges and not allowed_writers:
                blockers.add("candidate_trace_excludes_channel_write")
            if nonoverlap:
                blockers.add("no_overlapping_channel_write_region")
            for edge in allowed_writers:
                edge_atom, edge_object = writer_binding(edge)
                if not edge_atom and not edge_object:
                    blockers.add(
                        str(edge.get("analysis_blocker", ""))
                        or "missing_channel_store_operand_binding"
                    )
                    continue
                progressed = True
                queue.append(
                    (
                        edge_atom,
                        edge_object,
                        None,
                        path + [channel_write_step(edge)],
                        depth + 1,
                        0,
                        (),
                    )
                )
            call_output_writers, _call_output_blockers = (
                index.call_output_predecessors(
                    object_id,
                    offset=(object_region.start if object_region.relative else None),
                    extent=(
                        object_region.end - object_region.start + 1
                        if object_region.relative
                        and object_region.start is not None
                        and object_region.end is not None
                        else None
                    ),
                    allowed_edge_ids=allowed_edge_ids,
                    allowed_node_ids=allowed_node_ids,
                )
            )
            for predecessor in call_output_writers:
                predecessor_atom = str(predecessor.get("atom_id", ""))
                predecessor_object = str(predecessor.get("object_id", ""))
                if not predecessor_atom and not predecessor_object:
                    continue
                progressed = True
                queue.append(
                    (
                        predecessor_atom,
                        predecessor_object,
                        None,
                        path
                        + [
                            bind_path_step(
                                predecessor["edge"],
                                consumer_atom=atom_id,
                                consumer_object=object_id,
                                predecessor_atom=predecessor_atom,
                                predecessor_object=predecessor_object,
                            )
                        ],
                        depth + 1,
                        0,
                        (),
                    )
                )
            summary_writers = index.exact_store_predecessors(
                object_id,
                allowed_edge_ids=allowed_edge_ids,
                allowed_node_ids=allowed_node_ids,
                exclude_function_id=(varnode_entry[0] if varnode_entry else ""),
            )
            for predecessor in summary_writers:
                predecessor_atom = str(predecessor.get("atom_id", ""))
                predecessor_object = str(predecessor.get("object_id", ""))
                progressed = True
                queue.append(
                    (
                        predecessor_atom,
                        predecessor_object,
                        None,
                        path
                        + [
                            bind_path_step(
                                predecessor["edge"],
                                consumer_atom=atom_id,
                                consumer_object=object_id,
                                predecessor_atom=predecessor_atom,
                                predecessor_object=predecessor_object,
                            )
                        ],
                        depth + 1,
                        0,
                        (),
                    )
                )
            if (
                not writer_edges
                and not call_output_writers
                and not summary_writers
            ):
                rejected = graph.rejected_for(object_id)
                if rejected:
                    blockers.add("strict_mode_rejected_channel_edge")
                    for edge in rejected:
                        append_rejected(
                            edge,
                            "strict_mode_rejected_heuristic_or_legacy_channel_edge",
                        )
                elif not nonoverlap:
                    blockers.add("unresolved_object_definition")
                    blockers.add("unmodeled_origin")
                terminal_is_modeled = True

        if not progressed and not terminal_is_modeled:
            if varnode_entry and bool(varnode_entry[1].get("is_parameter")):
                blockers.add("unresolved_formal_parameter")
            else:
                blockers.add("unmodeled_origin")

    analysis_frontier: dict[str, Any] | None = None
    if queue:
        blockers.add("analysis_budget_exhausted")
        queued = list(queue)
        frontier_nodes = [
            {
                "value_id": str(index.public_value_by_atom.get(atom_id, "")),
                "object_id": str(index.resolved_object_by_atom.get(atom_id, object_id)),
                "depth": depth,
                "reason": "analysis_budget_exhausted_before_visit",
            }
            for atom_id, object_id, _region, _path, depth, _call_depth, _context in queued[:16]
        ]
        analysis_frontier = {
            "reason": "analysis_budget_exhausted",
            "remaining_nodes": len(queued),
            "truncated": len(queued) > len(frontier_nodes),
            "nodes": frontier_nodes,
        }

    deterministic = [
        item
        for item in found
        if item["source_decision"] == "ACCEPT_DETERMINISTIC"
        and item.get("path_precision") != "MAY"
    ]
    heuristic = [
        item
        for item in found
        if item["source_decision"] == "ACCEPT_HEURISTIC"
        or item.get("path_precision") == "MAY"
    ]
    graph_incomplete = graph_search is not None and str(graph_search.get("status", "")) == "GRAPH_INCOMPLETE"
    budget_exhausted = bool(queue) or (
        graph_search is not None
        and str(graph_search.get("status", "")) == "ANALYSIS_BUDGET_EXHAUSTED"
    )
    # Source reachability is an existential taint result: one body-proved path
    # to a deterministic Source is sufficient to retain the parameter.  A
    # remaining frontier is still reported below, but it must not erase that
    # positive path or be confused with proof that every reaching definition
    # was resolved.
    if deterministic:
        status = "SOURCE_REACHED_DETERMINISTIC"
        reason = "backward_closure_reached_deterministic_source"
    elif heuristic:
        status = "SOURCE_REACHED_HEURISTIC"
        reason = "backward_closure_reached_heuristic_source"
    elif index.strict and budget_exhausted:
        status = "ANALYSIS_BUDGET_EXHAUSTED"
        reason = "candidate_graph_or_reaching_definition_budget_exhausted"
    elif index.strict and graph_incomplete:
        status = "GRAPH_INCOMPLETE"
        reason = "unified_candidate_graph_is_incomplete"
    elif blockers:
        status = "GRAPH_INCOMPLETE"
        reason = "backward_closure_contains_unresolved_graph_edges"
    elif internal_leaves:
        status = "PROVEN_INTERNAL_ONLY"
        reason = "all_observed_reaching_definitions_closed_without_external_source"
    else:
        status = "GRAPH_INCOMPLETE" if index.strict else "SOURCE_NOT_RESOLVED"
        reason = (
            "backward_closure_contains_unresolved_graph_edges"
            if index.strict
            else "no_source_reached_within_analysis_scope"
        )
    return {
        "role": str(parameter.get("role", "")),
        "start_value_id": start_value,
        "start_object_id": start_object,
        "binding_evidence": binding_evidence,
        "status": status,
        "reason": reason,
        "paths": deterministic
        + (
            heuristic
            if (not index.strict or index.allow_may_channel)
            else []
        ),
        "blockers": sorted(blockers),
        "first_missing_relation": first_missing_relation(blockers),
        "rejected_evidence": rejected_evidence,
        "visited_nodes": len(visited),
        "steps": steps,
        "analysis_frontier": analysis_frontier,
        "trace_constraint": {
            "candidate_search_status": str((graph_search or {}).get("status", "UNCONSTRAINED")),
            "allowed_edges": len(allowed_edge_ids) if allowed_edge_ids is not None else None,
        },
    }


def chain_status(
    parameter_results: list[dict[str, Any]], *, strict: bool = False
) -> str:
    if not parameter_results:
        return "GRAPH_INCOMPLETE"
    statuses = [str(result.get("status", "")) for result in parameter_results]
    if strict:
        # Mango-level alert policy is existential over declared vulnerable
        # parameters. One source-backed parameter retains the sink; unresolved
        # sibling parameters remain visible in ``parameter_results`` and must
        # not be mistaken for a safety proof.
        if "SOURCE_REACHED_DETERMINISTIC" in statuses:
            return "SOURCE_REACHED_DETERMINISTIC"
        if "SOURCE_REACHED_HEURISTIC" in statuses:
            return "SOURCE_REACHED_HEURISTIC"
        if "ANALYSIS_BUDGET_EXHAUSTED" in statuses:
            return "ANALYSIS_BUDGET_EXHAUSTED"
        if any(
            status not in {
                "SOURCE_REACHED_DETERMINISTIC",
                "PROVEN_INTERNAL_ONLY",
            }
            for status in statuses
        ):
            return "GRAPH_INCOMPLETE"
        return "PROVEN_INTERNAL_ONLY"
    dynamic_statuses = [status for status in statuses if status != "PROVEN_INTERNAL_ONLY"]
    reached = {
        "SOURCE_REACHED_DETERMINISTIC",
        "SOURCE_REACHED_HEURISTIC",
    }
    if not dynamic_statuses:
        return "PROVEN_INTERNAL_ONLY"
    if all(status in reached for status in dynamic_statuses):
        return (
            "SOURCE_REACHED_DETERMINISTIC"
            if all(status == "SOURCE_REACHED_DETERMINISTIC" for status in dynamic_statuses)
            else "SOURCE_REACHED_HEURISTIC"
        )
    if any(status in reached for status in dynamic_statuses):
        return "PARTIAL_SOURCE_REACHABILITY"
    if "GRAPH_INCOMPLETE" in dynamic_statuses:
        return "GRAPH_INCOMPLETE"
    if "SOURCE_NOT_RESOLVED" in dynamic_statuses:
        return "SOURCE_NOT_RESOLVED"
    return "PROVEN_INTERNAL_ONLY"


def vulnerability_status_for_chain(status: str) -> str:
    if status.startswith("SOURCE_REACHED"):
        return "static_candidate_requires_dynamic_validation"
    if status == "PARTIAL_SOURCE_REACHABILITY":
        return "static_candidate_incomplete_parameter_closure"
    if status == "GRAPH_INCOMPLETE":
        return "analysis_inconclusive_graph_incomplete"
    if status == "ANALYSIS_BUDGET_EXHAUSTED":
        return "analysis_inconclusive_budget_exhausted"
    if status == "SOURCE_NOT_RESOLVED":
        return "source_not_resolved_not_proven_safe"
    return "no_external_source_observed_for_traced_parameters"


def analyze_sink(
    sink: dict[str, Any],
    index: ProgramIndex,
    sources_by_value: dict[str, list[dict[str, Any]]],
    sources_by_object: dict[str, list[dict[str, Any]]],
    *,
    max_steps: int,
    max_graph_steps: int | None = None,
    max_trace_witnesses: int = 64,
) -> dict[str, Any]:
    sink_function_id = index.sink_function_id(sink)
    # This is the only graph traversal. Every parameter RDA below consumes this
    # exact mixed CALL+CHANNEL result as its trace constraint.
    graph_search = index.graph.reverse_bfs(
        sink_function_id,
        max_steps=max(1, max_graph_steps if max_graph_steps is not None else max_steps),
        max_trace_witnesses=max(0, max_trace_witnesses),
    )
    parameters = list(sink.get("vulnerable_parameters", []) or [])
    results = [
        trace_parameter(
            parameter,
            index,
            sources_by_value,
            sources_by_object,
            max_steps=max(1, max_steps),
            sink=sink,
            graph_search=graph_search,
        )
        for parameter in parameters
    ]
    status = chain_status(results, strict=index.strict)
    source_reached = status in {
        "SOURCE_REACHED_DETERMINISTIC",
        "SOURCE_REACHED_HEURISTIC",
    }
    if (
        index.strict
        and not source_reached
        and graph_search.get("status") == "ANALYSIS_BUDGET_EXHAUSTED"
    ):
        status = "ANALYSIS_BUDGET_EXHAUSTED"
    elif (
        index.strict
        and not source_reached
        and graph_search.get("status") == "GRAPH_INCOMPLETE"
    ):
        status = "GRAPH_INCOMPLETE"
    return {
        "chain_id": f"chain:{sink.get('id', '')}",
        "sink_id": str(sink.get("id", "")),
        "sink_site_id": str(sink.get("site_id", "")),
        "sink_function_id": sink_function_id,
        "sink_function": str(sink.get("function", "")),
        "sink_callee": str(sink.get("callee", "")),
        "sink_label": str(sink.get("label", "")),
        "sink_decision": str(sink.get("decision", "")),
        "sink_recognition": str(sink.get("recognition", "")),
        "sink_recognition_method": str(sink.get("recognition_method", "")),
        "status": status,
        "candidate_search": {
            key: value
            for key, value in graph_search.items()
            if key != "candidate_traces"
        },
        "candidate_traces": list(graph_search.get("candidate_traces", []) or []),
        "parameter_results": results,
        "vulnerability_status": vulnerability_status_for_chain(status),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--program-facts", required=True, type=Path)
    parser.add_argument("--sources-json", required=True, type=Path)
    parser.add_argument("--sinks-json", required=True, type=Path)
    parser.add_argument("--channel-graph", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-steps", default=500, type=int)
    parser.add_argument("--max-graph-steps", type=int)
    parser.add_argument(
        "--max-trace-witnesses",
        default=64,
        type=int,
        help=(
            "Maximum representative reverse-BFS traces serialized per Sink; "
            "the complete admitted node/edge subgraph still constrains RDA"
        ),
    )
    parser.add_argument("--max-function-depth", default=3, type=int)
    parser.add_argument("--max-summary-ops", default=256, type=int)
    parser.add_argument("--max-summary-alternatives", default=8, type=int)
    parser.add_argument(
        "--strict",
        action="store_true",
        help="admit only deterministic channel/source evidence",
    )
    parser.add_argument(
        "--allow-may-channel",
        action="store_true",
        help=(
            "admit body-proved primitive-copy Channelgraph edges with explicit "
            "may-flow assumptions; resulting reachability remains heuristic"
        ),
    )
    parser.add_argument(
        "--graph-mode",
        choices=("unified", "callgraph-only"),
        default="unified",
        help=(
            "Use the full Callgraph + Channelgraph, or exclude only Channelgraph "
            "relations for a controlled ablation."
        ),
    )
    args = parser.parse_args()

    program_facts = read_json(args.program_facts)
    sources = read_json(args.sources_json)
    sinks = read_json(args.sinks_json)
    channel_graph = read_json(args.channel_graph)
    index = ProgramIndex(
        program_facts,
        channel_graph,
        strict=args.strict,
        allow_may_channel=args.allow_may_channel,
        graph_mode=args.graph_mode,
        max_function_depth=max(0, args.max_function_depth),
        max_summary_ops=max(1, args.max_summary_ops),
        max_summary_alternatives=max(1, args.max_summary_alternatives),
    )
    sources_by_value, sources_by_object = source_index(
        sources, channel_graph, index=index
    )

    chains = [
        analyze_sink(
            sink,
            index,
            sources_by_value,
            sources_by_object,
            max_steps=max(1, args.max_steps),
            max_graph_steps=args.max_graph_steps,
            max_trace_witnesses=max(0, args.max_trace_witnesses),
        )
        for sink in sink_rows(sinks)
    ]

    status_counts: dict[str, int] = defaultdict(int)
    for chain in chains:
        status_counts[str(chain.get("status", ""))] += 1
    candidate_traces = [
        trace
        for chain in chains
        for trace in list(chain.get("candidate_traces", []) or [])
    ]
    candidate_trace_count = sum(
        int(dict(chain.get("candidate_search", {}) or {}).get(
            "candidate_trace_count", 0
        ) or 0)
        for chain in chains
    )
    mixed_candidate_trace_count = sum(
        int(dict(chain.get("candidate_search", {}) or {}).get(
            "mixed_candidate_trace_count", 0
        ) or 0)
        for chain in chains
    )
    channel_assisted_chains = [
        chain
        for chain in chains
        if any(
            str(step.get("kind", ""))
            in {"CHANNEL_READ", "CHANNEL_WRITE_PREDECESSOR"}
            for result in list(chain.get("parameter_results", []) or [])
            for source_path in list(result.get("paths", []) or [])
            for step in list(source_path.get("path", []) or [])
        )
    ]
    artifact = {
        "schema_version": "ct-mini-chains-v1",
        "binary": str(program_facts.get("binary", "")),
        "binary_sha256": str(program_facts.get("binary_sha256", "")),
        "analysis": "unified_graph_reverse_bfs_then_trace_constrained_backward_rda",
        "graph_mode": args.graph_mode,
        "strict_mode": args.strict,
        "allow_may_channel": args.allow_may_channel,
        "function_effect_resolution": {
            "mode": "bounded_on_demand_body_derived",
            "limits": {
                "max_function_depth": max(0, args.max_function_depth),
                "max_summary_ops": max(1, args.max_summary_ops),
                "max_summary_alternatives": max(1, args.max_summary_alternatives),
            },
            "counts": index.effect_resolver.artifact_counts(),
        },
        "unified_graph": index.graph.to_artifact(),
        "counts": {
            "sink_startpoints": len(sink_rows(sinks)),
            "chains": len(chains),
            "reverse_bfs_runs": len(chains),
            "parameter_rda_runs": sum(
                len(list(chain.get("parameter_results", []) or []))
                for chain in chains
            ),
            "candidate_traces": candidate_trace_count,
            "mixed_candidate_traces": mixed_candidate_trace_count,
            "serialized_trace_witnesses": len(candidate_traces),
            "trace_witnesses_truncated": any(
                bool(dict(chain.get("candidate_search", {}) or {}).get(
                    "candidate_traces_truncated", False
                ))
                for chain in chains
            ),
            "channel_assisted_chains": len(channel_assisted_chains),
            "status": dict(sorted(status_counts.items())),
        },
        "chains": chains,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, indent=2) + "\n")
    print(json.dumps(artifact["counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
