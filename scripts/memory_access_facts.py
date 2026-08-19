#!/usr/bin/env python3
"""Canonical concrete memory-access facts for Channelgraph discovery.

The input is the exact High P-code ``OBJECT_READ``/``OBJECT_WRITE`` surface
already emitted by ``build_channel_graph_v2``.  This module does not infer
memory access from names, xrefs, calls, or address-taken evidence.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable


SUPPORTED_STORAGE_KINDS = {
    "STATIC_WRITABLE_DATA",
    "ABSOLUTE_SRAM",
}


class RegionRelation(str, Enum):
    """Provable relation between two accesses to one aggregate object."""

    EXACT_OVERLAP = "EXACT_OVERLAP"
    MAY_OVERLAP = "MAY_OVERLAP"
    DISJOINT = "DISJOINT"


def _fixed_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _fixed_interval(fact: "WriteFact | ReadFact") -> tuple[int, int] | None:
    if fact.selector_terms:
        return None
    offset = _fixed_int(fact.region_offset)
    extent = _fixed_int(fact.region_extent)
    if offset is None or extent is None or offset < 0 or extent <= 0:
        return None
    return offset, offset + extent


def region_relation(
    left: "WriteFact | ReadFact",
    right: "WriteFact | ReadFact",
) -> RegionRelation:
    """Classify overlap without treating unknown addresses as exact.

    Fixed intervals can prove overlap or disjointness. Dynamic selectors over
    the same aggregate object retain a may-overlap relation; this covers ring
    buffers indexed by independently recovered head and tail values.
    """

    if (
        not left.aggregate_object_id
        or left.aggregate_object_id != right.aggregate_object_id
    ):
        return RegionRelation.DISJOINT
    left_interval = _fixed_interval(left)
    right_interval = _fixed_interval(right)
    if left_interval is not None and right_interval is not None:
        if max(left_interval[0], right_interval[0]) < min(
            left_interval[1], right_interval[1]
        ):
            return RegionRelation.EXACT_OVERLAP
        return RegionRelation.DISJOINT
    if left.selector_terms or right.selector_terms:
        return RegionRelation.MAY_OVERLAP
    return RegionRelation.DISJOINT


def _stable_field_object(parent: str, field_path: tuple[str, ...]) -> str:
    token = hashlib.sha256(
        (parent + "|" + "|".join(field_path)).encode()
    ).hexdigest()[:20]
    return f"obj:field:{token}"


def _field_path(edge: dict[str, Any]) -> tuple[str, ...]:
    explicit = tuple(
        str(item)
        for item in list(edge.get("field_path", []) or [])
        if str(item)
    )
    if explicit:
        return explicit
    binding = dict(edge.get("address_binding", {}) or {})
    return tuple(
        str(item)
        for item in list(binding.get("field_path", []) or [])
        if str(item)
    )


def _selector_terms(edge: dict[str, Any]) -> tuple[str, ...]:
    terms = list(edge.get("selector_terms", []) or [])
    if not terms:
        terms = list(dict(edge.get("region", {}) or {}).get("selector_terms", []) or [])
    normalized: list[str] = []
    for raw in terms:
        item = dict(raw or {})
        selector = str(item.get("selector_value_id", ""))
        stride = str(item.get("stride", ""))
        if selector or stride:
            normalized.append(f"{selector}*{stride}")
    return tuple(normalized)


def _access_offset(edge: dict[str, Any]) -> Any:
    if edge.get("region_offset") is not None:
        return edge.get("region_offset")
    region = dict(edge.get("region", {}) or {})
    if region.get("offset") is not None:
        return region.get("offset")
    return "dynamic" if _selector_terms(edge) else "unknown"


def _access_extent(edge: dict[str, Any]) -> Any:
    if edge.get("region_extent") is not None:
        return edge.get("region_extent")
    region = dict(edge.get("region", {}) or {})
    if region.get("extent") is not None:
        return region.get("extent")
    width = edge.get("access_width")
    return width if width not in {None, 0, ""} else "unknown"


@dataclass(frozen=True)
class WriteFact:
    access_kind: str
    site_id: str
    function_id: str
    object_id: str
    aggregate_object_id: str
    base_object_id: str
    stored_atom_id: str
    loaded_atom_id: str
    region_offset: Any
    region_extent: Any
    selector_terms: tuple[str, ...]
    field_path: tuple[str, ...]
    address_provenance: str
    storage_kind: str
    deterministic_context_ids: tuple[str, ...]
    context_ids: tuple[str, ...]
    access_edge_id: str
    recognition: str = "deterministic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_kind": self.access_kind,
            "site_id": self.site_id,
            "function_id": self.function_id,
            "object_id": self.object_id,
            "aggregate_object_id": self.aggregate_object_id,
            "base_object_id": self.base_object_id,
            "stored_atom_id": self.stored_atom_id,
            "loaded_atom_id": self.loaded_atom_id,
            "region_offset": self.region_offset,
            "region_extent": self.region_extent,
            "selector_terms": list(self.selector_terms),
            "field_path": list(self.field_path),
            "address_provenance": self.address_provenance,
            "deterministic_context_ids": list(
                self.deterministic_context_ids
            ),
            "context_ids": list(self.context_ids),
        }


@dataclass(frozen=True)
class ReadFact:
    access_kind: str
    site_id: str
    function_id: str
    object_id: str
    aggregate_object_id: str
    base_object_id: str
    stored_atom_id: str
    loaded_atom_id: str
    region_offset: Any
    region_extent: Any
    selector_terms: tuple[str, ...]
    field_path: tuple[str, ...]
    address_provenance: str
    storage_kind: str
    deterministic_context_ids: tuple[str, ...]
    context_ids: tuple[str, ...]
    access_edge_id: str
    recognition: str = "deterministic"

    def to_dict(self) -> dict[str, Any]:
        return {
            "access_kind": self.access_kind,
            "site_id": self.site_id,
            "function_id": self.function_id,
            "object_id": self.object_id,
            "aggregate_object_id": self.aggregate_object_id,
            "base_object_id": self.base_object_id,
            "stored_atom_id": self.stored_atom_id,
            "loaded_atom_id": self.loaded_atom_id,
            "region_offset": self.region_offset,
            "region_extent": self.region_extent,
            "selector_terms": list(self.selector_terms),
            "field_path": list(self.field_path),
            "address_provenance": self.address_provenance,
            "deterministic_context_ids": list(
                self.deterministic_context_ids
            ),
            "context_ids": list(self.context_ids),
        }


class MemoryAccessFactIndex:
    """Index concrete High P-code accesses by normalized memory object."""

    def __init__(
        self,
        *,
        write_facts: Iterable[WriteFact] = (),
        read_facts: Iterable[ReadFact] = (),
        blockers: Iterable[dict[str, Any]] = (),
    ) -> None:
        self.write_facts = list(write_facts)
        self.read_facts = list(read_facts)
        self.blockers = [dict(item) for item in blockers]
        writes: dict[str, list[WriteFact]] = defaultdict(list)
        reads: dict[str, list[ReadFact]] = defaultdict(list)
        facts_by_site: dict[str, list[WriteFact | ReadFact]] = defaultdict(list)
        for fact in self.write_facts:
            writes[fact.aggregate_object_id].append(fact)
            facts_by_site[fact.site_id].append(fact)
        for fact in self.read_facts:
            reads[fact.aggregate_object_id].append(fact)
            facts_by_site[fact.site_id].append(fact)
        self.writes_by_object = {
            key: list(sorted(value, key=lambda row: (row.site_id, row.function_id)))
            for key, value in writes.items()
        }
        self.reads_by_object = {
            key: list(sorted(value, key=lambda row: (row.site_id, row.function_id)))
            for key, value in reads.items()
        }
        self.fact_by_site = {
            key: value[0] for key, value in facts_by_site.items() if len(value) == 1
        }

    @classmethod
    def from_exact_edges(
        cls,
        edges: Iterable[dict[str, Any]],
        object_nodes: Iterable[dict[str, Any]],
    ) -> "MemoryAccessFactIndex":
        nodes = {
            str(node.get("object_id", "") or node.get("node_id", "")): dict(node)
            for node in object_nodes
            if str(node.get("object_id", "") or node.get("node_id", ""))
        }
        writes: list[WriteFact] = []
        reads: list[ReadFact] = []
        blockers: list[dict[str, Any]] = []

        for raw in edges:
            edge = dict(raw or {})
            edge_kind = str(edge.get("edge_kind", ""))
            if edge_kind not in {"OBJECT_WRITE", "OBJECT_READ"}:
                continue
            candidate_class = str(edge.get("candidate_class", ""))
            if candidate_class != "EXACT_HIGH_PCODE_MEMORY_ACCESS":
                blockers.append(
                    {
                        "site_id": str(edge.get("site_id", "")),
                        "function_id": str(edge.get("function_id", "")),
                        "object_id": str(edge.get("object_id", "")),
                        "edge_kind": edge_kind,
                        "reason": "memory_access_candidate_class_not_exact",
                    }
                )
                continue
            site_id = str(edge.get("site_id", ""))
            function_id = str(edge.get("function_id", ""))
            object_id = str(edge.get("object_id", ""))
            atom_id = str(edge.get("value_id", "") or edge.get("value_atom_id", ""))
            node = nodes.get(object_id, {})
            storage_kind = str(
                edge.get("storage_kind", "")
                or node.get("storage_kind", "")
            )
            reasons: list[str] = []
            if not site_id or not function_id:
                reasons.append("concrete_access_identity_missing")
            if not object_id:
                reasons.append("concrete_access_object_missing")
            if not atom_id:
                reasons.append("concrete_access_value_atom_missing")
            selector_terms = _selector_terms(edge)
            region_offset = _access_offset(edge)
            region_extent = _access_extent(edge)
            if not selector_terms and _fixed_int(region_offset) is None:
                reasons.append("concrete_access_region_offset_missing")
            extent_value = _fixed_int(region_extent)
            if extent_value is None or extent_value <= 0:
                reasons.append("concrete_access_region_extent_missing")
            if storage_kind == "STACK_LOCAL":
                reasons.append("ineligible_stack_object")
            elif storage_kind == "CALL_RESULT_OBJECT":
                reasons.append("ineligible_call_result_object")
            elif storage_kind not in SUPPORTED_STORAGE_KINDS:
                reasons.append("unresolved_memory_object")
            base_object_id = str(
                edge.get("base_object_id", "")
                or node.get("base_object_id", "")
                or object_id
            )
            if not base_object_id:
                reasons.append("concrete_access_base_object_missing")
            if reasons:
                blockers.extend(
                    {
                        "site_id": site_id,
                        "function_id": function_id,
                        "object_id": object_id,
                        "edge_kind": edge_kind,
                        "reason": reason,
                    }
                    for reason in reasons
                )
                continue

            field_path = _field_path(edge)
            aggregate_object_id = str(edge.get("aggregate_object_id", ""))
            if not aggregate_object_id:
                if field_path:
                    node_field_path = tuple(
                        str(item)
                        for item in list(node.get("field_path", []) or [])
                        if str(item)
                    )
                    aggregate_object_id = (
                        object_id
                        if node_field_path == field_path
                        else _stable_field_object(object_id, field_path)
                    )
                elif selector_terms:
                    aggregate_object_id = base_object_id
                else:
                    aggregate_object_id = object_id
            deterministic_context_ids = tuple(
                sorted(
                    {
                        str(item)
                        for item in list(
                            edge.get("deterministic_context_ids", []) or []
                        )
                        if str(item)
                    }
                )
            )
            context_ids = tuple(
                sorted(
                    {
                        str(item)
                        for item in list(edge.get("context_ids", []) or [])
                        if str(item)
                        and str(item) not in deterministic_context_ids
                    }
                )
            )
            common = {
                "access_kind": (
                    "WRITE" if edge_kind == "OBJECT_WRITE" else "READ"
                ),
                "function_id": function_id,
                "site_id": site_id,
                "object_id": object_id,
                "base_object_id": base_object_id,
                "aggregate_object_id": aggregate_object_id,
                "field_path": field_path,
                "region_offset": region_offset,
                "region_extent": region_extent,
                "storage_kind": storage_kind,
                "deterministic_context_ids": deterministic_context_ids,
                "context_ids": context_ids,
                "access_edge_id": str(edge.get("edge_id", "")),
                "selector_terms": selector_terms,
                "address_provenance": str(edge.get("address_provenance", "")),
                "recognition": (
                    "heuristic"
                    if _selector_terms(edge)
                    or str(edge.get("analysis_precision", "EXACT")) == "MAY"
                    else "deterministic"
                ),
            }
            if edge_kind == "OBJECT_WRITE":
                writes.append(
                    WriteFact(
                        stored_atom_id=atom_id,
                        loaded_atom_id="",
                        **common,
                    )
                )
            else:
                reads.append(
                    ReadFact(
                        stored_atom_id="",
                        loaded_atom_id=atom_id,
                        **common,
                    )
                )

        return cls(write_facts=writes, read_facts=reads, blockers=blockers)

    def debug_dict(self) -> dict[str, Any]:
        return {
            "write_facts": [fact.to_dict() for fact in self.write_facts],
            "read_facts": [fact.to_dict() for fact in self.read_facts],
            "blockers": list(self.blockers),
            "counts": {
                "write_facts": len(self.write_facts),
                "read_facts": len(self.read_facts),
                "objects_with_writes": len(self.writes_by_object),
                "objects_with_reads": len(self.reads_by_object),
                "blockers": len(self.blockers),
            },
        }
