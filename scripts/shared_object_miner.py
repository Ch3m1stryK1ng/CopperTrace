#!/usr/bin/env python3
"""Admit Source-associated shared-objects before Channelgraph construction."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

import memory_access_facts


def _relation_id(kind: str, site_id: str, object_id: str) -> str:
    token = hashlib.sha256(
        f"{kind}|{site_id}|{object_id}".encode()
    ).hexdigest()[:20]
    return f"channel:{kind.lower()}:{token}"


def _shared_region_id(
    aggregate_object_id: str,
    write: memory_access_facts.WriteFact,
) -> str:
    if write.selector_terms:
        region_key = "dynamic"
    else:
        region_key = f"{write.region_offset}:{write.region_extent}"
    token = hashlib.sha256(
        f"{aggregate_object_id}|{region_key}".encode()
    ).hexdigest()[:20]
    return f"obj:shared-region:{token}"


def _region_partition_key(
    fact: memory_access_facts.WriteFact,
) -> tuple[str, ...]:
    if fact.selector_terms:
        return ("dynamic",)
    return ("fixed", str(fact.region_offset), str(fact.region_extent))


def _association_maps(
    associations: list[dict[str, Any]],
) -> tuple[
    dict[tuple[str, str], list[dict[str, Any]]],
    dict[str, list[dict[str, Any]]],
]:
    by_atom: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in associations:
        function_id = str(row.get("function_id", ""))
        atom_id = str(row.get("atom_id", ""))
        if function_id and atom_id:
            by_atom[(function_id, atom_id)].append(row)
        for object_id in {
            str(row.get("object_id", "")),
            str(dict(row.get("region", {}) or {}).get("object_id", "")),
        } - {""}:
            by_object[object_id].append(row)
    return dict(by_atom), dict(by_object)


def _source_rows_for_write(
    write: memory_access_facts.WriteFact,
    by_atom: dict[tuple[str, str], list[dict[str, Any]]],
    by_object: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    rows = list(by_atom.get((write.function_id, write.stored_atom_id), []))
    rows.extend(
        row
        for row in by_object.get(write.aggregate_object_id, [])
        if str(row.get("site_id", "")) == write.site_id
    )
    unique: dict[str, dict[str, Any]] = {}
    for row in rows:
        association_id = str(row.get("association_id", ""))
        if association_id:
            unique[association_id] = row
    return list(unique.values())


def _different_context(
    write: memory_access_facts.WriteFact,
    read: memory_access_facts.ReadFact,
) -> tuple[bool, str, bool]:
    if write.function_id == read.function_id:
        return False, "SAME_FUNCTION", False
    write_contexts = set(write.deterministic_context_ids)
    read_contexts = set(read.deterministic_context_ids)
    if (
        len(write_contexts) == 1
        and len(read_contexts) == 1
        and write_contexts != read_contexts
    ):
        return True, "DISTINCT_DETERMINISTIC_CONTEXT", True
    return True, "DISTINCT_FUNCTION_HEURISTIC_CONTEXT", False


def mine_source_associated_shared_objects(
    access_index: memory_access_facts.MemoryAccessFactIndex,
    source_associations: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Discover shared-objects from Source-associated concrete writes.

    Sink reachability, API names, queue contracts, and callback targets are
    deliberately absent from this admission procedure.
    """

    by_atom, by_object = _association_maps(source_associations)
    admitted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []

    for aggregate_object_id, writes in sorted(
        access_index.writes_by_object.items()
    ):
        source_rows_by_write = {
            write.site_id: _source_rows_for_write(write, by_atom, by_object)
            for write in writes
        }
        source_writes = [
            write
            for write in writes
            if source_rows_by_write.get(write.site_id)
        ]
        if not source_writes:
            continue
        all_reads = list(
            access_index.reads_by_object.get(aggregate_object_id, [])
        )
        source_groups: dict[
            tuple[str, ...], list[memory_access_facts.WriteFact]
        ] = defaultdict(list)
        for write in source_writes:
            source_groups[_region_partition_key(write)].append(write)

        for partition_key, partition_source_writes in sorted(
            source_groups.items()
        ):
            representative = partition_source_writes[0]
            paired_reads: list[
                tuple[
                    memory_access_facts.ReadFact,
                    memory_access_facts.RegionRelation,
                    str,
                    bool,
                ]
            ] = []
            disjoint_read_sites: list[str] = []
            same_function_read_sites: list[str] = []
            for read in all_reads:
                relation = memory_access_facts.region_relation(
                    representative, read
                )
                if relation == memory_access_facts.RegionRelation.DISJOINT:
                    disjoint_read_sites.append(read.site_id)
                    continue
                context_results = [
                    _different_context(write, read)
                    for write in partition_source_writes
                ]
                admissible_results = [
                    result for result in context_results if result[0]
                ]
                if not admissible_results:
                    same_function_read_sites.append(read.site_id)
                    continue
                deterministic_context = any(
                    result[2] for result in admissible_results
                )
                context_relation = (
                    "DISTINCT_DETERMINISTIC_CONTEXT"
                    if deterministic_context
                    else "DISTINCT_FUNCTION_HEURISTIC_CONTEXT"
                )
                paired_reads.append(
                    (
                        read,
                        relation,
                        context_relation,
                        deterministic_context,
                    )
                )
            if not paired_reads:
                if not all_reads:
                    reason = "source_associated_object_has_no_concrete_read"
                elif disjoint_read_sites and not same_function_read_sites:
                    reason = (
                        "source_associated_object_has_only_disjoint_read_regions"
                    )
                else:
                    reason = (
                        "source_associated_object_has_only_same_function_reads"
                    )
                blocker = {
                    "reason": reason,
                    "object_id": aggregate_object_id,
                    "write_site_ids": [
                        write.site_id for write in partition_source_writes
                    ],
                    "disjoint_read_site_ids": sorted(disjoint_read_sites),
                    "same_function_read_site_ids": sorted(
                        same_function_read_sites
                    ),
                }
                blockers.append(blocker)
                rejected.append(
                    {
                        "candidate_id": (
                            f"shared-candidate:{aggregate_object_id}:"
                            f"{':'.join(partition_key)}"
                        ),
                        "object_id": aggregate_object_id,
                        "admission_blockers": [reason],
                    }
                )
                continue

            partition_writes = [
                write
                for write in writes
                if _region_partition_key(write) == partition_key
            ]
            shared_object_id = _shared_region_id(
                aggregate_object_id, representative
            )

            for transfer_semantics in ("MEMORY_CONTENT", "OBJECT_REFERENCE"):
                matching_source_rows = [
                    row
                    for write in partition_source_writes
                    for row in source_rows_by_write.get(write.site_id, [])
                    if (
                        transfer_semantics == "OBJECT_REFERENCE"
                        and str(row.get("state_kind", "")) == "OBJECT_REFERENCE"
                    )
                    or (
                        transfer_semantics == "MEMORY_CONTENT"
                        and str(row.get("state_kind", "")) in {
                            "VALUE",
                            "MEMORY_CONTENT",
                        }
                    )
                ]
                if not matching_source_rows:
                    continue
                source_definition_ids = sorted(
                    {
                        str(row.get("source_definition_id", ""))
                        for row in matching_source_rows
                        if str(row.get("source_definition_id", ""))
                    }
                )
                source_ids = sorted(
                    {
                        str(row.get("source_id", ""))
                        for row in matching_source_rows
                        if str(row.get("source_id", ""))
                    }
                )
                source_decisions = sorted(
                    {
                        str(row.get("source_decision", ""))
                        for row in matching_source_rows
                        if str(row.get("source_decision", ""))
                    }
                )
                source_association_ids = sorted(
                    {
                        str(row.get("association_id", ""))
                        for row in matching_source_rows
                        if str(row.get("association_id", ""))
                    }
                )
                pointee_ids = sorted(
                    {
                        str(row.get("pointee_object_id", ""))
                        for row in matching_source_rows
                        if str(row.get("pointee_object_id", ""))
                    }
                )
                channel_depth = min(
                    int(row.get("channel_depth", 0) or 0)
                    for row in matching_source_rows
                )

                writer_rows: list[dict[str, Any]] = []
                for write in partition_writes:
                    writer_source_rows = source_rows_by_write.get(
                        write.site_id, []
                    )
                    source_associated = any(
                        (
                            transfer_semantics == "OBJECT_REFERENCE"
                            and str(row.get("state_kind", ""))
                            == "OBJECT_REFERENCE"
                        )
                        or (
                            transfer_semantics == "MEMORY_CONTENT"
                            and str(row.get("state_kind", ""))
                            in {"VALUE", "MEMORY_CONTENT"}
                        )
                        for row in writer_source_rows
                    )
                    writer_relation_deterministic = (
                        not write.selector_terms
                        and write.recognition == "deterministic"
                        and any(
                            relation
                            == memory_access_facts.RegionRelation.EXACT_OVERLAP
                            and _different_context(write, read)[2]
                            for (
                                read,
                                relation,
                                _,
                                _,
                            ) in paired_reads
                        )
                    )
                    writer_rows.append(
                        {
                            "edge_id": _relation_id(
                                "write",
                                write.site_id,
                                f"{shared_object_id}:{transfer_semantics}",
                            ),
                            "function_id": write.function_id,
                            "site_id": write.site_id,
                            "stored_atom_id": write.stored_atom_id,
                            "stored_value_id": write.stored_atom_id,
                            "value_atom_id": write.stored_atom_id,
                            "value_id": write.stored_atom_id,
                            "source_associated": source_associated,
                            "recognition": (
                                "deterministic"
                                if writer_relation_deterministic
                                else "heuristic"
                            ),
                            "deterministic": writer_relation_deterministic,
                            "region_relation": (
                                memory_access_facts.RegionRelation.MAY_OVERLAP.value
                                if write.selector_terms
                                else memory_access_facts.RegionRelation.EXACT_OVERLAP.value
                            ),
                            "source_definition_ids": sorted(
                                {
                                    str(row.get("source_definition_id", ""))
                                    for row in writer_source_rows
                                    if str(row.get("source_definition_id", ""))
                                }
                            ),
                            "source_ids": sorted(
                                {
                                    str(row.get("source_id", ""))
                                    for row in writer_source_rows
                                    if str(row.get("source_id", ""))
                                }
                            ),
                            "access": write.to_dict(),
                        }
                    )

                reader_rows = [
                    {
                        "edge_id": _relation_id(
                            "read",
                            read.site_id,
                            f"{shared_object_id}:{transfer_semantics}",
                        ),
                        "function_id": read.function_id,
                        "site_id": read.site_id,
                        "loaded_atom_id": read.loaded_atom_id,
                        "loaded_value_id": read.loaded_atom_id,
                        "value_atom_id": read.loaded_atom_id,
                        "value_id": read.loaded_atom_id,
                        "recognition": (
                            "deterministic"
                            if (
                                relation
                                == memory_access_facts.RegionRelation.EXACT_OVERLAP
                                and deterministic_context
                                and read.recognition == "deterministic"
                            )
                            else "heuristic"
                        ),
                        "deterministic": (
                            relation
                            == memory_access_facts.RegionRelation.EXACT_OVERLAP
                            and deterministic_context
                            and read.recognition == "deterministic"
                        ),
                        "access": read.to_dict(),
                        "region_relation": relation.value,
                        "context_relation": context_relation,
                    }
                    for (
                        read,
                        relation,
                        context_relation,
                        _,
                    ) in paired_reads
                ]
                deterministic = (
                    any(
                        row.get("source_associated")
                        and row.get("deterministic")
                        for row in writer_rows
                    )
                    and all(row.get("deterministic") for row in reader_rows)
                    and all(
                        str(row.get("precision", "MAY")) == "EXACT"
                        for row in matching_source_rows
                    )
                    and (
                        not source_decisions
                        or source_decisions == ["ACCEPT_DETERMINISTIC"]
                    )
                )
                reference_binding = {}
                if transfer_semantics == "OBJECT_REFERENCE":
                    reference_binding = {
                        "producer_atom_id": representative.stored_atom_id,
                        "pointee_object_id": (
                            pointee_ids[0] if len(pointee_ids) == 1 else ""
                        ),
                    }
                admitted.append(
                    {
                        "candidate_id": (
                            f"shared-candidate:{shared_object_id}:"
                            f"{transfer_semantics}"
                        ),
                        "node_id": shared_object_id,
                        "node_kind": "SHARED_OBJECT",
                        "object_id": shared_object_id,
                        "aggregate_object_id": aggregate_object_id,
                        "base_object_id": representative.base_object_id,
                        "region": {
                            "object_id": shared_object_id,
                            "aggregate_object_id": aggregate_object_id,
                            "base_object_id": representative.base_object_id,
                            "offset": representative.region_offset,
                            "extent": representative.region_extent,
                            "field_path": list(representative.field_path),
                            "selector_terms": list(
                                representative.selector_terms
                            ),
                        },
                        "region_relation": (
                            memory_access_facts.RegionRelation.EXACT_OVERLAP.value
                            if all(
                                relation
                                == memory_access_facts.RegionRelation.EXACT_OVERLAP
                                for _, relation, _, _ in paired_reads
                            )
                            else memory_access_facts.RegionRelation.MAY_OVERLAP.value
                        ),
                        "storage_kind": representative.storage_kind,
                        "transfer_semantics": transfer_semantics,
                        "analysis_precision": (
                            "EXACT" if deterministic else "MAY"
                        ),
                        "recognition": (
                            "deterministic" if deterministic else "heuristic"
                        ),
                        "source_ids": source_ids,
                        "source_decisions": source_decisions,
                        "source_id": (
                            source_ids[0] if len(source_ids) == 1 else ""
                        ),
                        "source_lineage_ids": source_definition_ids,
                        "reference_binding": reference_binding,
                        "channel_depth": channel_depth,
                        "writers": writer_rows,
                        "readers": reader_rows,
                        "evidence_level": (
                            "SOURCE_ASSOCIATED_CONCRETE_STORE_LOAD"
                        ),
                        "evidence": {
                            "source_association_ids": source_association_ids,
                            "admission_independent_of_sink": True,
                            "all_writer_accesses": [
                                write.to_dict() for write in writes
                            ],
                            "excluded_disjoint_read_site_ids": sorted(
                                disjoint_read_sites
                            ),
                        },
                        "admission_blockers": [],
                    }
                )

    return {
        "shared_objects": admitted,
        "rejected_candidates": rejected,
        "blockers": blockers + list(access_index.blockers),
    }


def mine_source_associated_transport_objects(
    transport_nodes: list[dict[str, Any]],
    transport_edges: list[dict[str, Any]],
    source_associations: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Admit a body-proved payload transport only after Source association.

    This covers queue/callback implementations whose physical record storage
    is body-proved but whose transported object is an allocation-site or
    caller-owned pointer.  The transport resolver remains independent of
    Source and Sink discovery; this admission step merely requires that its
    producer atom already carries an explicit Source lineage.
    """

    by_atom, _ = _association_maps(source_associations)
    node_by_id = {
        str(node.get("object_id", node.get("node_id", ""))): dict(node)
        for node in transport_nodes
        if str(node.get("object_id", node.get("node_id", "")))
    }
    edges_by_object: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in transport_edges:
        edge = dict(raw or {})
        object_id = str(edge.get("object_id", ""))
        if object_id:
            edges_by_object[object_id].append(edge)

    admitted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for object_id, relations in sorted(edges_by_object.items()):
        writers = [
            edge
            for edge in relations
            if str(edge.get("edge_kind", "")) == "CHANNEL_WRITE"
        ]
        readers = [
            edge
            for edge in relations
            if str(edge.get("edge_kind", "")) == "CHANNEL_READ"
        ]
        if not writers or not readers:
            blockers.append(
                {
                    "reason": "transport_relation_missing_writer_or_reader",
                    "object_id": object_id,
                }
            )
            continue

        source_rows_by_edge: dict[str, list[dict[str, Any]]] = {}
        for writer in writers:
            function_id = str(
                writer.get("src_node_id", writer.get("function_id", ""))
            )
            atom_id = str(
                writer.get("value_atom_id", "")
                or writer.get("stored_atom_id", "")
                or writer.get("value_id", "")
            )
            source_rows_by_edge[str(writer.get("edge_id", ""))] = [
                row
                for row in by_atom.get((function_id, atom_id), [])
                if str(row.get("state_kind", ""))
                in {"OBJECT_REFERENCE", "VALUE"}
            ]
        matching_rows = [
            row
            for rows in source_rows_by_edge.values()
            for row in rows
        ]
        if not matching_rows:
            rejected.append(
                {
                    "candidate_id": f"transport-candidate:{object_id}",
                    "object_id": object_id,
                    "admission_blockers": [
                        "transport_writer_has_no_source_association"
                    ],
                }
            )
            continue

        # The resolver must have linked a concrete submission chain to a
        # concrete consumer. A bare callback target or function name is not
        # sufficient evidence for a payload-preserving relation.
        evidence = dict(writers[0].get("evidence", {}) or {})
        submission_chain = list(evidence.get("submission_chain", []) or [])
        consumers = list(
            evidence.get("dequeue_dispatch_consumers", []) or []
        )
        if not submission_chain or not consumers:
            blockers.append(
                {
                    "reason": "transport_body_proof_incomplete",
                    "object_id": object_id,
                }
            )
            continue

        source_definition_ids = sorted(
            {
                str(row.get("source_definition_id", ""))
                for row in matching_rows
                if str(row.get("source_definition_id", ""))
            }
        )
        source_ids = sorted(
            {
                str(row.get("source_id", ""))
                for row in matching_rows
                if str(row.get("source_id", ""))
            }
        )
        source_decisions = sorted(
            {
                str(row.get("source_decision", ""))
                for row in matching_rows
                if str(row.get("source_decision", ""))
            }
        )
        association_ids = sorted(
            {
                str(row.get("association_id", ""))
                for row in matching_rows
                if str(row.get("association_id", ""))
            }
        )
        pointee_ids = sorted(
            {
                str(row.get("pointee_object_id", ""))
                for row in matching_rows
                if str(row.get("pointee_object_id", ""))
            }
        )
        writer_rows: list[dict[str, Any]] = []
        for writer in writers:
            edge_id = str(writer.get("edge_id", ""))
            rows = source_rows_by_edge.get(edge_id, [])
            writer_rows.append(
                {
                    "edge_id": edge_id,
                    "function_id": str(
                        writer.get(
                            "src_node_id", writer.get("function_id", "")
                        )
                    ),
                    "site_id": str(writer.get("site_id", "")),
                    "stored_atom_id": str(
                        writer.get("value_atom_id", "")
                        or writer.get("stored_atom_id", "")
                        or writer.get("value_id", "")
                    ),
                    "value_atom_id": str(
                        writer.get("value_atom_id", "")
                        or writer.get("stored_atom_id", "")
                        or writer.get("value_id", "")
                    ),
                    "source_associated": bool(rows),
                    "source_definition_ids": sorted(
                        {
                            str(row.get("source_definition_id", ""))
                            for row in rows
                            if str(row.get("source_definition_id", ""))
                        }
                    ),
                    "source_ids": sorted(
                        {
                            str(row.get("source_id", ""))
                            for row in rows
                            if str(row.get("source_id", ""))
                        }
                    ),
                    "recognition": "heuristic",
                    "deterministic": False,
                    "region_relation": "MAY_OVERLAP",
                    "transport_evidence": evidence,
                }
            )
        reader_rows = [
            {
                "edge_id": str(reader.get("edge_id", "")),
                "function_id": str(
                    reader.get(
                        "dst_node_id", reader.get("function_id", "")
                    )
                ),
                "site_id": str(reader.get("site_id", "")),
                "loaded_atom_id": str(
                    reader.get("value_atom_id", "")
                    or reader.get("loaded_atom_id", "")
                    or reader.get("value_id", "")
                ),
                "value_atom_id": str(
                    reader.get("value_atom_id", "")
                    or reader.get("loaded_atom_id", "")
                    or reader.get("value_id", "")
                ),
                "recognition": "heuristic",
                "deterministic": False,
                "region_relation": "MAY_OVERLAP",
                "transport_evidence": dict(reader.get("evidence", {}) or {}),
            }
            for reader in readers
        ]
        original_node = node_by_id.get(object_id, {})
        admitted.append(
            {
                "candidate_id": f"transport-candidate:{object_id}",
                "node_id": object_id,
                "node_kind": "SHARED_OBJECT",
                "object_id": object_id,
                "aggregate_object_id": object_id,
                "base_object_id": str(
                    original_node.get("base_object_id", object_id)
                ),
                "region": dict(
                    original_node.get(
                        "region",
                        {
                            "object_id": object_id,
                            "base_object_id": object_id,
                            "offset": 0,
                            "extent": 1,
                            "extent_kind": "PAYLOAD_OBJECT_REFERENCE",
                        },
                    )
                    or {}
                ),
                "region_relation": "MAY_OVERLAP",
                "storage_kind": "DEFERRED_PAYLOAD_REFERENCE",
                "transfer_semantics": "OBJECT_REFERENCE",
                "analysis_precision": "MAY",
                "recognition": "heuristic",
                "source_ids": source_ids,
                "source_decisions": source_decisions,
                "source_id": source_ids[0] if len(source_ids) == 1 else "",
                "source_lineage_ids": source_definition_ids,
                "reference_binding": {
                    "producer_atom_id": writer_rows[0][
                        "stored_atom_id"
                    ],
                    "pointee_object_id": (
                        pointee_ids[0] if len(pointee_ids) == 1 else ""
                    ),
                },
                "channel_depth": min(
                    int(row.get("channel_depth", 0) or 0)
                    for row in matching_rows
                ),
                "writers": writer_rows,
                "readers": reader_rows,
                "evidence_level": (
                    "SOURCE_ASSOCIATED_BODY_PROVED_TRANSPORT"
                ),
                "evidence": {
                    "source_association_ids": association_ids,
                    "admission_independent_of_sink": True,
                    "transport_contract": evidence,
                },
                "admission_blockers": [],
            }
        )

    return {
        "shared_objects": admitted,
        "rejected_candidates": rejected,
        "blockers": blockers,
    }


def mine_object_reference_effect_objects(
    writer_facts: list[dict[str, Any]],
    reader_facts: list[dict[str, Any]],
    source_associations: list[dict[str, Any]],
    *,
    deterministic_contexts: dict[str, tuple[set[str], str]] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """Convert body-proved object-reference effects into shared-objects.

    The body recognizer has already proved insert/remove effects and bound
    them to concrete callsites.  This admission step adds the two facts that
    make them CCC: a Source lineage on the inserted reference and a distinct
    reader Function for the same container Region.
    """

    contexts = deterministic_contexts or {}
    association_by_id = {
        str(row.get("association_id", "")): dict(row or {})
        for row in source_associations
        if str(row.get("association_id", ""))
    }

    def region_key(row: dict[str, Any]) -> tuple[str, int, int]:
        region = dict(row.get("region", {}) or {})
        return (
            str(region.get("base_object_id", "")),
            int(region.get("offset", 0) or 0),
            int(region.get("extent", 0) or 0),
        )

    writers_by_region: dict[tuple[str, int, int], list[dict[str, Any]]] = (
        defaultdict(list)
    )
    readers_by_region: dict[tuple[str, int, int], list[dict[str, Any]]] = (
        defaultdict(list)
    )
    for row in writer_facts:
        if bool(row.get("ccc_eligible")):
            writers_by_region[region_key(row)].append(dict(row))
    for row in reader_facts:
        if bool(row.get("ccc_eligible")):
            readers_by_region[region_key(row)].append(dict(row))

    admitted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    for key, writers in sorted(writers_by_region.items()):
        readers = readers_by_region.get(key, [])
        if not readers:
            continue
        base_object_id, offset, extent = key
        for writer in writers:
            for reader in readers:
                writer_function = str(writer.get("function_id", ""))
                reader_function = str(reader.get("function_id", ""))
                if not writer_function or not reader_function:
                    blockers.append(
                        {
                            "reason": "object_reference_context_function_unresolved",
                            "writer_fact_id": str(writer.get("fact_id", "")),
                            "reader_fact_id": str(reader.get("fact_id", "")),
                        }
                    )
                    continue
                if writer_function == reader_function:
                    rejected.append(
                        {
                            "candidate_id": str(writer.get("fact_id", "")),
                            "object_id": base_object_id,
                            "admission_blockers": [
                                "object_reference_same_function_not_ccc"
                            ],
                        }
                    )
                    continue

                writer_context_ids = set(contexts.get(writer_function, (set(), ""))[0])
                reader_context_ids = set(contexts.get(reader_function, (set(), ""))[0])
                deterministic_context_pair = (
                    len(writer_context_ids) == 1
                    and len(reader_context_ids) == 1
                    and writer_context_ids != reader_context_ids
                )
                exact = (
                    str(writer.get("analysis_precision", "")) == "EXACT"
                    and str(reader.get("analysis_precision", "")) == "EXACT"
                    and deterministic_context_pair
                )
                recognition = "deterministic" if exact else "heuristic"
                precision = "EXACT" if exact else "MAY"
                object_token = hashlib.sha256(
                    f"{base_object_id}|{offset}|{extent}|OBJECT_REFERENCE".encode()
                ).hexdigest()[:20]
                object_id = f"obj:shared-region:{object_token}"

                association_rows = [
                    association_by_id[association_id]
                    for association_id in list(
                        writer.get("source_association_ids", []) or []
                    )
                    if association_id in association_by_id
                ]
                source_definition_ids = sorted(
                    {
                        str(row.get("source_definition_id", ""))
                        for row in association_rows
                        if str(row.get("source_definition_id", ""))
                    }
                    or {
                        str(item)
                        for item in list(
                            writer.get("source_definition_ids", []) or []
                        )
                        if str(item)
                    }
                )
                source_ids = sorted(
                    {
                        str(row.get("source_id", ""))
                        for row in association_rows
                        if str(row.get("source_id", ""))
                    }
                    or {
                        str(item)
                        for item in list(writer.get("source_ids", []) or [])
                        if str(item)
                    }
                )
                source_decisions = sorted(
                    {
                        str(row.get("source_decision", ""))
                        for row in association_rows
                        if str(row.get("source_decision", ""))
                    }
                )
                pointee_ids = sorted(
                    {
                        str(row.get("pointee_object_id", ""))
                        for row in association_rows
                        if str(row.get("pointee_object_id", ""))
                    }
                )
                pointee_object_id = (
                    pointee_ids[0] if len(pointee_ids) == 1 else ""
                )
                writer_edge_id = _relation_id(
                    "OBJECT_REFERENCE_WRITE",
                    str(writer.get("callsite_id", "")),
                    object_id,
                )
                reader_edge_id = _relation_id(
                    "OBJECT_REFERENCE_READ",
                    str(reader.get("callsite_id", "")),
                    object_id,
                )
                writer_row = {
                    "edge_id": writer_edge_id,
                    "function_id": writer_function,
                    "site_id": str(writer.get("callsite_id", "")),
                    "physical_store_site_id": str(
                        writer.get("physical_store_site_id", "")
                    ),
                    "stored_atom_id": str(
                        writer.get("payload_actual_atom_id", "")
                    ),
                    "value_atom_id": str(
                        writer.get("payload_actual_atom_id", "")
                    ),
                    "source_associated": True,
                    "source_definition_ids": source_definition_ids,
                    "source_ids": source_ids,
                    "recognition": recognition,
                    "deterministic": exact,
                    "region_relation": "EXACT_OVERLAP",
                    "analysis_precision": precision,
                    "reference_binding": {
                        "producer_atom_id": str(
                            writer.get("payload_actual_atom_id", "")
                        ),
                        "pointee_object_id": pointee_object_id,
                    },
                }
                reader_row = {
                    "edge_id": reader_edge_id,
                    "function_id": reader_function,
                    "site_id": str(reader.get("callsite_id", "")),
                    "physical_load_site_id": str(
                        reader.get("physical_load_site_id", "")
                    ),
                    "loaded_atom_id": str(
                        reader.get("loaded_result_atom_id", "")
                    ),
                    "value_atom_id": str(
                        reader.get("loaded_result_atom_id", "")
                    ),
                    "value_object_id": str(
                        reader.get("loaded_result_object_id", "")
                    ),
                    "recognition": recognition,
                    "deterministic": exact,
                    "region_relation": "EXACT_OVERLAP",
                    "analysis_precision": precision,
                    "reference_binding": {
                        "consumer_atom_id": str(
                            reader.get("loaded_result_atom_id", "")
                        ),
                        "pointee_object_id": pointee_object_id,
                    },
                }
                admitted.append(
                    {
                        "candidate_id": (
                            f"object-reference-candidate:{writer_edge_id}:"
                            f"{reader_edge_id}"
                        ),
                        "node_id": object_id,
                        "node_kind": "SHARED_OBJECT",
                        "object_id": object_id,
                        "aggregate_object_id": base_object_id,
                        "base_object_id": base_object_id,
                        "region": {
                            "object_id": object_id,
                            "aggregate_object_id": base_object_id,
                            "base_object_id": base_object_id,
                            "offset": offset,
                            "extent": extent,
                        },
                        "region_relation": "EXACT_OVERLAP",
                        "storage_kind": "OBJECT_REFERENCE_CONTAINER",
                        "transfer_semantics": "OBJECT_REFERENCE",
                        "analysis_precision": precision,
                        "recognition": recognition,
                        "source_ids": source_ids,
                        "source_decisions": source_decisions,
                        "source_id": source_ids[0] if len(source_ids) == 1 else "",
                        "source_lineage_ids": source_definition_ids,
                        "reference_binding": {
                            "producer_atom_id": str(
                                writer.get("payload_actual_atom_id", "")
                            ),
                            "consumer_atom_id": str(
                                reader.get("loaded_result_atom_id", "")
                            ),
                            "pointee_object_id": pointee_object_id,
                        },
                        "channel_depth": min(
                            [
                                int(row.get("channel_depth", 0) or 0)
                                for row in association_rows
                            ]
                            or [0]
                        ),
                        "writers": [writer_row],
                        "readers": [reader_row],
                        "evidence_level": (
                            "SOURCE_ASSOCIATED_BODY_PROVED_OBJECT_REFERENCE"
                        ),
                        "evidence": {
                            "source_association_ids": list(
                                writer.get("source_association_ids", []) or []
                            ),
                            "insert_summary_id": str(
                                writer.get("summary_id", "")
                            ),
                            "remove_summary_id": str(
                                reader.get("summary_id", "")
                            ),
                            "writer_fact_id": str(writer.get("fact_id", "")),
                            "reader_fact_id": str(reader.get("fact_id", "")),
                            "writer_context_ids": sorted(writer_context_ids),
                            "reader_context_ids": sorted(reader_context_ids),
                            "admission_independent_of_sink": True,
                        },
                        "admission_blockers": [],
                    }
                )

    return {
        "shared_objects": admitted,
        "rejected_candidates": rejected,
        "blockers": blockers,
    }


def mine_shared_objects(
    candidates: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Apply the vNext shared-object contract to structural candidates."""

    admitted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    blockers: list[dict[str, Any]] = []
    seen: set[str] = set()

    for raw in candidates:
        candidate = dict(raw or {})
        object_id = str(candidate.get("object_id", ""))
        writers = list(candidate.get("writers", []) or [])
        readers = list(candidate.get("readers", []) or [])
        source_lineage = sorted(
            {
                str(item)
                for item in list(candidate.get("source_lineage_ids", []) or [])
                if str(item)
            }
        )
        transfer = str(candidate.get("transfer_semantics", ""))
        reasons: list[str] = []
        if not object_id:
            reasons.append("shared_object_identity_missing")
        if not source_lineage:
            reasons.append("shared_object_has_no_source_association")
        if not writers:
            reasons.append("shared_object_has_no_writer")
        if not readers:
            reasons.append("shared_object_has_no_reader")
        if transfer not in {"MEMORY_CONTENT", "OBJECT_REFERENCE"}:
            reasons.append("shared_object_transfer_semantics_unknown")
        if str(candidate.get("storage_kind", "")) == "STACK_LOCAL":
            reasons.append("source_derived_stack_local_not_shared")

        candidate_id = str(candidate.get("candidate_id", "")) or object_id
        if reasons:
            rejected.append({**candidate, "admission_blockers": reasons})
            blockers.extend(
                {
                    "reason": reason,
                    "object_id": object_id,
                    "candidate_id": candidate_id,
                }
                for reason in reasons
            )
            continue
        unique_key = "|".join(
            [
                object_id,
                transfer,
                ",".join(source_lineage),
                ",".join(
                    sorted(str(row.get("site_id", "")) for row in writers)
                ),
                ",".join(
                    sorted(str(row.get("site_id", "")) for row in readers)
                ),
            ]
        )
        if unique_key in seen:
            continue
        seen.add(unique_key)
        admitted.append(
            {
                **candidate,
                "node_id": object_id,
                "node_kind": "SHARED_OBJECT",
                "source_lineage_ids": source_lineage,
                "recognition": str(candidate.get("recognition", "heuristic")),
                "admission_blockers": [],
            }
        )

    merged: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for candidate in admitted:
        region = dict(candidate.get("region", {}) or {})
        reference = dict(candidate.get("reference_binding", {}) or {})
        key = (
            str(candidate.get("object_id", "")),
            str(candidate.get("transfer_semantics", "")),
            str(region.get("offset", "")),
            str(region.get("extent", region.get("size", ""))),
            str(reference.get("pointee_object_id", "")),
        )
        previous = merged.get(key)
        if previous is None:
            merged[key] = dict(candidate)
            continue
        previous["writers"] = list(
            {
                str(row.get("edge_id", "")): row
                for row in (
                    list(previous.get("writers", []) or [])
                    + list(candidate.get("writers", []) or [])
                )
                if str(row.get("edge_id", ""))
            }.values()
        )
        previous["readers"] = list(
            {
                str(row.get("edge_id", "")): row
                for row in (
                    list(previous.get("readers", []) or [])
                    + list(candidate.get("readers", []) or [])
                )
                if str(row.get("edge_id", ""))
            }.values()
        )
        previous["source_ids"] = sorted(
            {
                *list(previous.get("source_ids", []) or []),
                *list(candidate.get("source_ids", []) or []),
            }
        )
        previous["source_lineage_ids"] = sorted(
            {
                *list(previous.get("source_lineage_ids", []) or []),
                *list(candidate.get("source_lineage_ids", []) or []),
            }
        )
        previous_evidence = dict(previous.get("evidence", {}) or {})
        candidate_evidence = dict(candidate.get("evidence", {}) or {})
        previous_evidence["source_association_ids"] = sorted(
            {
                *list(previous_evidence.get("source_association_ids", []) or []),
                *list(candidate_evidence.get("source_association_ids", []) or []),
            }
        )
        previous["evidence"] = previous_evidence

    return {
        "shared_objects": sorted(
            merged.values(), key=lambda row: str(row.get("candidate_id", ""))
        ),
        "rejected_candidates": rejected,
        "blockers": blockers,
    }


def materialize_channel_edges(
    shared_objects: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Emit graph relations without rediscovering or rescoring objects."""

    edges: dict[str, dict[str, Any]] = {}
    for shared in shared_objects:
        object_id = str(shared.get("object_id", ""))
        common = {
            "object_id": object_id,
            "base_object_id": str(shared.get("base_object_id", object_id)),
            "region": dict(shared.get("region", {}) or {}),
            "transfer_semantics": str(shared.get("transfer_semantics", "")),
            "analysis_precision": str(shared.get("analysis_precision", "MAY")),
            "strict_admissible": True,
            "deterministic": str(shared.get("recognition", "")) == "deterministic",
            "candidate_only": False,
            "traversable": True,
            "source_lineage_ids": list(shared.get("source_lineage_ids", []) or []),
            "source_ids": list(shared.get("source_ids", []) or []),
            "source_id": str(shared.get("source_id", "")),
            "channel_depth": int(shared.get("channel_depth", 0) or 0),
            "evidence_level": str(shared.get("evidence_level", "")),
            "evidence": dict(shared.get("evidence", {}) or {}),
            "reference_binding": dict(shared.get("reference_binding", {}) or {}),
        }
        paired_ids = [
            str(row.get("edge_id", ""))
            for row in (
                list(shared.get("writers", []) or [])
                + list(shared.get("readers", []) or [])
            )
            if str(row.get("edge_id", ""))
        ]
        for relation in list(shared.get("writers", []) or []):
            writer_source_ids = list(relation.get("source_ids", []) or [])
            writer_definition_ids = list(
                relation.get("source_definition_ids", []) or []
            )
            edge = {
                **common,
                **dict(relation),
                "edge_kind": "CHANNEL_WRITE",
                "src_node_id": str(relation.get("function_id", "")),
                "dst_node_id": object_id,
                "source_associated": bool(
                    relation.get("source_associated", False)
                ),
                "source_ids": writer_source_ids,
                "source_id": (
                    writer_source_ids[0]
                    if len(writer_source_ids) == 1
                    else ""
                ),
                "source_lineage_ids": writer_definition_ids,
                "paired_edge_ids": [
                    edge_id
                    for edge_id in paired_ids
                    if edge_id != str(relation.get("edge_id", ""))
                ],
            }
            if str(edge.get("edge_id", "")):
                edges[str(edge["edge_id"])] = edge
        for relation in list(shared.get("readers", []) or []):
            edge = {
                **common,
                **dict(relation),
                "edge_kind": "CHANNEL_READ",
                "src_node_id": object_id,
                "dst_node_id": str(relation.get("function_id", "")),
                "source_associated": bool(
                    shared.get("source_lineage_ids", [])
                ),
                "paired_edge_ids": [
                    edge_id
                    for edge_id in paired_ids
                    if edge_id != str(relation.get("edge_id", ""))
                ],
            }
            if str(edge.get("edge_id", "")):
                edges[str(edge["edge_id"])] = edge
    return [edges[key] for key in sorted(edges)]
