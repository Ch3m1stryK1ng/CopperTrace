#!/usr/bin/env python3
"""CopperTrace A2 Alert Filter with exact Source-lineage deduplication."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any

from filter_static_alerts import (
    SOURCE_REACHED_STATUSES,
    load_json,
    sha256_file,
    stable_key,
    write_json,
)


DETERMINISTIC_DECISIONS = frozenset(
    {"ACCEPT_DETERMINISTIC", "DETERMINISTIC", "CONFIRMED_DETERMINISTIC"}
)


def _source_backed_parameters(chain: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        row
        for row in list(chain.get("parameter_results", []) or [])
        if str(row.get("status", "")) in SOURCE_REACHED_STATUSES
        and list(row.get("paths", []) or [])
    ]


def _source_descriptor(
    source_id: str, source_rows: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    source = source_rows.get(source_id, {})
    proof = dict(source.get("proof", {}) or {})
    resolution = dict(proof.get("register_resolution", {}) or {})
    register_addresses = list(proof.get("register_addresses", []) or [])
    if not register_addresses and proof.get("register_address"):
        register_addresses = [proof.get("register_address")]
    source_output = dict(source.get("source_output", {}) or {})
    return {
        "source_id": source_id,
        "label": str(source.get("label", "") or ""),
        "site_id": str(source.get("site_id", "") or ""),
        "function_id": str(source.get("function_id", "") or ""),
        "register_addresses": sorted(str(value) for value in register_addresses),
        "register_role": str(resolution.get("role", "") or ""),
        "source_object_id": str(
            source.get("source_object_id")
            or source_output.get("object_id")
            or ""
        ),
        "source_output_role": str(source_output.get("role", "") or ""),
    }


def _channel_descriptor(edge: dict[str, Any]) -> dict[str, Any] | None:
    kind = str(edge.get("kind", "") or "")
    if "CHANNEL" not in kind:
        return None
    region = dict(edge.get("region", {}) or {})
    return {
        "kind": kind,
        "graph_edge_id": str(
            edge.get("graph_edge_id") or edge.get("edge_id") or ""
        ),
        "object_id": str(edge.get("object_id", "") or ""),
        "region_start": str(region.get("start", "") or ""),
        "region_end": str(region.get("end", "") or ""),
        "region_precision": str(region.get("precision", "") or ""),
    }


def _path_lineage(
    role: str,
    path: dict[str, Any],
    source_rows: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    lineage_ids = [
        str(value)
        for value in (
            list(path.get("source_lineage_ids", []) or [])
            or [path.get("source_id", "")]
        )
        if str(value)
    ]
    channels = [
        descriptor
        for edge in list(path.get("path", []) or [])
        if (descriptor := _channel_descriptor(edge)) is not None
    ]
    descriptor = {
        "role": role,
        "source_boundary": [
            _source_descriptor(source_id, source_rows)
            for source_id in sorted(set(lineage_ids))
        ],
        "terminal_source_site_id": str(path.get("source_site_id", "") or ""),
        "channel_route": channels,
    }
    return {
        "fingerprint": f"lineage:{stable_key(descriptor)}",
        "descriptor": descriptor,
        "source_decision": str(path.get("source_decision", "") or ""),
        "path_precision": str(path.get("path_precision", "") or ""),
        "uses_channelgraph": bool(channels),
        "channel_precision": _channel_precision(path),
    }


def _channel_precision(path: dict[str, Any]) -> str:
    channel_edges = [
        edge
        for edge in list(path.get("path", []) or [])
        if "CHANNEL" in str(edge.get("kind", "") or "")
    ]
    if not channel_edges:
        return "NOT_USED"
    for edge in channel_edges:
        evidence = dict(edge.get("evidence", {}) or {})
        precision = str(evidence.get("analysis_precision", "") or "").upper()
        if precision not in {"EXACT", "DETERMINISTIC", "MUST"}:
            return "HEURISTIC"
    return "DETERMINISTIC"


def _lineages_for_chain(
    chain: dict[str, Any], source_rows: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for parameter in _source_backed_parameters(chain):
        role = str(parameter.get("role", "") or "unknown")
        for path in list(parameter.get("paths", []) or []):
            result.append(_path_lineage(role, path, source_rows))
    by_fingerprint = {row["fingerprint"]: row for row in result}
    return [by_fingerprint[key] for key in sorted(by_fingerprint)]


def _sink_effect_site(chain: dict[str, Any], sink: dict[str, Any]) -> str:
    return str(
        sink.get("effect_site_id")
        or chain.get("sink_site_id")
        or sink.get("site_id")
        or ""
    )


def _sink_boundary_site(chain: dict[str, Any], sink: dict[str, Any]) -> str:
    return str(sink.get("site_id") or chain.get("sink_site_id") or "")


def _vulnerable_roles(sink: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(row.get("role", "") or "unknown")
                for row in list(sink.get("vulnerable_parameters", []) or [])
            }
        )
    )


def _reached_roles(chain: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(row.get("role", "") or "unknown")
                for row in _source_backed_parameters(chain)
            }
        )
    )


def _proof_level(value: str) -> str:
    return "deterministic" if str(value or "").upper() in DETERMINISTIC_DECISIONS else "heuristic"


def _evidence_vector(
    chain: dict[str, Any],
    sink: dict[str, Any],
    lineages: list[dict[str, Any]],
) -> dict[str, Any]:
    vulnerable_roles = _vulnerable_roles(sink)
    reached_roles = _reached_roles(chain)
    source_level = (
        "deterministic"
        if any(
            _proof_level(row.get("source_decision", "")) == "deterministic"
            for row in lineages
        )
        else "heuristic"
    )
    path_level = (
        "deterministic"
        if lineages
        and any(
            str(row.get("path_precision", "")).upper()
            in {"EXACT", "DETERMINISTIC", "MUST"}
            and str(row.get("channel_precision", ""))
            in {"NOT_USED", "DETERMINISTIC"}
            for row in lineages
        )
        else "heuristic"
    )
    unresolved = any(
        list(row.get("blockers", []) or []) or row.get("first_missing_relation")
        for row in list(chain.get("parameter_results", []) or [])
        if str(row.get("role", "") or "") in vulnerable_roles
    ) or set(vulnerable_roles) != set(reached_roles)
    return {
        "sink_evidence": (
            "deterministic"
            if str(sink.get("recognition", "") or "").lower() == "deterministic"
            else "heuristic"
        ),
        "source_evidence": source_level,
        "parameter_coverage": {
            "reached": len(reached_roles),
            "total": len(vulnerable_roles),
            "reached_roles": list(reached_roles),
            "vulnerable_roles": list(vulnerable_roles),
        },
        "path_evidence": path_level,
        "uses_channelgraph": any(row.get("uses_channelgraph") for row in lineages),
        "channelgraph_evidence": (
            "heuristic"
            if any(row.get("channel_precision") == "HEURISTIC" for row in lineages)
            else "deterministic_or_not_used"
        ),
        "has_unresolved_relation": unresolved,
    }


def _rank_key(row: dict[str, Any]) -> tuple[Any, ...]:
    evidence = dict(row.get("evidence", {}) or {})
    coverage = dict(evidence.get("parameter_coverage", {}) or {})
    reached_roles = {
        str(value).lower()
        for value in list(coverage.get("reached_roles", []) or [])
    }
    scalar_control_reached = bool(
        reached_roles
        & {
            "len",
            "length",
            "size",
            "count",
            "amount",
            "index",
            "offset",
            "cursor",
            "width",
            "available_length",
            "bound",
        }
    )
    return (
        0 if scalar_control_reached else 1,
        int(coverage.get("total", 0)) - int(coverage.get("reached", 0)),
        1 if bool(evidence.get("has_unresolved_relation", False)) else 0,
        len(list(row.get("source_lineages", []) or [])),
        str(row.get("alert_id", "")),
    )


def _candidate(
    chain: dict[str, Any],
    sink: dict[str, Any],
    source_rows: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    lineages = _lineages_for_chain(chain, source_rows)
    boundary_site = _sink_boundary_site(chain, sink)
    effect_site = _sink_effect_site(chain, sink)
    roles = _vulnerable_roles(sink)
    lineage_fingerprints = tuple(row["fingerprint"] for row in lineages)
    equivalence = {
        "sink_label": str(chain.get("sink_label") or sink.get("label") or ""),
        "sink_boundary_site_id": boundary_site,
        "sink_effect_site_id": effect_site,
        "vulnerable_parameter_roles": roles,
        "source_lineage_fingerprints": lineage_fingerprints,
    }
    result = {
        "alert_id": str(chain.get("chain_id", "")),
        "sink_id": str(chain.get("sink_id", "")),
        "sink_label": equivalence["sink_label"],
        "sink_boundary_site_id": boundary_site,
        "sink_effect_site_id": effect_site,
        "vulnerable_parameter_roles": list(roles),
        "source_lineages": lineages,
        "source_lineage_fingerprints": list(lineage_fingerprints),
        "equivalence_group_id": f"a2-equivalence:{stable_key(equivalence)}",
    }
    result["evidence"] = _evidence_vector(chain, sink, lineages)
    return result


def _exact_lineage_dedup(
    candidates: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in candidates:
        groups.setdefault(str(row["equivalence_group_id"]), []).append(row)

    canonical: list[dict[str, Any]] = []
    merged: list[dict[str, Any]] = []
    for group_id in sorted(groups):
        rows = sorted(groups[group_id], key=_rank_key)
        representative = dict(rows[0])
        representative["represented_alert_ids"] = sorted(
            str(row["alert_id"]) for row in rows
        )
        representative["represented_sink_boundary_site_ids"] = sorted(
            {
                str(row.get("sink_boundary_site_id", ""))
                for row in rows
                if str(row.get("sink_boundary_site_id", ""))
            }
        )
        canonical.append(representative)
        for duplicate in rows[1:]:
            merged.append(
                {
                    "canonical_alert_id": representative["alert_id"],
                    "duplicate_alert_id": duplicate["alert_id"],
                    "equivalence_group_id": group_id,
                    "reason": "EXACT_SOURCE_LINEAGE_DUPLICATE",
                }
            )
    return canonical, merged


def filter_static_alerts_v2(
    chains_doc: dict[str, Any],
    sinks_doc: dict[str, Any],
    sources_doc: dict[str, Any],
) -> dict[str, Any]:
    chains_before = copy.deepcopy(chains_doc)
    sink_rows = {
        str(row.get("id", "")): row
        for row in list(sinks_doc.get("sink_startpoints", []) or [])
        if str(row.get("id", ""))
    }
    source_rows = {
        str(row.get("id", "")): row
        for row in list(sources_doc.get("source_sites", []) or [])
        if str(row.get("id", ""))
    }
    candidates: list[dict[str, Any]] = []
    non_alerts: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    for chain in list(chains_doc.get("chains", []) or []):
        alert_id = str(chain.get("chain_id", ""))
        sink = sink_rows.get(str(chain.get("sink_id", "")))
        if not alert_id or sink is None:
            contradictions.append(
                {"alert_id": alert_id, "reason": "ALERT_ENDPOINT_NOT_BOUND_TO_SINK_ARTIFACT"}
            )
            continue
        if str(chain.get("status", "")) not in SOURCE_REACHED_STATUSES:
            non_alerts.append({"chain_id": alert_id, "reason": "SOURCE_NOT_REACHED"})
            continue
        candidate = _candidate(chain, sink, source_rows)
        if not candidate["source_lineages"]:
            contradictions.append(
                {"alert_id": alert_id, "reason": "SOURCE_LINEAGE_MISSING"}
            )
            continue
        candidates.append(candidate)

    canonical, merged = _exact_lineage_dedup(candidates)
    rankable = list(canonical)
    rankable.sort(key=_rank_key)
    canonical_alerts: list[dict[str, Any]] = []
    for rank, row in enumerate(rankable, start=1):
        output = dict(row)
        output["rank"] = rank
        output["rank_vector"] = list(_rank_key(row)[:-1])
        canonical_alerts.append(output)

    if chains_doc != chains_before:
        raise AssertionError("A2 Filter modified the input Static Alerts")

    return {
        "schema_version": "ct-mini-alert-filter-a2-v4",
        "policy": {
            "name": "COPPERTRACE_A2",
            "deduplication": "exact_source_lineage_sink_boundary_and_effect",
            "ranking": "lexicographic_evidence_vector",
            "ranking_primary_signal": "source_reached_scalar_vulnerable_parameter",
            "ranking_is_reference_only": True,
            "pre_review_top_k": False,
            "all_canonical_alerts_review_eligible": True,
            "checks_used": False,
            "recognition_confidence_used_for_ranking": False,
            "channelgraph_presence_penalized": False,
            "public_profiles_used": False,
            "input_alerts_modified": False,
        },
        "counts": {
            "input_chains": len(list(chains_doc.get("chains", []) or [])),
            "input_static_alerts": len(candidates),
            "non_alert_chains": len(non_alerts),
            "canonical_alerts": len(canonical),
            "rankable_alerts": len(rankable),
            "exact_lineage_duplicates": len(merged),
            "dropped_invalid": 0,
            "artifact_contradictions": len(contradictions),
        },
        "canonical_alerts": canonical_alerts,
        "merged_duplicates": merged,
        "dropped_invalid": [],
        "non_alert_chains": non_alerts,
        "artifact_contradictions": contradictions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chains", required=True, type=Path)
    parser.add_argument("--sinks", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    result = filter_static_alerts_v2(
        load_json(args.chains),
        load_json(args.sinks),
        load_json(args.sources),
    )
    result["inputs"] = {
        "chains_sha256": sha256_file(args.chains),
        "sinks_sha256": sha256_file(args.sinks),
        "sources_sha256": sha256_file(args.sources),
    }
    write_json(args.out, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
