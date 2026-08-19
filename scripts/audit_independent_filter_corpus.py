#!/usr/bin/env python3
"""Summarize a frozen A2 run without using vulnerability ground truth."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def nested_count(summary: dict[str, Any], key: str) -> int:
    return int(dict(summary.get("pipeline_totals", {}) or {}).get(key, 0) or 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--pipeline-summary", required=True, type=Path)
    parser.add_argument("--a1-summary", required=True, type=Path)
    parser.add_argument("--a2-summary", required=True, type=Path)
    parser.add_argument("--a2-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--pipeline-out", required=True, type=Path)
    args = parser.parse_args()

    manifest = read_json(args.manifest)
    pipeline = read_json(args.pipeline_summary)
    a1 = read_json(args.a1_summary)
    a2 = read_json(args.a2_summary)

    sink_labels: Counter[str] = Counter()
    check_statuses: Counter[str] = Counter()
    source_decisions: Counter[str] = Counter()
    path_precision: Counter[str] = Counter()
    canonical_channelgraph = 0
    canonical_scalar_roles = 0
    canonical_rows = 0
    source_labels: Counter[str] = Counter()
    source_decisions_all: Counter[str] = Counter()
    source_detection_kinds: Counter[str] = Counter()
    all_sink_labels: Counter[str] = Counter()
    chain_statuses: Counter[str] = Counter()
    parameter_statuses: Counter[str] = Counter()
    first_missing_relations: Counter[str] = Counter()
    analysis_blockers: Counter[str] = Counter()
    samples_with_sources = 0
    per_sample: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    pipeline_root = args.pipeline_summary.parent / "per_sample"

    for sample in list(manifest.get("samples", []) or []):
        sample_id = str(sample.get("sample_id", ""))
        pipeline_sample = pipeline_root / sample_id
        sources_path = pipeline_sample / "sources.json"
        sinks_path = pipeline_sample / "sinks.json"
        chains_path = pipeline_sample / "chains.json"
        source_count = 0
        sink_count = 0
        chain_count = 0
        if sources_path.is_file() and sinks_path.is_file() and chains_path.is_file():
            sources_doc = read_json(sources_path)
            sinks_doc = read_json(sinks_path)
            chains_doc = read_json(chains_path)
            source_sites = list(sources_doc.get("source_sites", []) or [])
            sink_sites = list(sinks_doc.get("sink_startpoints", []) or [])
            chains = list(chains_doc.get("chains", []) or [])
            source_count = len(source_sites)
            sink_count = len(sink_sites)
            chain_count = len(chains)
            samples_with_sources += int(bool(source_sites))
            for row in source_sites:
                source_labels[str(row.get("label", "UNKNOWN"))] += 1
                source_decisions_all[str(row.get("decision", "UNKNOWN"))] += 1
                source_detection_kinds[str(row.get("detection_kind", "UNKNOWN"))] += 1
            for row in sink_sites:
                all_sink_labels[str(row.get("label", "UNKNOWN"))] += 1
            for chain in chains:
                chain_statuses[str(chain.get("status", "UNKNOWN"))] += 1
                for parameter in list(chain.get("parameter_results", []) or []):
                    parameter_statuses[str(parameter.get("status", "UNKNOWN"))] += 1
                    for blocker in list(parameter.get("blockers", []) or []):
                        analysis_blockers[str(blocker)] += 1
                    missing = dict(parameter.get("first_missing_relation", {}) or {})
                    first_missing_relations[str(missing.get("relation", "NONE"))] += 1
        artifact_path = args.a2_root / "per_sample" / sample_id / "alert_filter.json"
        if not artifact_path.exists():
            per_sample.append({"sample_id": sample_id, "status": "MISSING_A2_ARTIFACT"})
            continue
        artifact = read_json(artifact_path)
        canonical = list(artifact.get("canonical_alerts", []) or [])
        counts = dict(artifact.get("counts", {}) or {})
        canonical_rows += len(canonical)
        sample_channel = 0
        for row in canonical:
            sink_labels[str(row.get("sink_label", "UNKNOWN"))] += 1
            check = str(dict(row.get("check_evidence", {}) or {}).get("status", "UNKNOWN"))
            check_statuses[check] += 1
            evidence = dict(row.get("evidence", {}) or {})
            if bool(evidence.get("uses_channelgraph")):
                canonical_channelgraph += 1
                sample_channel += 1
            roles = {str(role) for role in list(row.get("vulnerable_parameter_roles", []) or [])}
            if roles & {"len", "length", "size", "count", "amount", "index", "offset", "bound"}:
                canonical_scalar_roles += 1
            for lineage in list(row.get("source_lineages", []) or []):
                source_decisions[str(lineage.get("source_decision", "UNKNOWN"))] += 1
                path_precision[str(lineage.get("path_precision", "UNKNOWN"))] += 1
        for row in canonical[:2]:
            audit_rows.append(
                {
                    "sample_id": sample_id,
                    "rank": row.get("rank"),
                    "alert_id": row.get("alert_id"),
                    "sink_id": row.get("sink_id"),
                    "sink_label": row.get("sink_label"),
                    "vulnerable_parameter_roles": row.get("vulnerable_parameter_roles", []),
                    "check_status": dict(row.get("check_evidence", {}) or {}).get("status"),
                    "source_lineage_fingerprints": row.get("source_lineage_fingerprints", []),
                    "uses_channelgraph": bool(
                        dict(row.get("evidence", {}) or {}).get("uses_channelgraph")
                    ),
                }
            )
        per_sample.append(
            {
                "sample_id": sample_id,
                "status": "OK",
                "source_sites": source_count,
                "sink_startpoints": sink_count,
                "chains": chain_count,
                "input_static_alerts": int(counts.get("input_static_alerts", 0)),
                "canonical_alerts": int(counts.get("canonical_alerts", 0)),
                "review_eligible": len(canonical),
                "dropped_invalid": int(counts.get("dropped_invalid", 0)),
                "exact_lineage_duplicates": int(counts.get("exact_lineage_duplicates", 0)),
                "parameter_bounded": int(counts.get("parameter_bounded", 0)),
                "capacity_safe": int(counts.get("capacity_safe", 0)),
                "canonical_using_channelgraph": sample_channel,
            }
        )

    counts = dict(a2.get("counts", {}) or {})
    report = {
        "schema_version": "ct-mini-independent-filter-audit-v3-canonical",
        "scope": {
            "samples": len(list(manifest.get("samples", []) or [])),
            "public_vulnerability_profiles_used": False,
            "semantic_precision_claimed": False,
            "purpose": "structural_generalization_and_candidate_density_audit",
        },
        "pipeline": {
            "samples_ok": int(pipeline.get("samples_ok", 0)),
            "samples_failed": int(pipeline.get("samples_failed", 0)),
            "source_count": nested_count(pipeline, "source_sites"),
            "sink_startpoints": nested_count(pipeline, "sink_startpoints"),
            "shared_objects": nested_count(pipeline, "shared_objects"),
            "channel_relations": nested_count(pipeline, "channel_edges"),
            "chain_runs": nested_count(pipeline, "chain_reverse_bfs_runs"),
        },
        "static_analysis_evidence": {
            "samples_with_source_sites": samples_with_sources,
            "samples_without_source_sites": len(list(manifest.get("samples", []) or []))
            - samples_with_sources,
            "source_labels": dict(sorted(source_labels.items())),
            "source_decisions": dict(sorted(source_decisions_all.items())),
            "source_detection_kinds": dict(sorted(source_detection_kinds.items())),
            "sink_labels": dict(sorted(all_sink_labels.items())),
            "chain_statuses": dict(sorted(chain_statuses.items())),
            "parameter_statuses": dict(sorted(parameter_statuses.items())),
            "first_missing_relations": dict(sorted(first_missing_relations.items())),
            "analysis_blockers": dict(analysis_blockers.most_common()),
        },
        "filter": {
            "source_backed_static_alerts": int(counts.get("input_static_alerts", 0)),
            "a1_canonical_alerts": int(dict(a1.get("counts", {}) or {}).get("canonical_alerts", 0)),
            "a2_canonical_alerts": int(counts.get("canonical_alerts", 0)),
            "a2_exact_lineage_duplicates": int(counts.get("exact_lineage_duplicates", 0)),
            "a2_review_eligible": int(
                counts.get("canonical_alerts", canonical_rows)
            ),
            "parameter_bounded": int(counts.get("parameter_bounded", 0)),
            "capacity_safe": int(counts.get("capacity_safe", 0)),
            "dropped_invalid": int(counts.get("dropped_invalid", 0)),
            "observed_not_bound": int(counts.get("observed_not_bound", 0)),
            "check_unknown": int(counts.get("check_unknown", 0)),
        },
        "canonical_evidence": {
            "sink_labels": dict(sorted(sink_labels.items())),
            "check_statuses": dict(sorted(check_statuses.items())),
            "source_decisions": dict(sorted(source_decisions.items())),
            "path_precision": dict(sorted(path_precision.items())),
            "using_channelgraph": canonical_channelgraph,
            "with_scalar_vulnerable_parameter": canonical_scalar_roles,
        },
        "invariants": {
            "all_ready_samples_have_a2_artifact": all(
                row.get("status") == "OK" for row in per_sample
            ),
            "every_canonical_alert_is_review_eligible": all(
                int(row.get("review_eligible", 0))
                == int(row.get("canonical_alerts", 0))
                for row in per_sample
                if row.get("status") == "OK"
            ),
        },
        "per_sample": per_sample,
        "audit_sample": audit_rows,
    }
    write_json(args.out, report)

    p = report["pipeline"]
    f = report["filter"]
    e = report["static_analysis_evidence"]
    lines = [
        f"ELF ({report['scope']['samples']} independent samples)",
        "  -> Ghidra Decompiled C + High P-code",
        f"  -> Source Miner [total={p['source_count']}]",
        f"  -> Sink Miner [startpoints={p['sink_startpoints']}]",
        f"  -> shared-object Miner [shared-objects={p['shared_objects']}]",
        f"  -> Channelgraph [relations={p['channel_relations']}]",
        f"  -> Unified BFS + RDA [runs={p['chain_runs']}]",
        "     "
        + "["
        + ", ".join(f"{key}={value}" for key, value in e["chain_statuses"].items())
        + "]",
        f"  -> Source-backed Static Alerts [total={f['source_backed_static_alerts']}]",
        f"  -> A2 exact-lineage dedup [canonical={f['a2_canonical_alerts']}, duplicates={f['a2_exact_lineage_duplicates']}]",
        f"  -> Review-eligible canonical Alerts [all={f['a2_review_eligible']}, dropped-invalid={f['dropped_invalid']}]",
        "  -> Independent structural audit [no public CVE oracle, no semantic precision claim]",
    ]
    args.pipeline_out.parent.mkdir(parents=True, exist_ok=True)
    args.pipeline_out.write_text("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0 if all(report["invariants"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
