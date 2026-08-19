#!/usr/bin/env python3
"""Merge completed run_mini_pipeline shards by manifest sample identity."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def aggregate_sample(counter: Counter[str], row: dict[str, Any]) -> None:
    counts = dict(row.get("counts", {}) or {})
    sources = dict(counts.get("sources", {}) or {})
    sinks = dict(counts.get("sinks", {}) or {})
    graph = dict(counts.get("graph", {}) or {})
    chains = dict(counts.get("chains", {}) or {})
    counter["source_sites"] += int(sources.get("source_sites", 0) or 0)
    counter["sink_startpoints"] += int(sinks.get("sink_startpoints", 0) or 0)
    counter["shared_objects"] += int(graph.get("shared_objects", 0) or 0)
    counter["channel_edges"] += int(graph.get("channel_edges", 0) or 0)
    counter["unified_nodes"] += int(graph.get("unified_nodes", 0) or 0)
    counter["unified_edges"] += int(graph.get("unified_edges", 0) or 0)
    counter["resolved_indirect_call_edges"] += int(
        graph.get("resolved_indirect_call_edges", 0) or 0
    )
    counter["chains"] += int(chains.get("chains", 0) or 0)
    counter["channel_assisted_chains"] += int(
        chains.get("channel_assisted_chains", 0) or 0
    )
    for key in (
        "deterministic_sink_calls",
        "heuristic_sink_calls",
        "heuristic_audit_candidates",
        "primitive_calls_observed",
    ):
        counter[f"sink_{key}"] += int(sinks.get(key, 0) or 0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    manifest = read_json(args.manifest)
    expected = [str(row.get("sample_id", "")) for row in manifest.get("samples", [])]
    expected = [sample_id for sample_id in expected if sample_id]
    found: dict[str, list[tuple[Path, dict[str, Any]]]] = {}
    for root in args.root:
        for path in sorted((root / "per_sample").glob("*/public_match.json")):
            row = read_json(path)
            sample_id = str(row.get("sample_id", ""))
            if sample_id and str(row.get("status", "")) == "OK":
                found.setdefault(sample_id, []).append((path, row))

    missing = sorted(set(expected) - set(found))
    unexpected = sorted(set(found) - set(expected))
    duplicate_conflicts: list[dict[str, Any]] = []
    selected: list[dict[str, Any]] = []
    totals: Counter[str] = Counter()
    binary_hashes: set[str] = set()
    for sample_id in expected:
        candidates = found.get(sample_id, [])
        if not candidates:
            continue
        path, row = candidates[0]
        fingerprints = {
            (
                str(item.get("provenance", {}).get("binary_sha256", "")),
                json.dumps(item.get("counts", {}), sort_keys=True),
            )
            for _, item in candidates
        }
        if len(fingerprints) != 1:
            duplicate_conflicts.append(
                {
                    "sample_id": sample_id,
                    "artifacts": [str(item_path) for item_path, _ in candidates],
                }
            )
        copied = dict(row)
        copied["artifact_path"] = str(path)
        selected.append(copied)
        aggregate_sample(totals, copied)
        binary_hash = str(copied.get("provenance", {}).get("binary_sha256", ""))
        if binary_hash:
            binary_hashes.add(binary_hash)

    result = {
        "schema_version": "ct-mini-sharded-pipeline-eval-v1",
        "manifest": str(args.manifest),
        "roots": [str(root) for root in args.root],
        "samples_requested": len(expected),
        "samples_ok": len(selected),
        "samples_failed": len(missing),
        "unique_binaries_ok": len(binary_hashes),
        "samples_expected": len(expected),
        "samples_completed": len(selected),
        "unique_binaries_completed": len(binary_hashes),
        "missing_samples": missing,
        "unexpected_samples": unexpected,
        "duplicate_complete_samples": sorted(
            sample_id for sample_id, rows in found.items() if len(rows) > 1
        ),
        "duplicate_conflicts": duplicate_conflicts,
        "pipeline_totals": dict(sorted(totals.items())),
        "samples": selected,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in (
        "samples_expected",
        "samples_completed",
        "unique_binaries_completed",
        "missing_samples",
        "unexpected_samples",
        "duplicate_complete_samples",
        "duplicate_conflicts",
        "pipeline_totals",
    )}, indent=2))
    return 0 if not missing and not unexpected and not duplicate_conflicts else 1


if __name__ == "__main__":
    raise SystemExit(main())
