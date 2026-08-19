#!/usr/bin/env python3
"""Run CopperTrace A2 Alert filtering over frozen Mini artifacts."""

from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any

from filter_static_alerts import load_json, write_json
from filter_static_alerts_v2 import filter_static_alerts_v2
from run_mango_filter_corpus import (
    _public_alert_rank,
    _public_reproduction_ids,
    _represented_ids,
)


def _render_pipeline(
    input_summary: dict[str, Any],
    totals: dict[str, int],
) -> str:
    pipeline = dict(input_summary.get("pipeline_totals", {}) or {})
    public_sources = dict(input_summary.get("public_sources", {}) or {})
    public_sinks = dict(input_summary.get("public_sinks", {}) or {})
    public_chains = dict(input_summary.get("public_chain_status", {}) or {})
    source_hits = sum(
        int(value or 0)
        for key, value in public_sources.items()
        if str(key) != "MISS"
    )
    source_expected = sum(int(value or 0) for value in public_sources.values())
    sink_hits = sum(
        int(value or 0)
        for key, value in public_sinks.items()
        if str(key) != "MISS"
    )
    sink_expected = sum(int(value or 0) for value in public_sinks.values())
    source_reached = sum(
        int(value or 0)
        for key, value in public_chains.items()
        if str(key).startswith("SOURCE_REACHED")
    )
    internal_only = int(public_chains.get("PROVEN_INTERNAL_ONLY", 0) or 0)
    samples_ok = int(input_summary.get("samples_ok", 0) or 0)
    samples_requested = int(input_summary.get("samples_requested", 0) or 0)
    reproduced = int(totals["public_cves_reproduced_before_filter"])
    return "\n".join(
        [
            f"ELF ({samples_ok}/{samples_requested} CVE samples)",
            "  -> Ghidra Decompiled C + High P-code ProgramFacts v5",
            (
                "  -> Source Miner "
                f"[sites={int(pipeline.get('source_sites', 0) or 0)}, "
                f"public hit={source_hits}/{source_expected}]"
            ),
            (
                "  -> Sink Miner "
                f"[startpoints={int(pipeline.get('sink_startpoints', 0) or 0)}, "
                f"public hit={sink_hits}/{sink_expected}]"
            ),
            (
                "  -> shared-object Miner "
                f"[shared-objects={int(pipeline.get('shared_objects', 0) or 0)}]"
            ),
            (
                "  -> Channelgraph "
                f"[relations={int(pipeline.get('channel_edges', 0) or 0)}]"
            ),
            (
                "  -> Unified reverse BFS "
                f"[runs={int(pipeline.get('chain_reverse_bfs_runs', 0) or 0)}, "
                f"candidate traces={int(pipeline.get('chain_candidate_traces', 0) or 0)}]"
            ),
            (
                "  -> RDA "
                f"[parameter runs={int(pipeline.get('chain_parameter_rda_runs', 0) or 0)}, "
                f"public endpoints Source-reached={source_reached}, "
                f"internal-only={internal_only}]"
            ),
            f"  -> Source-backed Static Alerts [total={totals['input_static_alerts']}]",
            f"  -> Static CVE Reproduction [{reproduced}/{samples_requested}]",
            (
                "  -> A2 Source-lineage Filter "
                f"[input={totals['input_static_alerts']}, "
                f"canonical={totals['canonical_alerts']}, "
                f"exact duplicates={totals['exact_lineage_duplicates']}]"
            ),
            (
                "  -> Public-CVE Filter Audit "
                f"[dedup={totals['public_cves_preserved_after_dedup']}/"
                f"{reproduced}, review-eligible="
                f"{totals['public_cves_review_eligible']}/{reproduced}]"
            ),
        ]
    )


def _render_summary(summary: dict[str, Any]) -> str:
    rows = [
        "# CopperTrace A2 Alert Filter",
        "",
        "```text",
        str(summary.get("pipeline", "")),
        "```",
        "",
        "| CVE | Sample | A2 Reference Rank | Review Eligible |",
        "|---|---|---:|---|",
    ]
    for sample in list(summary.get("samples", []) or []):
        if not bool(sample.get("public_cve_reproduced_before_filter", False)):
            continue
        rows.append(
            "| {cve} | `{sample}` | {a2} | {retained} |".format(
                cve=str(sample.get("cve", "")),
                sample=str(sample.get("sample_id", "")),
                a2=sample.get("public_alert_rank") or "-",
                retained=(
                    "yes"
                    if bool(sample.get("public_cve_review_eligible", False))
                    else "no"
                ),
            )
        )
    rows.extend(
        [
            "",
            "A2 ranking did not use CVE identities or public profiles. Public profiles were read only after filtering to audit retention.",
            "",
        ]
    )
    return "\n".join(rows)


def run_corpus(
    manifest: dict[str, Any],
    input_summary: dict[str, Any],
    input_root: Path,
    output_root: Path,
    static_root: Path | None = None,
) -> dict[str, Any]:
    sample_results: list[dict[str, Any]] = []
    totals = {
        "samples": 0,
        "input_chains": 0,
        "input_static_alerts": 0,
        "canonical_alerts": 0,
        "exact_lineage_duplicates": 0,
        "dropped_invalid": 0,
        "artifact_contradictions": 0,
        "public_cves_reproduced_before_filter": 0,
        "public_cves_preserved_after_dedup": 0,
        "public_cves_review_eligible": 0,
    }

    for sample in list(manifest.get("samples", []) or []):
        sample_id = str(sample.get("sample_id", ""))
        if not sample_id:
            continue
        started = time.monotonic()
        sample_in = input_root / sample_id
        sample_static = (static_root or input_root) / sample_id
        paths = {
            "chains": sample_in / "chains.json",
            "sinks": sample_static / "sinks.json",
            "sources": sample_static / "sources.json",
        }
        missing = [str(path) for path in paths.values() if not path.is_file()]
        if missing:
            sample_results.append(
                {
                    "sample_id": sample_id,
                    "cve": str(sample.get("cve", "")),
                    "status": "INPUT_MISSING",
                    "missing": missing,
                }
            )
            continue

        chains_doc = load_json(paths["chains"])
        result = filter_static_alerts_v2(
            chains_doc,
            load_json(paths["sinks"]),
            load_json(paths["sources"]),
        )
        write_json(
            output_root / "per_sample" / sample_id / "alert_filter.json", result
        )

        public_match_path = sample_in / "public_match.json"
        public_ids = (
            _public_reproduction_ids(chains_doc, load_json(public_match_path))
            if public_match_path.is_file()
            else set()
        )
        canonical_ids = _represented_ids(
            list(result.get("canonical_alerts", []) or [])
        )
        reproduced_before = bool(public_ids)
        preserved_after_dedup = bool(public_ids & canonical_ids)
        review_eligible = bool(public_ids & canonical_ids)
        row = {
            "sample_id": sample_id,
            "cve": str(sample.get("cve", "")),
            "status": "OK",
            **result["counts"],
            "public_reproduction_alert_ids": sorted(public_ids),
            "public_cve_reproduced_before_filter": reproduced_before,
            "public_cve_preserved_after_dedup": preserved_after_dedup,
            "public_cve_review_eligible": review_eligible,
            "public_alert_rank": _public_alert_rank(result, public_ids),
            "runtime_seconds": round(time.monotonic() - started, 3),
        }
        sample_results.append(row)

        totals["samples"] += 1
        for key in (
            "input_chains",
            "input_static_alerts",
            "canonical_alerts",
            "exact_lineage_duplicates",
            "dropped_invalid",
            "artifact_contradictions",
        ):
            totals[key] += int(result["counts"].get(key, 0) or 0)
        totals["public_cves_reproduced_before_filter"] += int(reproduced_before)
        totals["public_cves_preserved_after_dedup"] += int(
            preserved_after_dedup
        )
        totals["public_cves_review_eligible"] += int(review_eligible)

    summary = {
        "schema_version": "ct-mini-alert-filter-corpus-a2-v4",
        "policy": {
            "name": "COPPERTRACE_A2",
            "pre_review_top_k": False,
            "all_canonical_alerts_review_eligible": True,
            "public_profile_stage": "post_filter_evaluation_only",
            "input_static_artifacts_modified": False,
        },
        "input_root": str(input_root.resolve()),
        "counts": totals,
        "samples": sample_results,
    }
    summary["pipeline"] = _render_pipeline(input_summary, totals)
    write_json(output_root / "summary.json", summary)
    (output_root / "pipeline.txt").write_text(
        str(summary["pipeline"]) + "\n", encoding="utf-8"
    )
    (output_root / "summary.md").write_text(
        _render_summary(summary), encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--input-summary", required=True, type=Path)
    parser.add_argument("--input-root", required=True, type=Path)
    parser.add_argument(
        "--static-root",
        type=Path,
        help=(
            "Optional per-sample root containing frozen sources.json and "
            "sinks.json when the input root only contains recomputed chains."
        ),
    )
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    run_corpus(
        load_json(args.manifest),
        load_json(args.input_summary),
        args.input_root,
        args.out,
        args.static_root,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
