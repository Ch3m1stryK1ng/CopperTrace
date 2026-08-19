#!/usr/bin/env python3
"""Render one Mini evaluation using the project's fixed block-by-block format."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _count(mapping: dict[str, Any], *keys: str) -> int:
    return sum(int(mapping.get(key, 0) or 0) for key in keys)


def _reproduced_cves(summary: dict[str, Any]) -> tuple[int, int]:
    reproduced = 0
    rows = list(summary.get("samples", []) or [])
    for sample in rows:
        if any(
            str(match.get("status", "")).startswith("SOURCE_REACHED_")
            for match in list(sample.get("public_chain_matches", []) or [])
        ):
            reproduced += 1
    return reproduced, len(rows)


def _sample_count(summary: dict[str, Any], stage: str, key: str) -> int:
    return sum(
        int(
            dict(
                dict(sample.get("counts", {}) or {}).get(stage, {}) or {}
            ).get(key, 0)
            or 0
        )
        for sample in list(summary.get("samples", []) or [])
        if str(sample.get("status", "")) == "OK"
    )


def _sample_chain_status(summary: dict[str, Any], key: str) -> int:
    return sum(
        int(
            dict(
                dict(
                    dict(sample.get("counts", {}) or {}).get("chains", {})
                    or {}
                ).get("status", {})
                or {}
            ).get(key, 0)
            or 0
        )
        for sample in list(summary.get("samples", []) or [])
        if str(sample.get("status", "")) == "OK"
    )


def render(summary: dict[str, Any]) -> str:
    totals = dict(summary.get("pipeline_totals", {}) or {})
    public_sources = dict(summary.get("public_sources", {}) or {})
    public_sinks = dict(summary.get("public_sinks", {}) or {})
    chain_status = dict(summary.get("public_chain_status", {}) or {})
    reproduced, cve_total = _reproduced_cves(summary)
    source_hits = _count(public_sources, "DETERMINISTIC_HIT", "HEURISTIC_HIT")
    sink_hits = _count(public_sinks, "DETERMINISTIC_HIT", "HEURISTIC_HIT")
    source_reached = _count(
        chain_status,
        "SOURCE_REACHED_DETERMINISTIC",
        "SOURCE_REACHED_HEURISTIC",
    )
    samples_ok = int(summary.get("samples_ok", 0) or 0)
    samples_requested = int(summary.get("samples_requested", 0) or 0)
    static_alerts = _sample_chain_status(
        summary, "SOURCE_REACHED_DETERMINISTIC"
    ) + _sample_chain_status(summary, "SOURCE_REACHED_HEURISTIC")
    graph_incomplete = _sample_chain_status(summary, "GRAPH_INCOMPLETE")
    internal_only = _sample_chain_status(summary, "PROVEN_INTERNAL_ONLY")
    source_associations = _sample_count(summary, "graph", "source_associations")
    channel_writes = _sample_count(summary, "graph", "channel_write_edges")
    channel_reads = _sample_count(summary, "graph", "channel_read_edges")
    serialized_witnesses = _sample_count(
        summary, "chains", "serialized_trace_witnesses"
    )
    bfs_label = (
        "Unified BFS"
        if str(summary.get("graph_mode", "unified")) == "unified"
        else "Callgraph-only BFS"
    )
    lines = [
        f"ELF ({samples_ok}/{samples_requested} CVE samples)",
        "  -> Ghidra ProgramFacts",
        (
            "  -> Source Miner "
            f"[total={int(totals.get('source_sites', 0) or 0)}, "
            f"public={source_hits}/{sum(public_sources.values())}]"
        ),
        (
            "  -> Sink Miner "
            f"[startpoints={int(totals.get('sink_startpoints', 0) or 0)}, "
            f"public={sink_hits}/{sum(public_sinks.values())}]"
        ),
        (
            "  -> Source Association "
            f"[associations={source_associations}, "
            f"write candidates={int(totals.get('source_write_candidates', 0) or 0)}]"
        ),
        (
            "  -> shared-object Miner "
            f"[shared-objects={int(totals.get('shared_objects', 0) or 0)}]"
        ),
        (
            "  -> Channelgraph "
            f"[relations={int(totals.get('channel_edges', 0) or 0)}, "
            f"WRITE={channel_writes}, READ={channel_reads}]"
        ),
        (
            f"  -> {bfs_label} "
            f"[runs={int(totals.get('chain_reverse_bfs_runs', 0) or 0)}, "
            f"candidate traces={int(totals.get('chain_candidate_traces', 0) or 0)}, "
            f"serialized witnesses={serialized_witnesses}]"
        ),
        (
            "  -> RDA "
            f"[runs={int(totals.get('chain_parameter_rda_runs', 0) or 0)}, "
            f"public endpoints reached={source_reached}, "
            f"graph incomplete={graph_incomplete}, internal-only={internal_only}]"
        ),
        f"  -> Static Alerts [Source-backed={static_alerts}]",
        f"  -> Static CVE Reproduction [{reproduced}/{cve_total}]",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", type=Path)
    args = parser.parse_args()
    summary = json.loads(args.summary.read_text())
    print(render(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
