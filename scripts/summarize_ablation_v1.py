#!/usr/bin/env python3
"""Summarize the frozen CopperTrace Mini component ablations."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]


GROUND_CONFIGS = {
    "Full": {
        "static": (
            "artifacts/check_review_v4_1_development_static_20260811",
            "artifacts/check_review_v4_1_evaluation_static_20260811",
        ),
        "a2": (
            "artifacts/check_review_v4_1_development_a2_20260811",
            "artifacts/check_review_v4_1_evaluation_a2_20260811",
        ),
    },
    "-S": {
        "static": (
            "artifacts/ablation_v1_gt_minus_s_development_20260818",
            "artifacts/ablation_v1_gt_minus_s_evaluation_20260818",
        ),
        "a2": (
            "artifacts/ablation_v1_gt_minus_s_development_a2_20260818",
            "artifacts/ablation_v1_gt_minus_s_evaluation_a2_20260818",
        ),
    },
    "-K": {
        "static": (
            "artifacts/ablation_v1_gt_minus_k_development_20260818",
            "artifacts/ablation_v1_gt_minus_k_evaluation_20260818",
        ),
        "a2": (
            "artifacts/ablation_v1_gt_minus_k_development_a2_20260818",
            "artifacts/ablation_v1_gt_minus_k_evaluation_a2_20260818",
        ),
    },
    "-S-K": {
        "static": (
            "artifacts/ablation_v1_gt_minus_sk_development_20260818",
            "artifacts/ablation_v1_gt_minus_sk_evaluation_20260818",
        ),
        "a2": (
            "artifacts/ablation_v1_gt_minus_sk_development_a2_20260818",
            "artifacts/ablation_v1_gt_minus_sk_evaluation_a2_20260818",
        ),
    },
    "-G": {
        "static": (
            "artifacts/ablation_v1_gt_minus_g_development_20260818",
            "artifacts/ablation_v1_gt_minus_g_evaluation_20260818",
        ),
        "a2": (
            "artifacts/ablation_v1_gt_minus_g_development_a2_20260818",
            "artifacts/ablation_v1_gt_minus_g_evaluation_a2_20260818",
        ),
    },
    "-F": {
        "static": (
            "artifacts/check_review_v4_1_development_static_20260811",
            "artifacts/check_review_v4_1_evaluation_static_20260811",
        ),
        "a2": (),
    },
}


FRESH_CONFIGS = {
    "Full": {
        "static": ("artifacts/graph_store_round1/fresh_merged",),
        "a2": ("artifacts/ablation_v1_fresh_full_a2_20260818",),
    },
    "-S-K": {
        "static": ("artifacts/ablation_v1_fresh_minus_sk_20260818",),
        "a2": ("artifacts/ablation_v1_fresh_minus_sk_a2_20260818",),
    },
    "-G": {
        "static": ("artifacts/ablation_v1_fresh_minus_g_20260818",),
        "a2": ("artifacts/ablation_v1_fresh_minus_g_a2_20260818",),
    },
    "-F": {
        "static": ("artifacts/graph_store_round1/fresh_merged",),
        "a2": (),
    },
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def roots(values: Iterable[str]) -> list[Path]:
    return [(ROOT / value).resolve() for value in values]


def summaries(config: dict[str, tuple[str, ...]], key: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for root in roots(config.get(key, ())):
        path = root / "summary.json"
        if not path.is_file():
            raise FileNotFoundError(path)
        result.append(read_json(path))
    return result


def unique_samples(
    docs: Iterable[dict[str, Any]], eligible_elfs: set[str] | None = None
) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for doc in docs:
        for sample in list(doc.get("samples", []) or []):
            if sample.get("status") != "OK":
                continue
            digest = str(dict(sample.get("provenance", {}) or {}).get("binary_sha256", ""))
            if eligible_elfs is not None and digest not in eligible_elfs:
                continue
            identity = digest or str(sample.get("sample_id", ""))
            if identity in seen:
                continue
            seen.add(identity)
            result.append(sample)
    return result


def source_reached_count(sample: dict[str, Any]) -> int:
    statuses = dict(
        dict(dict(sample.get("counts", {}) or {}).get("chains", {}) or {}).get(
            "status", {}
        )
        or {}
    )
    return sum(
        int(count)
        for status, count in statuses.items()
        if str(status).startswith("SOURCE_REACHED")
    )


def total_count(samples: Iterable[dict[str, Any]], section: str, key: str) -> int:
    return sum(
        int(
            dict(dict(sample.get("counts", {}) or {}).get(section, {}) or {}).get(
                key, 0
            )
            or 0
        )
        for sample in samples
    )


def static_cve_status(
    docs: Iterable[dict[str, Any]], in_scope: set[str]
) -> dict[str, bool]:
    status = {cve: False for cve in in_scope}
    for doc in docs:
        for sample in list(doc.get("samples", []) or []):
            cve = str(sample.get("cve", ""))
            if cve not in status:
                continue
            status[cve] = status[cve] or any(
                str(row.get("status", "")).startswith("SOURCE_REACHED")
                for row in list(sample.get("public_chain_matches", []) or [])
            )
    return status


def a2_cve_status(
    docs: Iterable[dict[str, Any]], in_scope: set[str]
) -> dict[str, bool]:
    status = {cve: False for cve in in_scope}
    for doc in docs:
        for sample in list(doc.get("samples", []) or []):
            cve = str(sample.get("cve", ""))
            if cve in status:
                status[cve] = status[cve] or bool(
                    sample.get("public_cve_preserved_after_dedup", False)
                )
    return status


def unique_a2_count(
    static_docs: list[dict[str, Any]], a2_roots: list[Path],
    eligible_elfs: set[str] | None = None,
) -> int:
    by_sample: dict[str, Path] = {}
    for root in a2_roots:
        for artifact in (root / "per_sample").glob("*/alert_filter.json"):
            by_sample[artifact.parent.name] = artifact
    total = 0
    for sample in unique_samples(static_docs, eligible_elfs):
        sample_id = str(sample.get("sample_id", ""))
        artifact = by_sample.get(sample_id)
        if artifact is None:
            raise FileNotFoundError(f"missing A2 artifact for {sample_id}")
        total += int(dict(read_json(artifact).get("counts", {}) or {}).get("canonical_alerts", 0) or 0)
    return total


def parse_elapsed_seconds(text: str) -> float | None:
    match = re.search(
        r"^\s*Elapsed \(wall clock\) time .*\):\s*([^\s]+)\s*$",
        text,
        flags=re.MULTILINE,
    )
    if match is None:
        return None
    parts = [float(part) for part in match.group(1).strip().split(":")]
    if len(parts) == 3:
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    if len(parts) == 2:
        return parts[0] * 60 + parts[1]
    return parts[0]


def resource_counts(static_roots: list[Path]) -> tuple[float | None, int | None]:
    elapsed: list[float] = []
    peak: list[int] = []
    for root in static_roots:
        path = root / "resource_usage.txt"
        if not path.is_file():
            return None, None
        text = path.read_text(errors="replace")
        seconds = parse_elapsed_seconds(text)
        if seconds is not None:
            elapsed.append(seconds)
        match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", text)
        if match:
            peak.append(int(match.group(1)))
    return (sum(elapsed) if elapsed else None, max(peak) if peak else None)


def row_for(
    name: str,
    config: dict[str, tuple[str, ...]],
    *,
    in_scope: set[str] | None,
    eligible_elfs: set[str] | None = None,
) -> tuple[dict[str, Any], dict[str, bool]]:
    static_roots = roots(config["static"])
    static_docs = summaries(config, "static")
    samples = unique_samples(static_docs, eligible_elfs)
    raw_alerts = sum(source_reached_count(sample) for sample in samples)
    graph_disabled = name == "-G"
    a2_roots = roots(config.get("a2", ()))
    if a2_roots:
        a2_docs = summaries(config, "a2")
        canonical: int | str = unique_a2_count(
            static_docs, a2_roots, eligible_elfs
        )
    else:
        a2_docs = []
        canonical = "DISABLED"
    elapsed, peak = resource_counts(static_roots)
    cve_status = static_cve_status(static_docs, in_scope or set())
    retained = a2_cve_status(a2_docs, in_scope or set()) if a2_docs else cve_status
    row = {
        "configuration": name,
        "elfs": len(samples),
        "sources": total_count(samples, "sources", "source_sites"),
        "sinks": total_count(samples, "sinks", "sink_startpoints"),
        "shared_objects": 0 if graph_disabled else total_count(samples, "graph", "shared_objects"),
        "channelgraph_relations": 0 if graph_disabled else total_count(samples, "graph", "channel_edges"),
        "candidate_traces": total_count(samples, "chains", "candidate_traces"),
        "raw_static_alerts": raw_alerts,
        "a2_canonical_alerts": canonical,
        "static_cves_refound": sum(cve_status.values()) if in_scope else "N/A",
        "cves_after_a2": sum(retained.values()) if in_scope else "N/A",
        "wall_seconds": round(elapsed, 2) if elapsed is not None else "N/A",
        "peak_rss_kb": peak if peak is not None else "N/A",
    }
    return row, cve_status


def markdown_table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
    lines = [
        "| " + " | ".join(title for _, title in columns) + " |",
        "|" + "|".join("---" for _ in columns) + "|",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(str(row.get(key, "")).replace("|", "\\|") for key, _ in columns)
            + " |"
        )
    return "\n".join(lines)


def pipeline_figure(
    row: dict[str, Any], *, ground_truth: bool, cve_denominator: int = 0
) -> str:
    cves = (
        f"{row['static_cves_refound']}/{cve_denominator} CVEs"
        if ground_truth
        else "CVE metric N/A"
    )
    return "\n".join(
        [
            f"ELF [{row['elfs']}]",
            "  -> Frozen Ghidra Decompiled C + High P-code",
            f"  -> Source Miner [{row['sources']} Sources]",
            f"  -> Sink Miner [{row['sinks']} Sinks]",
            f"  -> shared-object Miner [{row['shared_objects']} active shared-objects]",
            f"  -> Channelgraph [{row['channelgraph_relations']} active relations]",
            f"  -> Reverse BFS/RDA [{row['candidate_traces']} candidate traces]",
            f"  -> Static Alerts [{row['raw_static_alerts']}; {cves}]",
            f"  -> A2 [{row['a2_canonical_alerts']} canonical Alerts]",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "artifacts/ablation_v1_results_20260818",
    )
    parser.add_argument(
        "--markdown",
        type=Path,
        default=ROOT / "docs/ABLATION_STUDY_20260818.md",
    )
    parser.add_argument(
        "--status-overrides",
        type=Path,
        default=None,
        help="Audited per-CVE correctness-rerun results keyed by configuration.",
    )
    args = parser.parse_args()

    scope = read_json(ROOT / "datasets/ground_truth_scope_manifest.json")
    in_scope = {
        str(row.get("cve", ""))
        for row in list(scope.get("cves", []) or [])
        if row.get("scope") == "IN_SCOPE"
        and row.get("sample_validity", "VALID") == "VALID"
    }
    expected = int((scope.get("counts", {}) or {}).get("evaluated_in_scope", 0))
    if len(in_scope) != expected:
        raise RuntimeError(
            f"expected {expected} evaluated In-scope CVEs, got {len(in_scope)}"
        )
    eligible_elfs = {
        str(row.get("elf_sha256", ""))
        for row in list(scope.get("cves", []) or [])
        if str(row.get("cve", "")) in in_scope
    }
    overrides = (
        dict(read_json(args.status_overrides).get("configurations", {}) or {})
        if args.status_overrides
        else {}
    )

    ground_rows: list[dict[str, Any]] = []
    cve_statuses: dict[str, dict[str, bool]] = {}
    for name, config in GROUND_CONFIGS.items():
        row, status = row_for(
            name, config, in_scope=in_scope, eligible_elfs=eligible_elfs
        )
        for cve, decision in dict(overrides.get(name, {}) or {}).items():
            if cve not in status:
                raise RuntimeError(f"{name}: override for non-evaluated CVE {cve}")
            old_static = bool(status[cve])
            new_static = bool(dict(decision).get("static_refound"))
            status[cve] = new_static
            row["static_cves_refound"] += int(new_static) - int(old_static)
            old_a2 = old_static
            new_a2 = bool(dict(decision).get("a2_preserved", new_static))
            row["cves_after_a2"] += int(new_a2) - int(old_a2)
        ground_rows.append(row)
        cve_statuses[name] = status

    fresh_rows: list[dict[str, Any]] = []
    for name, config in FRESH_CONFIGS.items():
        row, _status = row_for(name, config, in_scope=None)
        fresh_rows.append(row)

    full_status = cve_statuses["Full"]
    per_cve = [
        {
            "cve": cve,
            "full": "FOUND" if full_status[cve] else "MISS",
            "minus_s": "FOUND" if cve_statuses["-S"][cve] else "MISS",
            "minus_k": "FOUND" if cve_statuses["-K"][cve] else "MISS",
            "minus_sk": "FOUND" if cve_statuses["-S-K"][cve] else "MISS",
            "minus_g": "FOUND" if cve_statuses["-G"][cve] else "MISS",
        }
        for cve in sorted(in_scope)
    ]

    full = next(row for row in ground_rows if row["configuration"] == "Full")
    module_rows = []
    for capability, variant in (
        ("Source + Sink Mining", "-S-K"),
        ("Recovery of CCC", "-G"),
        ("A2 Filter", "-F"),
    ):
        row = next(item for item in ground_rows if item["configuration"] == variant)
        module_rows.append(
            {
                "capability": capability,
                "full_cves": full["static_cves_refound"],
                "without_cves": row["static_cves_refound"],
                "cve_delta": int(row["static_cves_refound"]) - int(full["static_cves_refound"]),
                "full_alerts": full["a2_canonical_alerts"],
                "without_alerts": (
                    row["raw_static_alerts"]
                    if variant == "-F"
                    else row["a2_canonical_alerts"]
                ),
            }
        )

    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "ground_truth.json").write_text(json.dumps(ground_rows, indent=2) + "\n")
    (args.out / "fresh.json").write_text(json.dumps(fresh_rows, indent=2) + "\n")
    (args.out / "per_cve.json").write_text(json.dumps(per_cve, indent=2) + "\n")
    (args.out / "paper_modules.json").write_text(json.dumps(module_rows, indent=2) + "\n")

    columns = [
        ("configuration", "Configuration"),
        ("elfs", "ELFs"),
        ("sources", "Sources"),
        ("sinks", "Sinks"),
        ("shared_objects", "shared-objects"),
        ("channelgraph_relations", "Channelgraph"),
        ("candidate_traces", "Candidate Traces"),
        ("raw_static_alerts", "Raw Alerts"),
        ("a2_canonical_alerts", "A2 Canonical"),
        ("static_cves_refound", "CVEs Refound"),
        ("cves_after_a2", "CVEs After A2"),
        ("wall_seconds", "Wall Seconds"),
        ("peak_rss_kb", "Peak RSS KB"),
    ]
    fresh_columns = [column for column in columns if column[0] not in {"static_cves_refound", "cves_after_a2"}]
    lines = [
        "# CopperTrace Mini Ablation Study",
        "",
        f"## Ground-Truth Set: {expected} Evaluated In-Scope CVEs / {len(eligible_elfs)} ELFs",
        "",
        markdown_table(ground_rows, columns),
        "",
        "## Fresh Set: 100 ELFs",
        "",
        markdown_table(fresh_rows, fresh_columns),
        "",
        "## Paper Modules",
        "",
        markdown_table(
            module_rows,
            [
                ("capability", "Capability"),
                ("full_cves", "Full CVEs"),
                ("without_cves", "Without Component"),
                ("cve_delta", "Delta"),
                ("full_alerts", "Full Alerts"),
                ("without_alerts", "Without Component Alerts"),
            ],
        ),
        "",
        "## Block-Level Runs",
        "",
    ]
    for row in ground_rows:
        lines.extend([f"### Ground Truth {row['configuration']}", "", "```text", pipeline_figure(row, ground_truth=True, cve_denominator=expected), "```", ""])
    for row in fresh_rows:
        lines.extend([f"### Fresh {row['configuration']}", "", "```text", pipeline_figure(row, ground_truth=False), "```", ""])
    lines.extend(
        [
            "## Per-CVE Appendix",
            "",
            markdown_table(
                per_cve,
                [
                    ("cve", "CVE"),
                    ("full", "Full"),
                    ("minus_s", "-S"),
                    ("minus_k", "-K"),
                    ("minus_sk", "-S-K"),
                    ("minus_g", "-G"),
                ],
            ),
            "",
            "`-G` reports active shared-object/Channelgraph counts as zero; the frozen mined artifact is reused but excluded from BFS/RDA.",
            "Runtime is the sum of independently measured execution shards; peak RSS is the maximum shard value. Full and -F retain N/A runtime because the frozen run used a different measurement setup.",
            "",
        ]
    )
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.write_text("\n".join(lines))
    print(json.dumps({"ground_truth": ground_rows, "fresh": fresh_rows}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
