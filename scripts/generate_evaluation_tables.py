#!/usr/bin/env python3
"""Generate the authoritative evaluation report for the frozen supported scope."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULT_ROOT = ROOT / "artifacts" / "evaluation_scope42_20260818"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def corpus_name(value: str) -> str:
    return "evaluation" if value.startswith("evaluation") else "development"


def percent(part: int, whole: int) -> str:
    return f"{100.0 * part / whole:.1f}%" if whole else "N/A"


def aggregate_static(summary_path: Path, eligible_hashes: set[str]) -> dict[str, int]:
    summary = read_json(summary_path)
    seen: set[str] = set()
    totals: defaultdict[str, int] = defaultdict(int)
    for sample in summary["samples"]:
        digest = str(sample["provenance"]["binary_sha256"])
        if digest not in eligible_hashes or digest in seen:
            continue
        seen.add(digest)
        counts = sample["counts"]
        totals["sources"] += int(counts["sources"]["source_sites"])
        totals["sinks"] += int(counts["sinks"]["sink_startpoints"])
        totals["shared_objects"] += int(counts["graph"]["shared_objects"])
        totals["channelgraph_relations"] += int(counts["graph"]["channel_edges"])
        totals["candidate_traces"] += int(counts["chains"]["candidate_traces"])
        totals["static_alerts"] += sum(
            int(count)
            for status, count in counts["chains"]["status"].items()
            if str(status).startswith("SOURCE_REACHED")
        )
    totals["elfs"] = len(seen)
    return dict(totals)


def aggregate_review(
    corpus: str,
    eligible_hashes: set[str],
    cve_views: dict[str, Any],
    live_summary: dict[str, Any],
) -> tuple[dict[str, int], set[str]]:
    review_ids = {
        str(row["review_sample_id"])
        for row in cve_views["cve_views"]
        if row["corpus"] == corpus and str(row["binary_sha256"]) in eligible_hashes
    }
    by_id = {str(row["sample_id"]): row for row in live_summary["samples"]}
    fields = (
        "a2_canonical",
        "alerts_with_checks",
        "check_candidates",
        "trupocs",
        "rejected",
        "unresolved",
    )
    totals = {
        field: sum(int(by_id[review_id].get(field, 0) or 0) for review_id in review_ids)
        for field in fields
    }
    totals["elfs"] = len(review_ids)
    return totals, review_ids


def aggregate_llm_runs(corpus: str, review_ids: set[str]) -> dict[str, int]:
    summary = read_json(ROOT / f"artifacts/llm_only_{corpus}_20260816/summary.json")
    rows = [row for row in summary["samples"] if str(row["firmware_id"]) in review_ids]
    return {
        "elfs": len(rows),
        "completed": sum(row["status"] == "COMPLETED" for row in rows),
        "reports": sum(int(row.get("reports", 0) or 0) for row in rows),
    }


def sum_dicts(*rows: dict[str, int]) -> dict[str, int]:
    keys = set().union(*(row.keys() for row in rows))
    return {key: sum(int(row.get(key, 0)) for row in rows) for key in keys}


def mini_miss_reasons(
    score: dict[str, Any], static_samples: dict[str, dict[str, Any]]
) -> Counter[str]:
    reasons: Counter[str] = Counter()
    for row in score["cves"]:
        if row["review_status"] != "NOT_STATICALLY_REFOUND":
            continue
        sample = static_samples[str(row["sample_id"])]
        statuses = {
            str(match.get("status", "")) for match in sample.get("public_chain_matches", [])
        }
        if statuses and statuses <= {"SINK_MISS"}:
            reasons["Sink not recognized"] += 1
        elif "PROVEN_INTERNAL_ONLY" in statuses:
            reasons["Source not modeled / internal origin"] += 1
        else:
            reasons["Data-flow not recovered"] += 1
    return reasons


def mango_totals(mango: dict[str, Any]) -> tuple[dict[str, int], Counter[str]]:
    totals: defaultdict[str, int] = defaultdict(int)
    reasons: Counter[str] = Counter()
    reason_names = {
        "SINK_NOT_RECOGNIZED": "Sink not recognized",
        "SOURCE_NOT_MODELED": "Source not modeled",
        "DATA_FLOW_INCOMPLETE": "Data-flow not recovered",
        "ANALYSIS_FAILED": "Analysis failed",
        "DIAGNOSTIC_REQUIRED": "Analysis failed",
    }
    for corpus in ("development", "evaluation"):
        data = mango["datasets"][corpus]
        for key, value in data["totals"].items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                totals[key] += int(value)
        for key, value in data["failure_reasons"].items():
            reasons[reason_names[key]] += int(value)
    return dict(totals), reasons


def llm_miss_reasons(
    llm_score: dict[str, Any], llm_samples: dict[str, dict[str, Any]]
) -> Counter[str]:
    reasons: Counter[str] = Counter()
    for row in llm_score["cves"]:
        if row["refound"]:
            continue
        reports = int(llm_samples[str(row["firmware_id"])].get("reports", 0) or 0)
        reasons["Sink not recognized" if reports else "Analysis failed"] += 1
    return reasons


def markdown_table(headers: list[str], rows: list[list[Any]], align: str = "---") -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join(align for _ in headers) + "|",
    ]
    lines.extend("| " + " | ".join(str(value) for value in row) + " |" for row in rows)
    return "\n".join(lines)


def build_report(summary: dict[str, Any]) -> str:
    gt = summary["with_ground_truth"]
    fresh = summary["without_ground_truth"]
    adjudication = gt["manual_adjudication"]
    lines = [
        "# CopperTrace Mini Evaluation Tables",
        "",
        "This report uses one frozen counting rule: only the 42 evaluated CVEs whose",
        "public Sink forms are supported by the current Pipeline are included. Scope",
        "decisions remain auditable in `datasets/ground_truth_scope_manifest.json`.",
        "",
        "## Datasets",
        "",
        markdown_table(
            ["Dataset", "Size", "Projects", "Origin", "Purpose"],
            [
                [
                    "With Ground Truth",
                    f"{gt['cves']} CVEs / {gt['elfs']} ELFs",
                    "Zephyr, Contiki/Contiki-NG, RIOT, Mbed OS, NuttX",
                    "Public advisories + affected-version builds",
                    "CVE reproduction",
                ],
                [
                    "Without Ground Truth",
                    f"{fresh['elfs']} ELFs",
                    "Contiki-NG, Mbed CE, NuttX, RIOT, Zephyr",
                    "Official releases + maintained repositories",
                    "New-vulnerability discovery",
                ],
            ],
        ),
        "",
        "### With Ground Truth Split",
        "",
        markdown_table(
            ["Set", "CVEs", "Unique ELFs", "Use"],
            [
                ["Development", gt["development"]["cves"], gt["development"]["elfs"], "Rule development and regression"],
                ["Evaluation", gt["evaluation"]["cves"], gt["evaluation"]["elfs"], "Post-freeze evaluation"],
                ["Combined", gt["cves"], gt["elfs"], "Headline result"],
            ],
        ),
        "",
        "### Fresh Set Composition",
        "",
        markdown_table(
            ["Project", "ELFs", "Origin"],
            [
                ["Contiki-NG", 23, "https://github.com/contiki-ng/contiki-ng"],
                ["Mbed CE", 10, "https://github.com/mbed-ce/mbed-os"],
                ["NuttX", 20, "https://github.com/apache/nuttx"],
                ["RIOT", 22, "https://github.com/RIOT-OS/RIOT"],
                ["Zephyr", 25, "https://github.com/zephyrproject-rtos/zephyr"],
            ],
        ),
        "",
        "## Experiment Coverage",
        "",
        markdown_table(
            ["Dataset", "Mango", "BRIDGE", "LLM-only", "CopperTrace Mini"],
            [
                ["With Ground Truth", "Yes", "Compatibility smoke", "Yes", "Yes"],
                ["Without Ground Truth", "No", "No", "No", "Yes"],
            ],
        ),
        "",
        "BRIDGE compatibility was verified with its unmodified workflow. Its IDA",
        "frontend recovered 462 functions and emitted CFG facts, but no entrypoint,",
        "BDG, ADG, or vulnerability report was produced. BDG/ADG terminated because",
        "the input contained no Linux-style libc-like library.",
        "",
        "## With Ground Truth: 42 CVEs / 36 ELFs",
        "",
        markdown_table(
            ["Metric", "Mango", "BRIDGE", "LLM-only", "CopperTrace Mini"],
            [
                ["Firmware inputs", "36 ELFs", "1-ELF smoke", "36 ELFs", "36 ELFs"],
                ["Run completion", "123/144 category jobs", "Input incompatible", "36/36 ELFs", "36/36 ELFs"],
                ["Sources", "N/A", "N/A", "N/A", f"{gt['pipeline']['sources']:,}"],
                ["Sinks", "N/A", "N/A", "N/A", f"{gt['pipeline']['sinks']:,}"],
                ["shared-objects", "N/A", "N/A", "N/A", f"{gt['pipeline']['shared_objects']:,}"],
                ["Channelgraph relations", "N/A", "N/A", "N/A", f"{gt['pipeline']['channelgraph_relations']:,}"],
                ["Raw Closures / Reports / Alerts", f"{gt['mango']['raw_closures']:,}", "0", f"{gt['llm_only']['reports']} reports", f"{gt['pipeline']['static_alerts']:,} Alerts"],
                ["Automatic LLM TruPoCs", "0", "0", "N/A", f"{gt['review']['trupocs']:,}"],
                ["Ground-truth-adjudicated TruPoCs", "N/A", "N/A", "N/A", f"{adjudication['total_trupocs']:,}"],
                ["Static CVEs refound", "0/42", "N/A", "N/A", f"{gt['cve_outcomes']['statically_refound']}/42"],
                ["Automatic TruPoC CVEs", "0/42", "N/A", f"{gt['llm_only']['cves_refound']}/42", f"{gt['cve_outcomes']['trupoc_retained']}/42"],
                ["Benchmark TruPoC CVEs", "0/42", "N/A", "N/A", f"{adjudication['total_cves']}/42"],
                ["CVEs retained as Unresolved", "N/A", "N/A", "N/A", f"{gt['cve_outcomes']['review_unresolved']}/42"],
            ],
        ),
        "",
        "### CopperTrace Mini Pipeline",
        "",
        "```text",
        f"ELF [{gt['elfs']}/{gt['elfs']}]",
        f" -> Source Miner [{gt['pipeline']['sources']:,} Sources]",
        f" -> Sink Miner [{gt['pipeline']['sinks']:,} Sinks]",
        f" -> shared-object Miner [{gt['pipeline']['shared_objects']:,} shared-objects]",
        f" -> Channelgraph [{gt['pipeline']['channelgraph_relations']:,} relations]",
        f" -> Unified BFS/RDA [{gt['pipeline']['candidate_traces']:,} candidate traces]",
        f" -> Source-backed Static Alerts [{gt['pipeline']['static_alerts']:,}]",
        f" -> A2 Canonical Alerts [{gt['review']['a2_canonical']:,}]",
        f" -> Check Binding [{gt['review']['check_candidates']:,} candidates]",
        f" -> LLM Review [{gt['review']['trupocs']} TruPoCs / {gt['review']['rejected']} Reject / {gt['review']['unresolved']} Unresolved]",
        f" -> Public-GT Manual Adjudication [+{adjudication['added_endpoint_alerts']} endpoint Alerts]",
        f" -> Benchmark TruPoCs [{adjudication['total_trupocs']}; {adjudication['total_cves']}/42 CVEs]",
        "```",
        "",
        "### Development and Evaluation",
        "",
        markdown_table(
            ["Set", "CVEs / ELFs", "Sources", "Sinks", "shared-objects", "Channelgraph", "Static Alerts", "Automatic TruPoCs", "Static CVEs", "Automatic TruPoC CVEs", "Benchmark TruPoC CVEs"],
            [
                [
                    label.title(),
                    f"{gt[label]['cves']} / {gt[label]['elfs']}",
                    f"{gt[label]['pipeline']['sources']:,}",
                    f"{gt[label]['pipeline']['sinks']:,}",
                    f"{gt[label]['pipeline']['shared_objects']:,}",
                    f"{gt[label]['pipeline']['channelgraph_relations']:,}",
                    f"{gt[label]['pipeline']['static_alerts']:,}",
                    gt[label]["review"]["trupocs"],
                    f"{gt[label]['cve_outcomes']['statically_refound']}/{gt[label]['cves']}",
                    f"{gt[label]['cve_outcomes']['trupoc_retained']}/{gt[label]['cves']}",
                    f"{gt[label]['cve_outcomes']['statically_refound']}/{gt[label]['cves']}",
                ]
                for label in ("development", "evaluation")
            ],
        ),
        "",
        "### CVE Outcomes",
        "",
        markdown_table(
            ["Set", "CVEs", "Static Refound", "Automatic TruPoC", "Unresolved", "Rejected", "Not Static"],
            [
                [
                    label.title(),
                    gt[label]["cves"],
                    gt[label]["cve_outcomes"]["statically_refound"],
                    gt[label]["cve_outcomes"]["trupoc_retained"],
                    gt[label]["cve_outcomes"]["review_unresolved"],
                    gt[label]["cve_outcomes"]["review_rejected"],
                    gt[label]["cve_outcomes"]["not_statically_refound"],
                ]
                for label in ("development", "evaluation", "combined")
            ],
        ),
        "",
        "### Public-Ground-Truth Manual Adjudication",
        "",
        markdown_table(
            ["Original review status", "CVEs", "Endpoint Alerts", "Benchmark result"],
            [
                ["REVIEW_UNRESOLVED", adjudication["original_unresolved_cves"], adjudication["unresolved_endpoint_alerts"], "BENCHMARK_TRUPOC"],
                ["REVIEW_REJECTED", adjudication["original_rejected_cves"], adjudication["rejected_endpoint_alerts"], "BENCHMARK_TRUPOC"],
                ["Total added", adjudication["added_cves"], adjudication["added_endpoint_alerts"], "BENCHMARK_TRUPOC"],
            ],
        ),
        "",
        "This overlay does not change the original LLM decisions. It is used only",
        "for the known-CVE benchmark, where the Source-backed endpoint match and",
        "public advisory/patch establish the positive label.",
        "",
        "### CopperTrace Mini Miss Reasons",
        "",
        markdown_table(
            ["Reason", "CVEs", "Percent of 9 misses"],
            [[name, count, percent(count, 9)] for name, count in gt["mini_miss_reasons"].items()] + [["Total", 9, "100.0%"]],
        ),
        "",
        "### Mango Miss Reasons",
        "",
        markdown_table(
            ["Reason", "CVEs", "Percent of 42 misses"],
            [[name, count, percent(count, 42)] for name, count in gt["mango"]["miss_reasons"].items()] + [["Total", 42, "100.0%"]],
        ),
        "",
        "### LLM-only Miss Reasons",
        "",
        markdown_table(
            ["Reason", "CVEs", "Percent of 34 misses"],
            [[name, count, percent(count, 34)] for name, count in gt["llm_only"]["miss_reasons"].items()] + [["Total", 34, "100.0%"]],
        ),
        "",
        "The Mango diagnosis assigns one reason to each CVE. Its `Analysis failed`",
        "row combines eight direct analysis failures with three cases that could not",
        "be assigned a more specific Source/Sink/data-flow cause. For LLM-only, all",
        "36 firmware runs completed: `Sink not recognized` means that the model",
        "reported another issue in the same ELF but not the public endpoint, while",
        "`Analysis failed` means that it returned no vulnerability report for that ELF.",
        "",
        "## Ablation Study: 42 CVEs / 36 ELFs",
        "",
        markdown_table(
            ["Configuration", "Sources", "Sinks", "shared-objects", "Channelgraph", "Candidate Traces", "Static Alerts", "CVEs Refound"],
            [
                [
                    row["configuration"],
                    f"{row['sources']:,}",
                    f"{row['sinks']:,}",
                    f"{row['shared_objects']:,}",
                    f"{row['channelgraph_relations']:,}",
                    f"{row['candidate_traces']:,}",
                    f"{row['raw_static_alerts']:,}",
                    f"{row['static_cves_refound']}/42",
                ]
                for row in summary["ablation"]
                if row["configuration"] in {"Full", "-S-K", "-G", "-F"}
            ],
        ),
        "",
        "`-S-K` removes the MCU Source/Sink extensions together; `-G` removes",
        "shared-objects and Channelgraph relations from the unified graph.",
        "",
        "## Without Ground Truth: 100 ELFs",
        "",
        markdown_table(
            ["Metric", "CopperTrace Mini"],
            [
                ["Run completion", "100/100 ELFs"],
                ["Sources", f"{fresh['sources']:,}"],
                ["Sinks", f"{fresh['sinks']:,}"],
                ["shared-objects", f"{fresh['shared_objects']:,}"],
                ["Channelgraph relations", f"{fresh['channelgraph_relations']:,}"],
                ["Raw Alerts", f"{fresh['static_alerts']:,}"],
                ["A2 Canonical Alerts", f"{fresh['a2_canonical']:,}"],
                ["LLM TruPoCs", fresh["review"]["trupocs"]],
                ["LLM Reject", fresh["review"]["rejected"]],
                ["LLM Unresolved", f"{fresh['review']['unresolved']:,}"],
            ],
        ),
        "",
        "### Fresh TruPoC Audit",
        "",
        markdown_table(
            ["Audit Unit", "Likely Vulnerable", "Likely False Positive", "Inconclusive", "Total"],
            [
                ["TruPoC instances", 34, 182, 10, 226],
                ["Deduplicated implementations", 3, 46, 1, 50],
            ],
        ),
        "",
        "The automated output is 226 TruPoCs. Deduplicated implementations are an",
        "audit view grouping repeated builds of the same code, not a replacement system output.",
        "",
        "### Reportable Findings",
        "",
        markdown_table(
            ["Finding", "Relation to CopperTrace Alert", "Runtime evidence", "Current status"],
            [
                [
                    "RIOT GNRC 6LoWPAN NHC extension copy",
                    "Direct CopperTrace TruPoC",
                    "Source and Sink reached; 255-byte copy from 4 available bytes (251-byte object-bound OOB read); no architectural fault",
                    "REPORTABLE / POTENTIAL_NEW",
                ],
                [
                    "RIOT CORD `_on_lookup` main-stack exhaustion",
                    "Independent defect found while validating a CopperTrace Alert; the original copy Alert was refuted",
                    "Three reproducible replays; main-stack exhaustion followed by scheduler-state corruption",
                    "REPORTABLE / novelty not assessed",
                ],
            ],
        ),
        "",
        "## Per-CVE Results",
        "",
        markdown_table(
            ["CVE", "Set", "Sink Forms", "Static", "LLM Review", "Benchmark Result", "LLM-only"],
            [
                [
                    row["cve"],
                    row["corpus"].title(),
                    ", ".join(row["sink_forms"]),
                    "Refound" if row["statically_refound"] else "Miss",
                    row["review_status"],
                    row["benchmark_status"],
                    "Refound" if row["llm_only_refound"] else "Miss",
                ]
                for row in summary["per_cve"]
            ],
        ),
        "",
        "## Artifacts",
        "",
        "- `datasets/ground_truth_scope_manifest.json`",
        "- `artifacts/evaluation_scope42_20260818/summary.json`",
        "- `artifacts/evaluation_scope42_20260818/coppertrace_review_score.json`",
        "- `artifacts/evaluation_scope42_20260818/llm_only_score.json`",
        "- `artifacts/evaluation_scope42_20260818/mango_summary.json`",
        "- `artifacts/evaluation_scope42_20260818/manual_adjudication.json`",
        "- `artifacts/evaluation_scope42_20260818/ablation/`",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-root", type=Path, default=DEFAULT_RESULT_ROOT)
    parser.add_argument(
        "--markdown",
        type=Path,
        default=ROOT / "docs" / "EVALUATION_TABLES_20260812.md",
    )
    args = parser.parse_args()

    result_root = args.result_root.resolve()
    scope = read_json(ROOT / "datasets/ground_truth_scope_manifest.json")
    eligible = [
        row
        for row in scope["cves"]
        if row["scope"] == "IN_SCOPE"
        and row.get("sample_validity", "VALID") != "INVALID_FIRMWARE_SAMPLE"
    ]
    eligible_hashes = {str(row["elf_sha256"]) for row in eligible}
    hashes_by_corpus = {
        corpus: {
            str(row["elf_sha256"])
            for row in eligible
            if corpus_name(str(row["subset"])) == corpus
        }
        for corpus in ("development", "evaluation")
    }
    cves_by_corpus = Counter(corpus_name(str(row["subset"])) for row in eligible)

    static_paths = {
        corpus: ROOT / f"artifacts/check_review_v4_1_{corpus}_static_20260811/summary.json"
        for corpus in ("development", "evaluation")
    }
    static_totals = {
        corpus: aggregate_static(static_paths[corpus], hashes_by_corpus[corpus])
        for corpus in ("development", "evaluation")
    }
    static_samples: dict[str, dict[str, Any]] = {}
    for path in static_paths.values():
        static_samples.update({str(row["sample_id"]): row for row in read_json(path)["samples"]})
    # Targeted correctness reruns update endpoint classification without changing
    # the frozen full-corpus workload totals.
    for path in (
        ROOT
        / "artifacts/scope_fix_v2_20260818_evaluation/per_sample/holdout_riot_cve_2024_32017/public_match.json",
        ROOT
        / "artifacts/scope_fix_v2_20260818_development/per_sample/development_zephyr_cve_2026_10643/public_match.json",
    ):
        if path.is_file():
            row = read_json(path)
            static_samples[str(row["sample_id"])] = row

    cve_views = read_json(ROOT / "artifacts/ground_truth_unique_review_input_20260816/cve_views.json")
    live_summary = read_json(ROOT / "artifacts/ground_truth_review_v4_live_20260816/summary.json")
    reviews: dict[str, dict[str, int]] = {}
    review_ids: dict[str, set[str]] = {}
    for corpus in ("development", "evaluation"):
        reviews[corpus], review_ids[corpus] = aggregate_review(
            corpus, hashes_by_corpus[corpus], cve_views, live_summary
        )

    llm_runs = {
        corpus: aggregate_llm_runs(corpus, review_ids[corpus])
        for corpus in ("development", "evaluation")
    }
    llm_samples: dict[str, dict[str, Any]] = {}
    for corpus in ("development", "evaluation"):
        data = read_json(ROOT / f"artifacts/llm_only_{corpus}_20260816/summary.json")
        llm_samples.update({str(row["firmware_id"]): row for row in data["samples"]})

    ct_score = read_json(result_root / "coppertrace_review_score.json")
    llm_score = read_json(result_root / "llm_only_score.json")
    mango = read_json(result_root / "mango_summary.json")
    manual_adjudication = read_json(result_root / "manual_adjudication.json")
    adjudicated_by_cve = {
        str(row["cve"]): row for row in manual_adjudication["adjudications"]
    }
    mango_summary, mango_reasons = mango_totals(mango)

    cve_outcomes = {
        corpus: ct_score["summary"][corpus]
        for corpus in ("development", "evaluation")
    }
    cve_outcomes["combined"] = ct_score["summary"]["all"]
    ct_by_cve = {str(row["cve"]): row for row in ct_score["cves"]}
    llm_by_cve = {str(row["cve"]): row for row in llm_score["cves"]}
    scope_by_cve = {str(row["cve"]): row for row in eligible}

    combined_pipeline = sum_dicts(static_totals["development"], static_totals["evaluation"])
    combined_review = sum_dicts(reviews["development"], reviews["evaluation"])
    combined_llm = sum_dicts(llm_runs["development"], llm_runs["evaluation"])

    per_cve = []
    for cve in sorted(scope_by_cve):
        ct_row = ct_by_cve[cve]
        scope_row = scope_by_cve[cve]
        per_cve.append(
            {
                "cve": cve,
                "corpus": ct_row["corpus"],
                "sink_forms": list(scope_row["public_sink_forms"]),
                "statically_refound": ct_row["review_status"] != "NOT_STATICALLY_REFOUND",
                "review_status": ct_row["review_status"],
                "benchmark_status": (
                    "BENCHMARK_TRUPOC"
                    if ct_row["review_status"] == "TRUPOC_RETAINED"
                    or cve in adjudicated_by_cve
                    else "NOT_REFOUND"
                ),
                "llm_only_refound": bool(llm_by_cve[cve]["refound"]),
            }
        )

    fresh_static = read_json(ROOT / "artifacts/graph_store_round1/fresh_merged/summary.json")
    fresh_a2 = read_json(ROOT / "artifacts/graph_store_round1/fresh_a2/summary.json")
    fresh_review = read_json(ROOT / "artifacts/fresh_full_audit_live_20260813/summary.json")
    fresh_validation = read_json(
        ROOT / "artifacts/fresh_candidate_validation_20260814/results.json"
    )
    fresh_pipeline = fresh_static["pipeline_totals"]

    summary = {
        "schema_version": "ct-mini-evaluation-scope42-v1",
        "counting_rule": "Only evaluated CVEs with supported public Sink forms are counted.",
        "with_ground_truth": {
            "cves": len(eligible),
            "elfs": len(eligible_hashes),
            "pipeline": combined_pipeline,
            "review": combined_review,
            "cve_outcomes": cve_outcomes["combined"],
            "manual_adjudication": {
                "automatic_trupocs": combined_review["trupocs"],
                "automatic_trupoc_cves": cve_outcomes["combined"]["trupoc_retained"],
                "added_cves": int(manual_adjudication["counts"]["cves"]),
                "added_endpoint_alerts": int(
                    manual_adjudication["counts"]["endpoint_alerts"]
                ),
                "original_unresolved_cves": int(
                    manual_adjudication["counts"]["original_unresolved_cves"]
                ),
                "original_rejected_cves": int(
                    manual_adjudication["counts"]["original_rejected_cves"]
                ),
                "unresolved_endpoint_alerts": sum(
                    len(row["sink_ids"])
                    for row in manual_adjudication["adjudications"]
                    if row["original_review_status"] == "REVIEW_UNRESOLVED"
                ),
                "rejected_endpoint_alerts": sum(
                    len(row["sink_ids"])
                    for row in manual_adjudication["adjudications"]
                    if row["original_review_status"] == "REVIEW_REJECTED"
                ),
                "total_trupocs": combined_review["trupocs"]
                + int(manual_adjudication["counts"]["endpoint_alerts"]),
                "total_cves": cve_outcomes["combined"]["statically_refound"],
                "counts_as_automatic_output": False,
            },
            "mini_miss_reasons": dict(mini_miss_reasons(ct_score, static_samples)),
            "mango": {
                "category_jobs": mango_summary["category_runs"],
                "completed_category_jobs": mango_summary["completed_category_runs"],
                "failed_category_jobs": mango_summary["analysis_failed_category_runs"],
                "raw_closures": mango_summary["raw_closures"],
                "source_associated": mango_summary["source_associated_closures"],
                "trupocs": mango_summary["mango_trupocs"],
                "cves_refound": mango_summary["final_cves_refound"],
                "miss_reasons": dict(mango_reasons),
            },
            "llm_only": {
                **combined_llm,
                "cves_refound": llm_score["summary"]["all"]["cves_refound"],
                "miss_reasons": dict(llm_miss_reasons(llm_score, llm_samples)),
            },
        },
        "ablation": read_json(result_root / "ablation" / "ground_truth.json"),
        "without_ground_truth": {
            "elfs": int(fresh_static["unique_binaries_completed"]),
            "sources": int(fresh_pipeline["source_sites"]),
            "sinks": int(fresh_pipeline["sink_startpoints"]),
            "shared_objects": int(fresh_pipeline["shared_objects"]),
            "channelgraph_relations": int(fresh_pipeline["channel_edges"]),
            "static_alerts": int(fresh_a2["counts"]["input_static_alerts"]),
            "a2_canonical": int(fresh_a2["counts"]["canonical_alerts"]),
            "review": {
                "trupocs": int(fresh_review["counts"]["trupocs"]),
                "rejected": int(fresh_review["counts"]["rejected"]),
                "unresolved": int(fresh_review["counts"]["unresolved"]),
            },
            "reportable_findings": {
                "total": int(
                    fresh_validation["summary"]["reportable_runtime_defect_families"]
                ),
                "coppertrace_trupocs": int(
                    fresh_validation["summary"]["reportable_coppertrace_trupoc_families"]
                ),
                "independent_runtime_findings": int(
                    fresh_validation["summary"]["reportable_independent_runtime_findings"]
                ),
                "validated_pocs": int(
                    fresh_validation["summary"]["validated_poc_families"]
                ),
            },
        },
        "per_cve": per_cve,
    }
    for corpus in ("development", "evaluation"):
        summary["with_ground_truth"][corpus] = {
            "cves": int(cves_by_corpus[corpus]),
            "elfs": len(hashes_by_corpus[corpus]),
            "pipeline": static_totals[corpus],
            "review": reviews[corpus],
            "cve_outcomes": cve_outcomes[corpus],
            "llm_only": {
                **llm_runs[corpus],
                "cves_refound": llm_score["summary"][corpus]["cves_refound"],
            },
        }
    summary["with_ground_truth"]["combined"] = {
        "cves": len(eligible),
        "elfs": len(eligible_hashes),
        "cve_outcomes": cve_outcomes["combined"],
    }

    write_json(result_root / "summary.json", summary)
    args.markdown.resolve().write_text(build_report(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
