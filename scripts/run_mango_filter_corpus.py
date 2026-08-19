#!/usr/bin/env python3
"""Run the A1 Mango-equivalent Filter over an existing Mini corpus."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from filter_static_alerts import filter_static_alerts, load_json, write_json


SOURCE_REACHED_STATUSES = frozenset(
    {"SOURCE_REACHED_DETERMINISTIC", "SOURCE_REACHED_HEURISTIC"}
)


def _public_reproduction_ids(
    chains_doc: dict[str, Any], public_match: dict[str, Any]
) -> set[str]:
    """Return Alert IDs counted by the existing Static CVE Reproduction rule.

    ``render_pipeline_run.py`` counts a public endpoint as reproduced whenever
    its chain has a ``SOURCE_REACHED_*`` status.  Matching the exact Source in
    the public profile is a stricter diagnostic field, not part of that frozen
    headline metric.  The Filter evaluation must reuse the same boundary.
    """

    chains_by_sink = {
        str(row.get("sink_id", "")): str(row.get("chain_id", ""))
        for row in list(chains_doc.get("chains", []) or [])
    }
    result: set[str] = set()
    for row in list(public_match.get("public_chain_matches", []) or []):
        if str(row.get("status", "")) not in SOURCE_REACHED_STATUSES:
            continue
        chain_id = chains_by_sink.get(str(row.get("sink_id", "")), "")
        if chain_id:
            result.add(chain_id)
    return result


def _represented_ids(rows: list[dict[str, Any]]) -> set[str]:
    return {
        str(alert_id)
        for row in rows
        for alert_id in list(row.get("represented_alert_ids", []) or [])
        if str(alert_id)
    }


def _public_alert_rank(
    filter_doc: dict[str, Any], public_ids: set[str]
) -> int | None:
    rows = list(filter_doc.get("canonical_alerts", []) or [])
    if not rows:
        rows = list(filter_doc.get("selected", []) or []) + list(
            filter_doc.get("deferred", []) or []
        )
    return min(
        (
            int(item.get("rank", 0))
            for item in rows
            if public_ids
            & {
                str(value)
                for value in list(item.get("represented_alert_ids", []) or [])
            }
        ),
        default=None,
    )


def _render_pipeline(
    input_root: Path, totals: dict[str, int], *, max_selected: int
) -> str:
    input_pipeline = input_root.parent / "pipeline.txt"
    prefix = (
        input_pipeline.read_text(encoding="utf-8").rstrip()
        if input_pipeline.is_file()
        else "Existing CopperTrace Mini Static Alerts"
    )
    reproduced = int(totals["public_cves_reproduced_before_filter"])
    return "\n".join(
        [
            prefix,
            (
                "  -> A1 Mango-equivalent Filter "
                f"[input={totals['input_static_alerts']}, "
                f"canonical={totals['canonical_alerts']}, "
                f"subsumed={totals['source_set_subsumed']}]"
            ),
            (
                f"  -> Top-{max_selected} Selection "
                f"[selected={totals['selected']}, deferred={totals['deferred']}]"
            ),
            (
                "  -> Public-CVE Filter Audit "
                f"[dedup={totals['public_cves_preserved_after_dedup']}/"
                f"{reproduced}, Top-{max_selected}="
                f"{totals['public_cves_retained_in_top_n']}/{reproduced}]"
            ),
        ]
    )


def _render_summary_markdown(summary: dict[str, Any]) -> str:
    counts = dict(summary.get("counts", {}) or {})
    rows = [
        "# A1 Mango-equivalent Alert Filter",
        "",
        "```text",
        str(summary.get("pipeline", "")),
        "```",
        "",
        "| CVE | Sample | Public Alert Rank | Top-N |",
        "|---|---|---:|---|",
    ]
    for sample in list(summary.get("samples", []) or []):
        if not bool(sample.get("public_cve_reproduced_before_filter", False)):
            continue
        rows.append(
            "| {cve} | `{sample}` | {rank} | {retained} |".format(
                cve=str(sample.get("cve", "")),
                sample=str(sample.get("sample_id", "")),
                rank=sample.get("public_alert_rank") or "-",
                retained=(
                    "retained"
                    if bool(sample.get("public_cve_retained_in_top_n", False))
                    else "deferred"
                ),
            )
        )
    rows.extend(
        [
            "",
            (
                "The A1 deduplication stage preserved "
                f"{counts.get('public_cves_preserved_after_dedup', 0)}/"
                f"{counts.get('public_cves_reproduced_before_filter', 0)} "
                "previously reproduced public CVEs. Ranking is evaluated "
                "separately and does not delete deferred Alerts."
            ),
            "",
        ]
    )
    return "\n".join(rows)


def run_corpus(
    manifest: dict[str, Any],
    input_root: Path,
    output_root: Path,
    *,
    max_selected: int,
) -> dict[str, Any]:
    sample_results: list[dict[str, Any]] = []
    totals = {
        "samples": 0,
        "input_chains": 0,
        "input_static_alerts": 0,
        "canonical_alerts": 0,
        "source_set_subsumed": 0,
        "selected": 0,
        "deferred": 0,
        "artifact_contradictions": 0,
        "public_cves_reproduced_before_filter": 0,
        "public_cves_preserved_after_dedup": 0,
        "public_cves_retained_in_top_n": 0,
    }

    for sample in list(manifest.get("samples", []) or []):
        sample_id = str(sample.get("sample_id", ""))
        if not sample_id:
            continue
        sample_in = input_root / sample_id
        chains_path = sample_in / "chains.json"
        sinks_path = sample_in / "sinks.json"
        sources_path = sample_in / "sources.json"
        public_match_path = sample_in / "public_match.json"
        required = (chains_path, sinks_path, sources_path, public_match_path)
        if not all(path.is_file() for path in required):
            sample_results.append(
                {
                    "sample_id": sample_id,
                    "cve": str(sample.get("cve", "")),
                    "status": "INPUT_MISSING",
                    "missing": [str(path) for path in required if not path.is_file()],
                }
            )
            continue

        chains_doc = load_json(chains_path)
        result = filter_static_alerts(
            chains_doc,
            load_json(sinks_path),
            load_json(sources_path),
            max_selected=max_selected,
        )
        sample_out = output_root / "per_sample" / sample_id / "alert_filter.json"
        write_json(sample_out, result)

        public_ids = _public_reproduction_ids(
            chains_doc, load_json(public_match_path)
        )
        selected_ids = _represented_ids(list(result.get("selected", []) or []))
        canonical_ids = _represented_ids(
            list(result.get("selected", []) or [])
            + list(result.get("deferred", []) or [])
        )
        reproduced_before = bool(public_ids)
        preserved_after_dedup = bool(public_ids & canonical_ids)
        retained = bool(public_ids & selected_ids)
        row = {
            "sample_id": sample_id,
            "cve": str(sample.get("cve", "")),
            "status": "OK",
            **result["counts"],
            "public_reproduction_alert_ids": sorted(public_ids),
            "public_cve_reproduced_before_filter": reproduced_before,
            "public_cve_preserved_after_dedup": preserved_after_dedup,
            "public_cve_retained_in_top_n": retained,
            "public_alert_rank": _public_alert_rank(result, public_ids),
        }
        sample_results.append(row)

        totals["samples"] += 1
        for key in (
            "input_chains",
            "input_static_alerts",
            "canonical_alerts",
            "source_set_subsumed",
            "selected",
            "deferred",
            "artifact_contradictions",
        ):
            totals[key] += int(result["counts"].get(key, 0))
        totals["public_cves_reproduced_before_filter"] += int(reproduced_before)
        totals["public_cves_preserved_after_dedup"] += int(
            preserved_after_dedup
        )
        totals["public_cves_retained_in_top_n"] += int(retained)

    summary = {
        "schema_version": "ct-mini-alert-filter-corpus-a1-v1",
        "policy": {
            "name": "MANGO_EQUIVALENT_A1",
            "max_selected_per_firmware": max_selected,
            "public_profile_stage": "post_filter_evaluation_only",
            "checks_used": False,
            "mcu_evidence_used_for_ranking": False,
        },
        "input_root": str(input_root.resolve()),
        "counts": totals,
        "samples": sample_results,
    }
    summary["pipeline"] = _render_pipeline(
        input_root, totals, max_selected=max_selected
    )
    write_json(output_root / "summary.json", summary)
    (output_root / "pipeline.txt").write_text(
        str(summary["pipeline"]) + "\n", encoding="utf-8"
    )
    (output_root / "summary.md").write_text(
        _render_summary_markdown(summary), encoding="utf-8"
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--input-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--max-selected", type=int, default=20)
    args = parser.parse_args()
    run_corpus(
        load_json(args.manifest),
        args.input_root,
        args.out,
        max_selected=max(1, args.max_selected),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
