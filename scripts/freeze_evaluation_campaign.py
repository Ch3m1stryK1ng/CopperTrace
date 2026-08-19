#!/usr/bin/env python3
"""Freeze the analyzer and evaluation inputs after the Development gate passes."""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tracked_files(paths: Iterable[Path]) -> list[Path]:
    result: set[Path] = set()
    for path in paths:
        if path.is_file():
            result.add(path.resolve())
            continue
        if not path.is_dir():
            continue
        for candidate in path.rglob("*"):
            if not candidate.is_file():
                continue
            if "__pycache__" in candidate.parts or candidate.suffix == ".pyc":
                continue
            result.add(candidate.resolve())
    return sorted(result)


def file_manifest(paths: Iterable[Path]) -> dict[str, str]:
    rows: dict[str, str] = {}
    for path in tracked_files(paths):
        try:
            label = str(path.relative_to(ROOT))
        except ValueError:
            label = str(path)
        rows[label] = sha256_file(path)
    return rows


def manifest_digest(rows: dict[str, str]) -> str:
    encoded = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def referenced_profiles(manifest_path: Path) -> list[Path]:
    result: list[Path] = []
    for sample in list(load_json(manifest_path).get("samples", []) or []):
        value = str(sample.get("expected_profile_path", "") or "")
        if value:
            result.append(Path(value))
        value = str(sample.get("hardware_metadata_path", "") or "")
        if value:
            candidate = Path(value)
            result.append(candidate if candidate.is_absolute() else ROOT / candidate)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--development-summary", required=True, type=Path)
    parser.add_argument("--a1-summary", required=True, type=Path)
    parser.add_argument("--a2-summary", required=True, type=Path)
    parser.add_argument("--development-manifest", required=True, type=Path)
    parser.add_argument("--holdout-manifest", required=True, type=Path)
    parser.add_argument("--fresh-selection", required=True, type=Path)
    parser.add_argument("--source-profiles", required=True, type=Path)
    parser.add_argument("--holdout-source-profiles", required=True, type=Path)
    parser.add_argument("--evaluation-plan", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--max-finite-callind-targets", type=int, default=64)
    args = parser.parse_args()

    development = load_json(args.development_summary)
    a1 = load_json(args.a1_summary)
    a2 = load_json(args.a2_summary)
    counts = dict(a2.get("counts", {}) or {})
    budgets = dict(development.get("analysis_budgets", {}) or {})

    reproduced = int(counts.get("public_cves_reproduced_before_filter", 0) or 0)
    gates = {
        "development_30_of_30_completed": (
            int(development.get("samples_requested", 0) or 0) == 30
            and int(development.get("samples_ok", 0) or 0) == 30
            and int(development.get("samples_failed", 0) or 0) == 0
        ),
        "development_reproduction_at_least_21": reproduced >= 21,
        "a2_preserves_every_reproduced_cve": (
            int(counts.get("public_cves_preserved_after_dedup", 0) or 0)
            == reproduced
        ),
        "a2_drops_no_public_cve": (
            int(counts.get("public_cves_dropped_by_check", 0) or 0) == 0
        ),
        "a2_has_no_artifact_contradictions": (
            int(counts.get("artifact_contradictions", 0) or 0) == 0
        ),
        "callind_budget_is_frozen_value": (
            int(budgets.get("max_finite_callind_targets", 0) or 0)
            == args.max_finite_callind_targets
        ),
        "a2_reviews_every_canonical_alert": (
            bool(dict(a2.get("policy", {}) or {}).get(
                "all_canonical_alerts_review_eligible", False
            ))
            and int(counts.get("public_cves_review_eligible", 0) or 0)
            == reproduced
        ),
    }

    analyzer_files = file_manifest(
        [ROOT / "scripts", ROOT / "registries", ROOT / "schemas"]
    )
    input_paths = [
        args.development_manifest,
        args.holdout_manifest,
        args.fresh_selection,
        args.source_profiles,
        args.holdout_source_profiles,
        args.evaluation_plan,
        *referenced_profiles(args.development_manifest),
        *referenced_profiles(args.holdout_manifest),
    ]
    input_files = file_manifest(input_paths)
    result = {
        "schema_version": "ct-mini-evaluation-freeze-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "FROZEN" if all(gates.values()) else "GATE_FAILED",
        "gates": gates,
        "configuration": {
            "max_finite_callind_targets": args.max_finite_callind_targets,
            "max_trace_witnesses": int(
                budgets.get("max_trace_witnesses", 0) or 0
            ),
            "graph_mode": str(development.get("graph_mode", "")),
            "a2_pre_review_top_k": False,
            "check_policy": "deterministic_capacity_safe_hard_drop_only",
            "holdout_rule_changes_allowed": False,
            "fresh_rule_changes_allowed": False,
        },
        "development_gate": {
            "samples_requested": int(development.get("samples_requested", 0) or 0),
            "samples_ok": int(development.get("samples_ok", 0) or 0),
            "public_cves_reproduced": reproduced,
            "public_cves_preserved_after_a2": int(
                counts.get("public_cves_preserved_after_dedup", 0) or 0
            ),
            "public_cves_review_eligible": int(
                counts.get("public_cves_review_eligible", 0) or 0
            ),
            "a1_public_cves_in_top_n_reference": int(
                dict(a1.get("counts", {}) or {}).get(
                    "public_cves_retained_in_top_n", 0
                )
                or 0
            ),
        },
        "ghidra_tool_fingerprint": str(
            dict(development.get("provenance", {}) or {}).get(
                "ghidra_tool_fingerprint", ""
            )
        ),
        "analyzer_files": analyzer_files,
        "analyzer_tree_sha256": manifest_digest(analyzer_files),
        "evaluation_inputs": input_files,
        "evaluation_inputs_sha256": manifest_digest(input_files),
        "result_artifacts": {
            str(args.development_summary.resolve()): sha256_file(args.development_summary),
            str(args.a1_summary.resolve()): sha256_file(args.a1_summary),
            str(args.a2_summary.resolve()): sha256_file(args.a2_summary),
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({
        "status": result["status"],
        "gates": gates,
        "analyzer_tree_sha256": result["analyzer_tree_sha256"],
        "evaluation_inputs_sha256": result["evaluation_inputs_sha256"],
    }, indent=2))
    return 0 if result["status"] == "FROZEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
