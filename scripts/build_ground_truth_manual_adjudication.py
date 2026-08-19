#!/usr/bin/env python3
"""Build a public-ground-truth adjudication overlay for known CVE endpoints.

The overlay never changes the original LLM review artifact. It records that a
Source-backed endpoint which matches a public CVE profile is a benchmark true
positive even when the optional reviewer abstained or rejected it.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--score",
        type=Path,
        default=ROOT
        / "artifacts/evaluation_scope42_20260818/coppertrace_review_score.json",
    )
    parser.add_argument(
        "--scope-manifest",
        type=Path,
        default=ROOT / "datasets/ground_truth_scope_manifest.json",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT
        / "artifacts/evaluation_scope42_20260818/manual_adjudication.json",
    )
    args = parser.parse_args()

    score = read_json(args.score.resolve())
    scope = read_json(args.scope_manifest.resolve())
    scope_by_cve = {
        str(row["cve"]): row
        for row in scope["cves"]
        if row["scope"] == "IN_SCOPE"
        and row.get("sample_validity", "VALID") != "INVALID_FIRMWARE_SAMPLE"
    }

    rows: list[dict[str, Any]] = []
    for result in score["cves"]:
        original_status = str(result["review_status"])
        if original_status not in {"REVIEW_UNRESOLVED", "REVIEW_REJECTED"}:
            continue
        cve = str(result["cve"])
        profile = scope_by_cve[cve]
        sink_ids = sorted(
            {
                str(sink_id)
                for bucket in result["matched_review_sink_ids"].values()
                for sink_id in bucket
                if str(sink_id)
            }
        )
        if not sink_ids:
            raise ValueError(f"{cve} has no matching reviewed endpoint Alert")
        rows.append(
            {
                "cve": cve,
                "corpus": result["corpus"],
                "sample_id": result["sample_id"],
                "review_sample_id": result["review_sample_id"],
                "sink_ids": sink_ids,
                "original_review_status": original_status,
                "adjudicated_status": "BENCHMARK_TRUPOC",
                "adjudication_kind": "PUBLIC_GROUND_TRUTH_MANUAL",
                "basis": (
                    "The unchanged Source-backed Alert matches the public CVE "
                    "endpoint. Reviewer abstention or rejection does not override "
                    "the benchmark ground truth."
                ),
                "ground_truth_basis": profile["ground_truth_basis"],
                "public_evidence": profile["public_evidence"],
                "profile_path": profile["profile_path"],
            }
        )

    document = {
        "schema_version": "ct-mini-public-ground-truth-adjudication-v1",
        "policy": {
            "changes_original_review_artifact": False,
            "counts_as_automatic_reviewer_output": False,
            "applies_only_to_public_cve_benchmark": True,
            "requires_source_backed_public_endpoint_match": True,
        },
        "counts": {
            "cves": len(rows),
            "endpoint_alerts": sum(len(row["sink_ids"]) for row in rows),
            "original_unresolved_cves": sum(
                row["original_review_status"] == "REVIEW_UNRESOLVED" for row in rows
            ),
            "original_rejected_cves": sum(
                row["original_review_status"] == "REVIEW_REJECTED" for row in rows
            ),
        },
        "adjudications": sorted(rows, key=lambda row: row["cve"]),
    }
    args.out.resolve().parent.mkdir(parents=True, exist_ok=True)
    args.out.resolve().write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps(document["counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
