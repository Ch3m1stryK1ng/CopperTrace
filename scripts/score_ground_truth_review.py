#!/usr/bin/env python3
"""Score post-review CVE retention without exposing CVE profiles to the reviewer."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ct-mini-ground-truth-review-score-v1"
ROOT = Path(__file__).resolve().parents[1]
STATUSES = (
    "TRUPOC_RETAINED",
    "REVIEW_UNRESOLVED",
    "REVIEW_REJECTED",
    "NOT_STATICALLY_REFOUND",
)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def alert_sink_ids(row: dict[str, Any]) -> set[str]:
    alert = dict(row.get("alert", {}) or {})
    result = {str(alert.get("sink_id", "") or "")}
    result.update(
        str(value)
        for value in list(alert.get("represented_sink_ids", []) or [])
        if str(value)
    )
    return {value for value in result if value}


def partition_ids(review: dict[str, Any]) -> dict[str, set[str]]:
    return {
        "TRUPOC_RETAINED": {
            sink_id
            for row in list(review.get("trupocs", []) or [])
            for sink_id in alert_sink_ids(dict(row))
        },
        "REVIEW_UNRESOLVED": {
            sink_id
            for row in list(review.get("unresolved_alerts", []) or [])
            for sink_id in alert_sink_ids(dict(row))
        },
        "REVIEW_REJECTED": {
            sink_id
            for row in list(review.get("rejected_alerts", []) or [])
            for sink_id in alert_sink_ids(dict(row))
        },
    }


def canonical_sink_ids(a2: dict[str, Any]) -> set[str]:
    rows = list(a2.get("canonical_alerts", []) or [])
    if not rows:
        rows = [
            *list(a2.get("selected", []) or []),
            *list(a2.get("deferred", []) or []),
            *list(a2.get("dropped", []) or []),
        ]
    result: set[str] = set()
    for raw in rows:
        row = dict(raw or {})
        sink_id = str(row.get("sink_id", "") or "")
        if sink_id:
            result.add(sink_id)
    return result


def expected_source_backed_sink_ids(public_match: dict[str, Any]) -> set[str]:
    """Return public Sink endpoints counted by the frozen CVE metric.

    The headline metric counts an endpoint when its matched chain reaches any
    modeled Source. ``matched_public_source`` remains a stricter diagnostic for
    auditing the public Source profile; it is not part of this metric.
    """
    return {
        str(row.get("sink_id", "") or "")
        for row in list(public_match.get("public_chain_matches", []) or [])
        if str(row.get("status", "") or "").startswith("SOURCE_REACHED")
        and str(row.get("sink_id", "") or "")
    }


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter(str(row["review_status"]) for row in rows)
    return {
        "cves": len(rows),
        **{status.lower(): counts[status] for status in STATUSES},
        "statically_refound": len(rows) - counts["NOT_STATICALLY_REFOUND"],
        "retained_or_unresolved": counts["TRUPOC_RETAINED"] + counts["REVIEW_UNRESOLVED"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve-views", type=Path, required=True)
    parser.add_argument("--review-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--scope-manifest",
        type=Path,
        default=ROOT / "datasets/ground_truth_scope_manifest.json",
    )
    parser.add_argument(
        "--public-match-override",
        action="append",
        default=[],
        metavar="CVE=PATH",
        help="Use a correctness-rerun public_match.json for one CVE.",
    )
    args = parser.parse_args()

    views = list(read_json(args.cve_views).get("cve_views", []) or [])
    scope_rows = {
        str(row.get("cve", "")): dict(row)
        for row in list(read_json(args.scope_manifest).get("cves", []) or [])
    }
    evaluated = {
        cve for cve, row in scope_rows.items()
        if row.get("scope") == "IN_SCOPE"
        and row.get("sample_validity", "VALID") == "VALID"
    }
    overrides: dict[str, Path] = {}
    for value in args.public_match_override:
        cve, separator, path = str(value).partition("=")
        if not separator or not cve or not path:
            raise ValueError("--public-match-override requires CVE=PATH")
        overrides[cve] = Path(path)
    reviews: dict[str, dict[str, Any]] = {}
    scored: list[dict[str, Any]] = []
    for raw_view in views:
        view = dict(raw_view)
        cve = str(view.get("cve", ""))
        if cve not in evaluated:
            continue
        review_sample_id = str(view["review_sample_id"])
        if review_sample_id not in reviews:
            path = args.review_root / "per_sample" / review_sample_id / "reviewed_alerts.json"
            if not path.is_file():
                raise FileNotFoundError(f"missing review output: {path}")
            reviews[review_sample_id] = read_json(path)
        public_match_path = overrides.get(
            cve, Path(str(view["static_artifact_dir"])) / "public_match.json"
        )
        public_match = read_json(public_match_path)
        expected_ids = expected_source_backed_sink_ids(public_match)
        a2_ids = canonical_sink_ids(read_json(Path(str(view["a2_artifact_path"]))))
        review_ids = partition_ids(reviews[review_sample_id])
        canonical_matches = expected_ids & a2_ids
        matched = {
            status: sorted(canonical_matches & values)
            for status, values in review_ids.items()
        }
        if not canonical_matches:
            status = "NOT_STATICALLY_REFOUND"
        elif matched["TRUPOC_RETAINED"]:
            status = "TRUPOC_RETAINED"
        elif matched["REVIEW_UNRESOLVED"]:
            status = "REVIEW_UNRESOLVED"
        elif matched["REVIEW_REJECTED"]:
            status = "REVIEW_REJECTED"
        else:
            raise RuntimeError(
                f"{view['cve']}: canonical public Sink Alert is absent from review partitions"
            )
        scored.append(
            {
                "corpus": view["corpus"],
                "sample_id": view["sample_id"],
                "review_sample_id": review_sample_id,
                "cve": cve,
                "scope": "IN_SCOPE",
                "scope_reason": scope_rows[cve].get("reason", ""),
                "review_status": status,
                "source_backed_public_sink_ids": sorted(expected_ids),
                "canonical_public_sink_ids": sorted(canonical_matches),
                "matched_review_sink_ids": matched,
            }
        )

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in scored:
        grouped["all"].append(row)
        grouped[str(row["corpus"])].append(row)
        if row["scope"] == "IN_SCOPE":
            grouped["in_scope"].append(row)
            grouped[f"{row['corpus']}_in_scope"].append(row)
    summary = {name: aggregate(rows) for name, rows in sorted(grouped.items())}
    output = {
        "schema_version": SCHEMA_VERSION,
        "status_definitions": {
            "TRUPOC_RETAINED": "At least one matching public endpoint Alert was classified as TRUPOC.",
            "REVIEW_UNRESOLVED": "No matching endpoint was a TruPoC, but at least one remained unresolved.",
            "REVIEW_REJECTED": "Every matching canonical endpoint Alert was rejected.",
            "NOT_STATICALLY_REFOUND": "No Source-backed matching endpoint entered the canonical review input.",
        },
        "summary": summary,
        "cves": scored,
        "scope": {
            "manifest": str(args.scope_manifest.resolve()),
            "evaluated_in_scope_cves": len(evaluated),
            "excluded_cves_not_scored": len(scope_rows) - len(evaluated),
        },
    }
    write_json(args.out, output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
