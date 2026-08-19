#!/usr/bin/env python3
"""Materialize callsite-audited family decisions into per-Alert results."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


VALID_RESULTS = {
    "LIKELY_VULNERABLE",
    "LIKELY_FALSE_POSITIVE",
    "INCONCLUSIVE",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", required=True, type=Path)
    parser.add_argument("--decisions", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def load_json(path: Path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def main() -> int:
    args = parse_args()
    index = load_json(args.index)
    decision_document = load_json(args.decisions)
    decisions = decision_document["families"]

    by_family = {row["family_id"]: row for row in decisions}
    if len(by_family) != len(decisions):
        raise SystemExit("duplicate family_id in decisions")

    indexed_ids = {row["family_id"] for row in index["families"]}
    decision_ids = set(by_family)
    if indexed_ids != decision_ids:
        raise SystemExit(
            "family coverage mismatch: "
            f"missing={sorted(indexed_ids - decision_ids)} "
            f"extra={sorted(decision_ids - indexed_ids)}"
        )

    alert_rows = []
    for family in index["families"]:
        decision = by_family[family["family_id"]]
        if decision["result"] not in VALID_RESULTS:
            raise SystemExit(f"invalid result for {family['family_id']}")

        for member in family["members"]:
            alert_rows.append(
                {
                    "alert_id": member["alert_id"],
                    "sample_id": member["sample_id"],
                    "family_id": family["family_id"],
                    "implementation_key": decision["implementation_key"],
                    "sink": {
                        "label": member["sink_label"],
                        "function": member["sink_function"],
                        "callee": member["sink_callee"],
                        "site_id": member["sink_site_id"],
                        "instruction_address": member["sink_instruction_address"],
                        "expr": member["sink_expr"],
                    },
                    "result": decision["result"],
                    "confidence": decision["confidence"],
                    "concise_reason": decision["concise_reason"],
                    "propagation_basis": decision["propagation_basis"],
                    "source_refs": decision.get("source_refs", []),
                    "existing_review_reason": member.get("reason"),
                }
            )

    alert_ids = [row["alert_id"] for row in alert_rows]
    if len(alert_ids) != len(set(alert_ids)):
        duplicates = [key for key, count in Counter(alert_ids).items() if count > 1]
        raise SystemExit(f"duplicate Alert IDs: {duplicates}")
    indexed_alert_count = len(index["trupocs"])
    if len(alert_rows) != indexed_alert_count:
        raise SystemExit(
            f"Alert coverage mismatch: {len(alert_rows)} != {indexed_alert_count}"
        )

    result_counts = Counter(row["result"] for row in alert_rows)
    implementation_results = {}
    for decision in decisions:
        key = decision["implementation_key"]
        previous = implementation_results.setdefault(key, decision["result"])
        if previous != decision["result"]:
            raise SystemExit(f"conflicting result for implementation {key}")

    implementation_counts = Counter(implementation_results.values())
    output = {
        "schema_version": "coppertrace.fresh-trupoc-manual-audit.v1",
        "input_index": str(args.index.resolve()),
        "decision_source": str(args.decisions.resolve()),
        "coverage": {
            "indexed_alerts": indexed_alert_count,
            "audited_alerts": len(alert_rows),
            "missing_alerts": 0,
            "duplicate_alerts": 0,
            "coarse_families": len(index["families"]),
            "audited_implementations": len(implementation_results),
        },
        "alert_results": dict(sorted(result_counts.items())),
        "implementation_results": dict(sorted(implementation_counts.items())),
        "alerts": sorted(alert_rows, key=lambda row: (row["sample_id"], row["alert_id"])),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as stream:
        json.dump(output, stream, indent=2, sort_keys=False)
        stream.write("\n")

    print(json.dumps({key: value for key, value in output.items() if key != "alerts"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
