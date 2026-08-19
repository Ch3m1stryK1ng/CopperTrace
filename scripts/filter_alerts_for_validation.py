#!/usr/bin/env python3
"""Select unchanged Static Alerts for bounded execution validation."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from validation_common import (
    SOURCE_REACHED_STATUSES,
    SUPPORTED_SINK_LABELS,
    load_json,
    reached_source_ids,
    sha256_file,
    source_backed_callsite_ids,
    write_json,
)


def filter_alerts(
    chains_doc: dict[str, Any],
    sinks_doc: dict[str, Any],
    *,
    max_selected: int,
) -> dict[str, Any]:
    sink_rows = {
        str(row.get("id", "")): row
        for row in sinks_doc.get("sink_startpoints", []) or []
    }
    selected: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []

    ranked: list[tuple[tuple[int, int, int, str], dict[str, Any], dict[str, Any]]] = []
    for chain in chains_doc.get("chains", []) or []:
        alert_id = str(chain.get("chain_id", ""))
        sink_id = str(chain.get("sink_id", ""))
        sink = sink_rows.get(sink_id)
        if not alert_id or sink is None:
            contradictions.append(
                {
                    "alert_id": alert_id,
                    "reason": "ALERT_ENDPOINT_NOT_BOUND_TO_SINK_ARTIFACT",
                }
            )
            continue
        label = str(chain.get("sink_label") or sink.get("label") or "")
        if label not in SUPPORTED_SINK_LABELS:
            deferred.append(
                {"alert_id": alert_id, "reason": "SINK_OUTSIDE_VALIDATION_V1"}
            )
            continue
        status = str(chain.get("status", ""))
        if status not in SOURCE_REACHED_STATUSES:
            deferred.append(
                {"alert_id": alert_id, "reason": "SOURCE_NOT_REACHED_BY_STATIC_ALERT"}
            )
            continue
        source_ids = reached_source_ids(chain)
        if not source_ids:
            deferred.append(
                {"alert_id": alert_id, "reason": "SOURCE_ID_NOT_BOUND"}
            )
            continue
        deterministic = int(status == "SOURCE_REACHED_DETERMINISTIC")
        exact_paths = sum(
            1
            for parameter in chain.get("parameter_results", []) or []
            for path in parameter.get("paths", []) or []
            if path.get("path_precision") == "EXACT"
        )
        blockers = sum(
            len(parameter.get("blockers", []) or [])
            for parameter in chain.get("parameter_results", []) or []
        )
        rank = (-deterministic, -exact_paths, blockers, alert_id)
        ranked.append((rank, chain, sink))

    ranked.sort(key=lambda item: item[0])
    for index, (_, chain, sink) in enumerate(ranked):
        alert_id = str(chain["chain_id"])
        if index >= max_selected:
            deferred.append({"alert_id": alert_id, "reason": "EXECUTION_BUDGET"})
            continue
        effect_site = str(chain.get("sink_site_id") or sink.get("effect_site_id") or "")
        selected.append(
            {
                "alert_id": alert_id,
                "sink_id": str(chain.get("sink_id", "")),
                "sink_site_id": effect_site,
                "source_ids": reached_source_ids(chain),
                "source_backed_callsite_ids": source_backed_callsite_ids(chain),
                "reason": "SOURCE_BACKED_SUPPORTED_SINK",
            }
        )

    return {
        "schema_version": "ct-mini-validation-filter-v1",
        "policy": {
            "ranking_only": True,
            "low_rank_is_deferred": True,
            "runtime_failure_is_not_non_poc": True,
        },
        "counts": {
            "input_alerts": len(chains_doc.get("chains", []) or []),
            "selected": len(selected),
            "deferred": len(deferred),
            "deterministic_contradictions": len(contradictions),
        },
        "selected": selected,
        "deferred": sorted(deferred, key=lambda row: row["alert_id"]),
        "deterministic_contradictions": contradictions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chains", required=True, type=Path)
    parser.add_argument("--sinks", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--max-selected", type=int, default=8)
    args = parser.parse_args()
    result = filter_alerts(
        load_json(args.chains),
        load_json(args.sinks),
        max_selected=max(1, args.max_selected),
    )
    result["inputs"] = {
        "chains_sha256": sha256_file(args.chains),
        "sinks_sha256": sha256_file(args.sinks),
    }
    write_json(args.out, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
