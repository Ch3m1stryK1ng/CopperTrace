#!/usr/bin/env python3
"""Build a callsite-diverse validation queue from reviewed TruPoCs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _alert(row: dict[str, Any]) -> dict[str, Any]:
    return dict(row.get("alert", {}) or {})


def _alert_id(row: dict[str, Any]) -> str:
    return str(_alert(row).get("alert_id", "") or "")


def _reference_rank(row: dict[str, Any]) -> int:
    value = _alert(row).get("rank")
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 2**31 - 1


def _sink_callsites(row: dict[str, Any]) -> tuple[str, ...]:
    alert = _alert(row)
    sites = {
        str(value)
        for value in list(alert.get("represented_sink_boundary_site_ids", []) or [])
        if str(value)
    }
    for key in ("sink_boundary_site_id", "sink_effect_site_id"):
        value = str(alert.get(key, "") or "")
        if value:
            sites.add(value)
            if key == "sink_boundary_site_id":
                break
    if not sites:
        sites.add(f"unbound:{_alert_id(row)}")
    return tuple(sorted(sites))


def _queue_entry(
    row: dict[str, Any], *, queue_rank: int, queue_round: str
) -> dict[str, Any]:
    return {
        "queue_rank": queue_rank,
        "queue_round": queue_round,
        "alert_id": _alert_id(row),
        "sink_callsite_ids": list(_sink_callsites(row)),
        "a2_reference_rank": _reference_rank(row),
    }


def build_validation_queue(
    trupocs: list[dict[str, Any]], *, limit: int
) -> list[dict[str, Any]]:
    """Select diverse callsites first, then additional lineages.

    A2 rank is only a stable reference tie-breaker inside each round. The input
    TruPoCs are never modified and rows outside the queue remain reported.
    """

    if limit <= 0:
        return []
    ordered = sorted(trupocs, key=lambda row: (_reference_rank(row), _alert_id(row)))
    selected: list[tuple[dict[str, Any], str]] = []
    selected_ids: set[str] = set()
    covered_callsites: set[str] = set()

    for row in ordered:
        alert_id = _alert_id(row)
        sites = set(_sink_callsites(row))
        if alert_id in selected_ids or not (sites - covered_callsites):
            continue
        selected.append((row, "DISTINCT_SINK_CALLSITE"))
        selected_ids.add(alert_id)
        covered_callsites.update(sites)
        if len(selected) >= limit:
            break

    if len(selected) < limit:
        for row in ordered:
            alert_id = _alert_id(row)
            if alert_id in selected_ids:
                continue
            selected.append((row, "ADDITIONAL_SOURCE_LINEAGE"))
            selected_ids.add(alert_id)
            if len(selected) >= limit:
                break

    return [
        _queue_entry(row, queue_rank=index, queue_round=queue_round)
        for index, (row, queue_round) in enumerate(selected, start=1)
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--reviewed-alerts", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=20)
    args = parser.parse_args()

    reviewed = json.loads(args.reviewed_alerts.read_text(errors="replace"))
    result = {
        "schema_version": "ct-mini-validation-queue-v1",
        "policy": {
            "top_k_after_llm_review": True,
            "distinct_sink_callsites_first": True,
            "a2_rank_is_reference_tiebreaker_only": True,
        },
        "validation_queue": build_validation_queue(
            list(reviewed.get("trupocs", []) or []),
            limit=max(0, args.limit),
        ),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
