#!/usr/bin/env python3
"""Recover the actual planner exception from stored batch logs."""

from __future__ import annotations

import argparse
from pathlib import Path

from validation_common import load_json, write_json


def planner_error(log_text: str) -> str:
    candidates: list[str] = []
    for line in log_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(("ValueError:", "TypeError:", "RuntimeError:")):
            continue
        if "Event loop is closed" in stripped:
            continue
        candidates.append(stripped)
    return candidates[0][:1000] if candidates else "planner_failed_without_primary_exception"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--planning-results", required=True, type=Path)
    parser.add_argument("--validation-dir", required=True, type=Path)
    args = parser.parse_args()

    document = load_json(args.planning_results)
    for row in document.get("results", []) or []:
        if row.get("status") != "PLANNING_FAILED":
            continue
        rank = int(row["rank"])
        log_path = args.validation_dir / f"alert-{rank:02d}/planner.log"
        if log_path.exists():
            row["reason"] = planner_error(log_path.read_text(encoding="utf-8"))
    write_json(args.planning_results, document)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
