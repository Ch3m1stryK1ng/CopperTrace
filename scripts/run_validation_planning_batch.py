#!/usr/bin/env python3
"""Run the Execution Planner over one post-review validation queue."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

from validation_common import load_json, reviewed_validation_entries, write_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-dir", required=True, type=Path)
    parser.add_argument("--reviewed-alerts", required=True, type=Path)
    parser.add_argument("--program-facts", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--binary-sha256", required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--skip-existing", action="store_true")
    args = parser.parse_args()

    script = Path(__file__).resolve().parent / "plan_alert_execution.py"
    queued = reviewed_validation_entries(load_json(args.reviewed_alerts))
    args.out_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, object]] = []

    for queue_row, selection in queued:
        rank = int(queue_row["queue_rank"])
        alert_id = str(selection["alert_id"])
        alert_dir = args.out_dir / f"alert-{rank:02d}"
        alert_dir.mkdir(parents=True, exist_ok=True)
        plan_path = alert_dir / "execution_plan.json"
        log_path = alert_dir / "planner.log"
        if args.skip_existing and plan_path.exists():
            results.append(
                {
                    "rank": rank,
                    "alert_id": alert_id,
                    "status": "PLAN_READY",
                    "reason": "existing_verified_plan",
                    "duration_seconds": 0.0,
                }
            )
            continue

        command = [
            sys.executable,
            str(script),
            "--reviewed-alerts",
            str(args.reviewed_alerts),
            "--chains",
            str(args.sample_dir / "chains.json"),
            "--sinks",
            str(args.sample_dir / "sinks.json"),
            "--sources",
            str(args.sample_dir / "sources.json"),
            "--channel-graph",
            str(args.sample_dir / "channel_graph.json"),
            "--program-facts",
            str(args.program_facts),
            "--binary",
            str(args.binary),
            "--functions-jsonl",
            str(args.sample_dir / "functions.jsonl"),
            "--binary-sha256",
            args.binary_sha256,
            "--alert-id",
            alert_id,
            "--model",
            args.model,
            "--evidence-out",
            str(alert_dir / "evidence.json"),
            "--raw-response-out",
            str(alert_dir / "response_LLM.txt"),
            "--out",
            str(plan_path),
        ]
        started = time.monotonic()
        completed = subprocess.run(command, capture_output=True, text=True)
        duration = round(time.monotonic() - started, 3)
        log_path.write_text(
            "COMMAND: " + " ".join(command) + "\n\nSTDOUT:\n"
            + completed.stdout
            + "\nSTDERR:\n"
            + completed.stderr,
            encoding="utf-8",
        )
        if completed.returncode == 0 and plan_path.exists():
            status = "PLAN_READY"
            reason = "verified_execution_plan"
        else:
            status = "PLANNING_FAILED"
            error_lines = [
                line.strip()
                for line in (completed.stderr + "\n" + completed.stdout).splitlines()
                if line.strip()
            ]
            reason = error_lines[-1][:500] if error_lines else "planner_failed"
        results.append(
            {
                "rank": rank,
                "alert_id": alert_id,
                "status": status,
                "reason": reason,
                "duration_seconds": duration,
            }
        )
        write_json(
            args.out_dir / "planning_results.json",
            {
                "schema_version": "ct-mini-planning-batch-v2",
                "model": args.model,
                "queued_trupocs": len(queued),
                "results": results,
            },
        )
        print(json.dumps(results[-1], sort_keys=True), flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
