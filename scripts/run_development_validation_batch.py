#!/usr/bin/env python3
"""Run blind deterministic validation for each queued reviewed TruPoC."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from validation_common import load_json, reviewed_validation_entries, write_json


INCONCLUSIVE = "INCONCLUSIVE"


def failure_result(alert_id: str, reason: str, detail: str) -> dict[str, Any]:
    return {
        "schema_version": "ct-mini-validation-result-v1",
        "alert_id": alert_id,
        "plan_id": "",
        "result_class": INCONCLUSIVE,
        "reason_code": reason,
        "detail": detail,
        "policy": {
            "known_cve_input_used": False,
            "source_boundary_injection_required": True,
            "sink_hit_without_fault_is_inconclusive": True,
            "fuzzware_modified": False,
        },
        "variants": [],
    }


def useful_error(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    preferred = [
        line
        for line in lines
        if line.startswith(("ValueError:", "RuntimeError:", "FileNotFoundError:"))
    ]
    return (preferred[-1] if preferred else (lines[-1] if lines else "runner failed"))[
        :1000
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--reviewed-alerts", required=True, type=Path)
    parser.add_argument("--planning-results", required=True, type=Path)
    parser.add_argument("--validation-dir", required=True, type=Path)
    parser.add_argument("--rehosting-dir", required=True, type=Path)
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--fuzzware-root", required=True, type=Path)
    parser.add_argument("--instruction-limit", type=int, default=3_000_000)
    parser.add_argument("--consumption-timeout", type=int, default=1_000_000)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--readiness-manifest", type=Path)
    args = parser.parse_args()

    queued = reviewed_validation_entries(load_json(args.reviewed_alerts))
    planning = {
        int(row["rank"]): row
        for row in load_json(args.planning_results).get("results", []) or []
    }
    readiness = load_json(args.readiness_manifest) if args.readiness_manifest else {}
    base_input = (
        Path(str(readiness["readiness_input"]))
        if readiness
        else Path(
            (args.rehosting_dir / "baseline-validation/base_input.path")
            .read_text(encoding="utf-8")
            .strip()
        )
    )
    baseline_mmio = (
        Path(str(readiness["baseline_mmio"]))
        if readiness
        else args.rehosting_dir / "baseline-validation/mmio.txt"
    )
    baseline_bb = (
        Path(str(readiness["baseline_bb"]))
        if readiness
        else args.rehosting_dir / "baseline-validation/bb.txt"
    )
    runner = Path(__file__).resolve().parent / "run_fuzzware_validation.py"
    results: list[dict[str, Any]] = []

    for queue_row, selection in queued:
        rank = int(queue_row["queue_rank"])
        alert_id = str(selection["alert_id"])
        alert_dir = args.validation_dir / f"alert-{rank:02d}"
        result_path = alert_dir / "validation_result.json"
        plan = alert_dir / "execution_plan.json"
        manifest = alert_dir / "compiled/manifest.json"
        if not plan.exists() or not manifest.exists():
            detail = str(planning.get(rank, {}).get("reason", "planning failed"))
            result = failure_result(alert_id, "PLANNING_FAILED", detail)
            write_json(result_path, result)
            results.append({"rank": rank, **result})
            print(json.dumps(results[-1], sort_keys=True), flush=True)
            continue

        config = (
            Path(str(readiness["config"]))
            if readiness
            else args.rehosting_dir
            / "fuzzware-bootstrap-v1/main001"
            / f"config.validation.alert-{rank:02d}.yml"
        )
        command = [
            sys.executable,
            str(runner),
            "--fuzzware-root",
            str(args.fuzzware_root),
            "--target-root",
            str(args.target_root),
            "--binary",
            str(args.rehosting_dir / "firmware.elf"),
            "--config",
            str(config),
            "--evidence",
            str(alert_dir / "evidence.json"),
            "--plan",
            str(plan),
            "--semantic-manifest",
            str(manifest),
            "--base-input",
            str(base_input),
            "--baseline-mmio",
            str(baseline_mmio),
            "--baseline-bb",
            str(baseline_bb),
            "--output-dir",
            str(alert_dir / "runtime"),
            "--result",
            str(result_path),
            "--instruction-limit",
            str(args.instruction_limit),
            "--consumption-timeout",
            str(args.consumption_timeout),
            "--timeout-seconds",
            str(args.timeout_seconds),
        ]
        completed = subprocess.run(command, capture_output=True, text=True)
        (alert_dir / "validation_runner.log").write_text(
            "COMMAND: "
            + " ".join(command)
            + "\n\nSTDOUT:\n"
            + completed.stdout
            + "\nSTDERR:\n"
            + completed.stderr,
            encoding="utf-8",
        )
        if completed.returncode != 0 or not result_path.exists():
            result = failure_result(
                alert_id,
                "VALIDATION_ADAPTER_FAILED",
                useful_error(completed.stderr + "\n" + completed.stdout),
            )
            write_json(result_path, result)
        else:
            result = load_json(result_path)
        results.append({"rank": rank, **result})
        print(
            json.dumps(
                {
                    "rank": rank,
                    "alert_id": alert_id,
                    "result_class": result["result_class"],
                    "reason_code": result["reason_code"],
                },
                sort_keys=True,
            ),
            flush=True,
        )

    counts: dict[str, int] = {}
    reasons: dict[str, int] = {}
    for row in results:
        counts[str(row["result_class"])] = counts.get(str(row["result_class"]), 0) + 1
        reasons[str(row["reason_code"])] = reasons.get(str(row["reason_code"]), 0) + 1
    write_json(
        args.validation_dir / "validation_summary.json",
        {
            "schema_version": "ct-mini-development-validation-summary-v2",
            "sample_id": args.sample_id,
            "queued_trupoc_count": len(queued),
            "counts": counts,
            "reason_counts": reasons,
            "results": results,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
