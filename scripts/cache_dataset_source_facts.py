#!/usr/bin/env python3
"""Precompute blind Ghidra Source-Miner facts for a dataset manifest."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from eval_cve_source_mining import prepare_program_facts  # noqa: E402


def task(sample: dict[str, Any], cache: Path, logs: Path) -> dict[str, Any]:
    sample_id = str(sample.get("sample_id", ""))
    decompiled = Path(str(sample.get("decompiled_c_path", "")))
    result = prepare_program_facts(
        sample=sample,
        decompiled=decompiled,
        cache_dir=cache,
        out_dir=logs / sample_id,
    )
    return {"sample_id": sample_id, **result}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=ROOT / "datasets/sink_mining_main.json", type=Path)
    parser.add_argument("--cache", default=ROOT / "artifacts/ghidra_source_facts_cache", type=Path)
    parser.add_argument("--logs", default=ROOT / "artifacts/ghidra_source_facts_runs", type=Path)
    parser.add_argument("--jobs", default=3, type=int)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(errors="replace"))
    samples = list(manifest.get("samples", []) or [])

    # The same binary/corpus can represent multiple public CVEs. Export it once;
    # this grouping is based on input paths, never expected source profiles.
    unique: dict[tuple[str, str], dict[str, Any]] = {}
    aliases: dict[tuple[str, str], list[str]] = {}
    for sample in samples:
        key = (str(sample.get("binary_path", "")), str(sample.get("decompiled_c_path", "")))
        unique.setdefault(key, sample)
        aliases.setdefault(key, []).append(str(sample.get("sample_id", "")))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as executor:
        future_keys = {
            executor.submit(task, sample, args.cache, args.logs): key
            for key, sample in unique.items()
        }
        for future in concurrent.futures.as_completed(future_keys):
            key = future_keys[future]
            try:
                row = future.result()
            except Exception as exc:  # noqa: BLE001
                row = {
                    "sample_id": aliases[key][0],
                    "returncode": 1,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            row["sample_aliases"] = aliases[key]
            results.append(row)
            print(json.dumps(row, sort_keys=True), flush=True)

    summary = {
        "schema_version": "ct-mini-source-facts-cache-run-v1",
        "manifest": str(args.manifest),
        "sample_count": len(samples),
        "unique_input_count": len(unique),
        "success_count": sum(1 for row in results if row.get("returncode") == 0),
        "failure_count": sum(1 for row in results if row.get("returncode") != 0),
        "results": sorted(results, key=lambda row: str(row.get("sample_id", ""))),
    }
    args.logs.mkdir(parents=True, exist_ok=True)
    (args.logs / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return 0 if summary["failure_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
