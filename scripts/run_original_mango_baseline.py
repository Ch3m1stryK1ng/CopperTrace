#!/usr/bin/env python3
"""Run the frozen Original Mango image over unique ELFs from CVE manifests."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_IMAGE = (
    "cl4sm/operation-mango@"
    "sha256:2e4201cf779ff79ac5d2b253908db0bbf5e678a36cc0fa1d4fb1ff90bbea701e"
)
DEFAULT_CATEGORIES = ("memcpy", "overflow", "strcat", "strfmt")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_inventory(manifests: list[Path]) -> list[dict[str, Any]]:
    by_hash: dict[str, dict[str, Any]] = {}
    for manifest in manifests:
        payload = read_json(manifest)
        for sample in list(payload.get("samples", []) or []):
            binary = Path(str(sample.get("binary_path", ""))).resolve()
            if not binary.is_file():
                raise FileNotFoundError(f"missing binary for {sample.get('sample_id')}: {binary}")
            digest = sha256_path(binary)
            declared = str(sample.get("sha256", ""))
            if declared and declared != digest:
                raise ValueError(f"SHA-256 mismatch for {binary}: {declared} != {digest}")
            row = by_hash.setdefault(
                digest,
                {
                    "binary_sha256": digest,
                    "binary_path": str(binary),
                    "byte_size": binary.stat().st_size,
                    "sample_records": [],
                },
            )
            if row["binary_path"] != str(binary):
                row.setdefault("equivalent_binary_paths", []).append(str(binary))
            row["sample_records"].append(
                {
                    "manifest": str(manifest.resolve()),
                    "sample_id": str(sample.get("sample_id", "")),
                    "cve": str(sample.get("cve", sample.get("cve_id", ""))),
                    "expected_profile_path": str(sample.get("expected_profile_path", "")),
                }
            )
    return sorted(by_hash.values(), key=lambda row: row["binary_sha256"])


def result_path(job_dir: Path, category: str) -> Path:
    return job_dir / f"{category}_results.json"


def completed_result(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        payload = read_json(path)
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(payload.get("closures", []), list) and "error" in payload


def run_job(
    *,
    image: str,
    binary: Path,
    binary_sha256: str,
    category: str,
    output_root: Path,
    max_depth: int,
    rda_timeout: int,
    wall_timeout: int,
    memory: str,
    cpus: str,
    resume: bool,
) -> dict[str, Any]:
    job_dir = (output_root / "per_elf" / binary_sha256[:12] / category).resolve()
    job_dir.mkdir(parents=True, exist_ok=True)
    result = result_path(job_dir, category)
    status_path = job_dir / "run_status.json"
    if resume and completed_result(result):
        payload = read_json(result)
        return {
            "binary_sha256": binary_sha256,
            "category": category,
            "status": "COMPLETED_REUSED",
            "closure_count": len(list(payload.get("closures", []) or [])),
            "error": payload.get("error"),
            "result_path": str(result),
        }

    command = [
        "docker",
        "run",
        "--rm",
        "--cpus",
        cpus,
        "--memory",
        memory,
        "--volume",
        f"{binary.resolve()}:/input/firmware.elf:ro",
        "--volume",
        f"{job_dir}:/results",
        image,
        "mango",
        "/input/firmware.elf",
        "--results",
        "/results",
        "--category",
        category,
        "--max-depth",
        str(max_depth),
        "--rda-timeout",
        str(rda_timeout),
        "--workers",
        "1",
        "--disable-progress",
        "--concise",
    ]
    started = utc_now()
    started_clock = time.monotonic()
    status = "ANALYSIS_FAILED"
    return_code: int | None = None
    failure = ""
    with (job_dir / "runner.log").open("w") as log:
        log.write("COMMAND: " + " ".join(command) + "\n")
        log.flush()
        try:
            process = subprocess.run(
                command,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=wall_timeout,
                check=False,
                text=True,
            )
            return_code = process.returncode
            if completed_result(result):
                status = "COMPLETED"
            else:
                failure = f"docker_exit_{process.returncode}_without_result"
        except subprocess.TimeoutExpired:
            status = "TIMEOUT"
            failure = f"wall_timeout_{wall_timeout}s"
        except Exception as exc:  # Preserve infrastructure failures as evidence.
            failure = f"runner_exception:{type(exc).__name__}:{exc}"

    elapsed = time.monotonic() - started_clock
    result_payload: dict[str, Any] = {}
    if completed_result(result):
        result_payload = read_json(result)
    row = {
        "schema_version": "ct-mini-original-mango-run-v1",
        "binary_sha256": binary_sha256,
        "binary_path": str(binary),
        "category": category,
        "status": status,
        "failure": failure,
        "return_code": return_code,
        "started_at": started,
        "finished_at": utc_now(),
        "wall_seconds": elapsed,
        "closure_count": len(list(result_payload.get("closures", []) or [])),
        "mango_error": result_payload.get("error"),
        "result_path": str(result),
        "command": command,
    }
    write_json(status_path, row)
    return row


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--category", action="append", choices=DEFAULT_CATEGORIES)
    parser.add_argument("--max-depth", default=8, type=int)
    parser.add_argument("--rda-timeout", default=300, type=int)
    parser.add_argument("--wall-timeout", default=3600, type=int)
    parser.add_argument("--max-concurrency", default=2, type=int)
    parser.add_argument("--memory", default="12g")
    parser.add_argument("--cpus", default="1")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--inventory-only", action="store_true")
    args = parser.parse_args()

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifests = [path.resolve() for path in args.manifest]
    inventory = build_inventory(manifests)
    categories = tuple(args.category or DEFAULT_CATEGORIES)
    campaign = {
        "schema_version": "ct-mini-original-mango-campaign-v1",
        "created_at": utc_now(),
        "manifests": [str(path) for path in manifests],
        "manifest_sha256": {str(path): sha256_path(path) for path in manifests},
        "image": args.image,
        "categories": list(categories),
        "max_depth": args.max_depth,
        "rda_timeout_seconds_per_trace": args.rda_timeout,
        "wall_timeout_seconds_per_category": args.wall_timeout,
        "max_concurrency": args.max_concurrency,
        "container_memory": args.memory,
        "container_cpus": args.cpus,
        "unique_elf_count": len(inventory),
        "cve_record_count": sum(len(row["sample_records"]) for row in inventory),
        "inventory": inventory,
    }
    write_json(output / "campaign.json", campaign)
    if args.inventory_only:
        return 0

    jobs_total = len(inventory) * len(categories)
    results: list[dict[str, Any]] = []
    lock = threading.Lock()

    def run_binary(row: dict[str, Any]) -> list[dict[str, Any]]:
        # Keep the four categories sequential for one ELF.  This preserves the
        # one-CPU-per-ELF resource contract while still allowing different ELF
        # images to run in parallel.
        binary_results: list[dict[str, Any]] = []
        for category in categories:
            binary_results.append(
                run_job(
                    image=args.image,
                    binary=Path(row["binary_path"]),
                    binary_sha256=row["binary_sha256"],
                    category=category,
                    output_root=output,
                    max_depth=max(1, args.max_depth),
                    rda_timeout=max(1, args.rda_timeout),
                    wall_timeout=max(1, args.wall_timeout),
                    memory=args.memory,
                    cpus=args.cpus,
                    resume=args.resume,
                )
            )
        return binary_results

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, args.max_concurrency)
    ) as executor:
        future_map = {
            executor.submit(run_binary, row): row["binary_sha256"]
            for row in inventory
        }
        for future in concurrent.futures.as_completed(future_map):
            binary_sha256 = future_map[future]
            try:
                completed_rows = future.result()
            except Exception as exc:
                completed_rows = [
                    {
                        "binary_sha256": binary_sha256,
                        "category": "all",
                        "status": "RUNNER_FAILED",
                        "failure": f"{type(exc).__name__}:{exc}",
                    }
                ]
            with lock:
                results.extend(completed_rows)
                counts: dict[str, int] = {}
                for item in results:
                    key = str(item.get("status", ""))
                    counts[key] = counts.get(key, 0) + 1
                write_json(
                    output / "run_summary.json",
                    {
                        "schema_version": "ct-mini-original-mango-run-summary-v1",
                        "updated_at": utc_now(),
                        "jobs_total": jobs_total,
                        "jobs_finished": len(results),
                        "status_counts": counts,
                        "runs": sorted(
                            results,
                            key=lambda item: (
                                str(item.get("binary_sha256", "")),
                                str(item.get("category", "")),
                            ),
                        ),
                    },
                )
                statuses = ", ".join(
                    f"{row.get('category')}={row.get('status')}"
                    for row in completed_rows
                )
                print(f"[{len(results)}/{jobs_total}] {binary_sha256[:12]}: {statuses}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
