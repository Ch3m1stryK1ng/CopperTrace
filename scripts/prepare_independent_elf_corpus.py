#!/usr/bin/env python3
"""Generate frozen Ghidra facts and Decompiled C for an ELF selection."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import eval_cve_source_mining as source_eval  # noqa: E402


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], log_path: Path) -> None:
    proc = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        "CMD: "
        + " ".join(command)
        + "\n\nSTDOUT:\n"
        + proc.stdout
        + "\nSTDERR:\n"
        + proc.stderr
    )
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(command)}")


def valid_facts(path: Path, binary_hash: str) -> bool:
    if not path.exists():
        return False
    try:
        facts = read_json(path)
    except (OSError, ValueError):
        return False
    return bool(
        str(facts.get("schema_version", "")) == source_eval.GHIDRA_FACT_SCHEMA
        and str(facts.get("binary_sha256", "")) == binary_hash
        and bool(dict(facts.get("capabilities", {}) or {}).get("basic_blocks"))
    )


def prepare_sample(
    sample: dict[str, Any], artifact_root: Path, fingerprint: str
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    sample_id = str(sample["sample_id"])
    binary = Path(str(sample["binary_path"]))
    binary_hash = sha256_path(binary)
    sample_dir = artifact_root / sample_id
    sample_dir.mkdir(parents=True, exist_ok=True)
    generated_facts_path = sample_dir / (
        f"{binary_hash[:20]}-full-{fingerprint[:12]}.program_facts.json"
    )
    generated_corpus_path = sample_dir / "plain_decompiled.c"
    prebuilt_facts = Path(str(sample.get("program_facts_path", "")))
    prebuilt_corpus = Path(str(sample.get("decompiled_c_path", "")))
    reuse_prebuilt = (
        valid_facts(prebuilt_facts, binary_hash) and prebuilt_corpus.is_file()
    )
    facts_path = prebuilt_facts if reuse_prebuilt else generated_facts_path
    corpus_path = prebuilt_corpus if reuse_prebuilt else generated_corpus_path
    try:
        if not reuse_prebuilt and not valid_facts(facts_path, binary_hash):
            run(
                [
                    str(source_eval.GHIDRA_EXPORT_RUNNER),
                    str(binary),
                    str(facts_path),
                ],
                sample_dir / "stage_1_ghidra.log",
            )
        if not reuse_prebuilt:
            run(
                [
                    sys.executable,
                    str(ROOT / "scripts/program_facts_to_corpus.py"),
                    "--program-facts",
                    str(facts_path),
                    "--out",
                    str(corpus_path),
                ],
                sample_dir / "stage_2_corpus.log",
            )
        facts = read_json(facts_path)
        function_count = len(list(facts.get("functions", []) or []))
        # Preserve evaluation metadata (CVE, project and public profile) while
        # replacing only the analysis-artifact fields.  This makes the output
        # directly consumable by run_mini_pipeline.py after an explicit unseal.
        ready = dict(sample)
        ready.update(
            {
                "binary_path": str(binary.resolve()),
                "binary_sha256": binary_hash,
                "program_facts_path": str(facts_path.resolve()),
                "decompiled_c_path": str(corpus_path.resolve()),
                "analysis_status": "PREPARED_FOR_AUTHORIZED_ANALYSIS",
            }
        )
        result = {
            "sample_id": sample_id,
            "status": "OK",
            "binary_sha256": binary_hash,
            "program_facts": str(facts_path),
            "program_facts_sha256": sha256_path(facts_path),
            "decompiled_c": str(corpus_path),
            "decompiled_c_sha256": sha256_path(corpus_path),
            "functions": function_count,
            "artifact_reused": reuse_prebuilt,
        }
        return ready, result
    except Exception as exc:
        return None, {"sample_id": sample_id, "status": "FAILED", "reason": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--out-manifest", required=True, type=Path)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Number of isolated Ghidra exports to run concurrently.",
    )
    args = parser.parse_args()

    selection = read_json(args.selection)
    selected_ids = set(args.sample)
    samples = [
        dict(row)
        for row in list(selection.get("samples", []) or [])
        if not selected_ids or str(row.get("sample_id", "")) in selected_ids
    ]
    fingerprint = source_eval.ghidra_tool_fingerprint()
    if args.jobs < 1 or args.jobs > 8:
        parser.error("--jobs must be between 1 and 8")
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        prepared = list(
            executor.map(
                lambda sample: prepare_sample(sample, args.artifact_root, fingerprint),
                samples,
            )
        )
    ready_samples = [ready for ready, _ in prepared if ready is not None]
    results = [result for _, result in prepared]

    manifest = {
        "schema_version": "ct-mini-independent-ready-manifest-v1",
        "description": "Hash-disjoint ELF corpus with frozen Ghidra artifacts.",
        "selection_manifest": str(args.selection.resolve()),
        "selection_manifest_sha256": sha256_path(args.selection),
        "samples": ready_samples,
    }
    summary = {
        "schema_version": "ct-mini-independent-preparation-v1",
        "selection_manifest": str(args.selection.resolve()),
        "ghidra_fact_schema": source_eval.GHIDRA_FACT_SCHEMA,
        "ghidra_tool_fingerprint": fingerprint,
        "parallel_jobs": args.jobs,
        "samples_requested": len(samples),
        "samples_ok": len(ready_samples),
        "samples_failed": len(samples) - len(ready_samples),
        "results": results,
    }
    write_json(args.out_manifest, manifest)
    write_json(args.summary, summary)
    print(json.dumps(summary, indent=2))
    return 0 if len(ready_samples) == len(samples) else 1


if __name__ == "__main__":
    raise SystemExit(main())
