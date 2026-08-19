#!/usr/bin/env python3
"""Generate Sink Miner v2 audit artifacts for an independent firmware corpus."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import eval_cve_source_mining as source_eval  # noqa: E402


DEFAULT_MANIFEST = ROOT / "datasets/sink_heuristic_audit_manifest.json"
SINK_REGISTRY = ROOT / "registries/sink_patterns.v2.json"
SINK_ANALYZERS = (
    ROOT / "scripts/build_sink_artifacts.py",
    ROOT / "scripts/deterministic_sink_engine.py",
    ROOT / "scripts/body_sink_heuristics.py",
    ROOT / "scripts/high_pcode_loop_analysis.py",
    ROOT / "scripts/parser_oob_read_heuristic.py",
)


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def valid_facts(path: Path, binary: Path) -> bool:
    if not path.exists():
        return False
    try:
        facts = read_json(path)
    except (OSError, ValueError):
        return False
    return bool(
        str(facts.get("schema_version", "")) == source_eval.GHIDRA_FACT_SCHEMA
        and str(facts.get("binary_sha256", "")) == sha256_path(binary)
        and bool(dict(facts.get("capabilities", {}) or {}).get("basic_blocks"))
    )


def compatible_high_pcode_facts(path: Path, binary: Path) -> bool:
    """Accept an older fact schema only when the audit-required IR is present."""
    if not path.exists():
        return False
    try:
        facts = read_json(path)
    except (OSError, ValueError):
        return False
    capabilities = dict(facts.get("capabilities", {}) or {})
    return bool(
        str(facts.get("binary_sha256", "")) == sha256_path(binary)
        and capabilities.get("high_pcode")
        and capabilities.get("ssa_def_use")
        and capabilities.get("basic_blocks")
        and capabilities.get("cfg_edges")
    )


def select_facts_path(sample_dir: Path, preferred: Path, binary: Path) -> Path:
    if valid_facts(preferred, binary):
        return preferred
    candidates = sorted(
        sample_dir.glob("*-full-*.program_facts.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    for candidate in candidates:
        if compatible_high_pcode_facts(candidate, binary):
            return candidate
    return preferred


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument(
        "--heuristic-method",
        action="append",
        default=[],
        help=(
            "Audit one named body-derived heuristic in addition to the "
            "registry's default-enabled methods. Repeat for multiple methods."
        ),
    )
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--with-source-miner",
        action="store_true",
        help=(
            "Run the full Source Miner before Sink auditing. Disabled by "
            "default because the independent audit measures Sink semantics; "
            "without Source evidence, MMIO producer loops remain conservative "
            "false-positive candidates for manual review."
        ),
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=ROOT / "artifacts/sink_heuristic_audit_v2/run_summary.json",
    )
    args = parser.parse_args()

    manifest = read_json(args.manifest)
    selected = set(args.sample)
    samples = [
        dict(row)
        for row in list(manifest.get("samples", []) or [])
        if not selected or str(row.get("sample_id", "")) in selected
    ]
    results: list[dict[str, Any]] = []
    fingerprint = source_eval.ghidra_tool_fingerprint()

    for sample in samples:
        sample_id = str(sample.get("sample_id", ""))
        binary = Path(str(sample.get("binary_path", "")))
        sinks_path = Path(str(sample.get("sinks_path", "")))
        if not sinks_path.is_absolute():
            sinks_path = ROOT / sinks_path
        sample_dir = sinks_path.parent
        sample_dir.mkdir(parents=True, exist_ok=True)
        preferred_facts_path = sample_dir / (
            f"{sha256_path(binary)[:20]}-full-{fingerprint[:12]}.program_facts.json"
        )
        facts_path = select_facts_path(sample_dir, preferred_facts_path, binary)
        corpus_path = sample_dir / "plain_decompiled.c"
        sources_path = sample_dir / "sources.json"
        source_compat = sample_dir / "source_unconfirmed.json"
        sink_compat = sample_dir / "sink_unconfirmed.json"

        try:
            if args.force or not compatible_high_pcode_facts(facts_path, binary):
                facts_path = preferred_facts_path
                run(
                    [
                        str(source_eval.GHIDRA_EXPORT_RUNNER),
                        str(binary),
                        str(facts_path),
                    ],
                    sample_dir / "stage_1_ghidra.log",
                )
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
            if args.with_source_miner:
                run(
                    [
                        sys.executable,
                        str(ROOT / "scripts/build_source_artifacts.py"),
                        "--input",
                        str(corpus_path),
                        "--elf",
                        str(binary),
                        "--program-facts",
                        str(facts_path),
                        "--sources-json",
                        str(sources_path),
                        "--source-unconfirmed-json",
                        str(source_compat),
                    ],
                    sample_dir / "stage_3_sources.log",
                )
            sink_command = [
                sys.executable,
                str(ROOT / "scripts/build_sink_artifacts.py"),
                "--input",
                str(corpus_path),
                "--elf",
                str(binary),
                "--program-facts",
                str(facts_path),
                "--sinks-json",
                str(sinks_path),
                "--sink-unconfirmed-json",
                str(sink_compat),
                "--audit-heuristics",
            ]
            if args.with_source_miner:
                sink_command.extend(["--sources-json", str(sources_path)])
            for method in args.heuristic_method:
                sink_command.extend(["--heuristic-method", str(method)])
            run(
                sink_command,
                sample_dir / "stage_4_sinks.log",
            )
            sinks = read_json(sinks_path)
            facts_document = read_json(facts_path)
            results.append(
                {
                    "sample_id": sample_id,
                    "status": "OK",
                    "binary_sha256": sha256_path(binary),
                    "facts": str(facts_path),
                    "facts_schema_version": str(
                        facts_document.get("schema_version", "")
                    ),
                    "program_facts_sha256": sha256_path(facts_path),
                    "sinks": str(sinks_path),
                    "sinks_sha256": sha256_path(sinks_path),
                    "counts": dict(sinks.get("counts", {}) or {}),
                }
            )
        except Exception as exc:
            results.append(
                {"sample_id": sample_id, "status": "FAILED", "reason": str(exc)}
            )

    summary = {
        "schema_version": "ct-mini-sink-heuristic-audit-run-v1",
        "manifest": str(args.manifest),
        "ghidra_fact_schema": source_eval.GHIDRA_FACT_SCHEMA,
        "compatible_fact_policy": (
            "binary hash + High P-code + SSA def-use + basic blocks + CFG edges"
        ),
        "ghidra_tool_fingerprint": fingerprint,
        "source_evidence_mode": (
            "full_source_miner"
            if args.with_source_miner
            else "omitted_conservative_sink_only_audit"
        ),
        "requested_heuristic_methods": sorted(set(args.heuristic_method)),
        "provenance": {
            "manifest_sha256": sha256_path(args.manifest),
            "sink_registry": str(SINK_REGISTRY),
            "sink_registry_sha256": sha256_path(SINK_REGISTRY),
            "analyzer_sha256": {
                str(path.relative_to(ROOT)): sha256_path(path)
                for path in SINK_ANALYZERS
            },
        },
        "samples_requested": len(samples),
        "samples_ok": sum(row["status"] == "OK" for row in results),
        "samples_failed": sum(row["status"] != "OK" for row in results),
        "results": results,
    }
    output = args.summary if args.summary.is_absolute() else ROOT / args.summary
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    return 0 if summary["samples_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
