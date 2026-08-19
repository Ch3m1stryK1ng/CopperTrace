#!/usr/bin/env python3
"""Assemble and verify canonical public-CVE Development/Evaluation manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def prepared_index(path: Path) -> dict[str, dict[str, Any]]:
    return {
        str(row["sample_id"]): dict(row)
        for row in list(read_json(path).get("samples", []) or [])
    }


def enrich_binary(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    binary = Path(str(result["binary_path"]))
    if not binary.is_file():
        raise ValueError(f"missing ELF: {binary}")
    profile = Path(str(result["expected_profile_path"]))
    if not profile.is_file():
        raise ValueError(f"missing public profile: {profile}")
    result["sha256"] = sha256(binary)
    result["byte_size"] = binary.stat().st_size
    result["elf_format"] = (
        "ELF32 ARM EABI5, statically linked, debug_info, not stripped"
    )
    profile_hash = str(read_json(profile).get("binary_sha256", ""))
    if profile_hash != result["sha256"]:
        raise ValueError(
            f"profile binary hash mismatch for {result['sample_id']}: "
            f"{profile_hash} != {result['sha256']}"
        )
    return result


def attach_prepared(
    row: dict[str, Any], prepared: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    result = dict(row)
    artifact = prepared.get(str(result["sample_id"]))
    if artifact is None:
        raise ValueError(f"missing Development Ghidra artifacts: {result['sample_id']}")
    result["program_facts_path"] = str(artifact["program_facts_path"])
    result["decompiled_c_path"] = str(artifact["decompiled_c_path"])
    result["analysis_status"] = "READY_FOR_DEVELOPMENT_ANALYSIS"
    return result


def validate_unique(rows: list[dict[str, Any]], label: str) -> tuple[set[str], set[str]]:
    cves = [str(row.get("cve", "")) for row in rows]
    hashes = [str(row.get("sha256", "")) for row in rows]
    duplicate_cves = sorted(name for name, count in Counter(cves).items() if count > 1)
    if duplicate_cves:
        raise ValueError(f"{label} duplicate CVEs: {duplicate_cves}")
    return set(cves), set(hashes)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--development-base", required=True, type=Path)
    parser.add_argument("--evaluation-base", required=True, type=Path)
    parser.add_argument("--replacements", required=True, type=Path)
    parser.add_argument("--development-prepared", required=True, type=Path)
    parser.add_argument("--development-out", required=True, type=Path)
    parser.add_argument("--evaluation-out", required=True, type=Path)
    parser.add_argument("--verification-out", required=True, type=Path)
    args = parser.parse_args()

    dev_base = read_json(args.development_base)
    eval_base = read_json(args.evaluation_base)
    replacement_doc = read_json(args.replacements)
    prepared = prepared_index(args.development_prepared)

    dev_rows = [dict(row) for row in list(dev_base.get("samples", []) or [])]
    existing_profiles = {
        "development_zephyr_cve_2024_6135": ROOT / "datasets/public_expected_sinks_replacements_v1/development_zephyr_cve_2024_6135.json",
        "development_zephyr_cve_2024_6137": ROOT / "datasets/public_expected_sinks_replacements_v1/development_zephyr_cve_2024_6137.json",
    }
    for row in dev_rows:
        sample_id = str(row.get("sample_id", ""))
        if sample_id in existing_profiles:
            row["expected_profile_path"] = str(existing_profiles[sample_id])
            row.update(attach_prepared(row, prepared))

    for raw in list(replacement_doc.get("development", []) or []):
        row = attach_prepared(enrich_binary(dict(raw)), prepared)
        dev_rows.append(row)

    eval_rows = [dict(row) for row in list(eval_base.get("samples", []) or [])]
    sealed_profiles = {
        sample_id: ROOT / f"datasets/public_expected_sinks_replacements_v1/{sample_id}.json"
        for sample_id in (
            "evaluation_riot_cve_2025_66647",
            "evaluation_riot_cve_2024_31225",
            "evaluation_riot_cve_2024_32018",
            "evaluation_riot_cve_2023_24817",
            "evaluation_zephyr_cve_2024_6259",
            "evaluation_zephyr_cve_2024_5931",
            "evaluation_zephyr_cve_2024_6444",
            "evaluation_zephyr_cve_2025_1675",
            "evaluation_freertos_cve_2025_5688",
        )
    }
    for row in eval_rows:
        sample_id = str(row.get("sample_id", ""))
        if sample_id in sealed_profiles:
            row["expected_profile_path"] = str(sealed_profiles[sample_id])
        if row.get("program_facts_path") or row.get("decompiled_c_path"):
            row["analysis_status"] = "LEGACY_ANALYSIS_AVAILABLE_NOT_RERUN"
        else:
            row["analysis_status"] = "NOT_RUN_SEALED"
    evaluation_additions: list[dict[str, Any]] = []
    for raw in list(replacement_doc.get("evaluation", []) or []):
        row = enrich_binary(dict(raw))
        row["analysis_status"] = "NOT_RUN_SEALED"
        evaluation_additions.append(row)
        eval_rows.append(row)

    # Normalize binary identity for pre-existing rows as part of the freeze.
    for row in dev_rows + eval_rows:
        binary = Path(str(row.get("binary_path", "")))
        if not binary.is_file():
            raise ValueError(f"missing ELF: {binary}")
        actual = sha256(binary)
        claimed = str(row.get("sha256", "") or "")
        if claimed and claimed != actual:
            raise ValueError(f"ELF hash mismatch for {row.get('sample_id')}")
        row["sha256"] = actual
        row["byte_size"] = binary.stat().st_size
        profile_path = Path(str(row.get("expected_profile_path", "")))
        if not profile_path.is_file():
            raise ValueError(f"missing public profile: {row.get('sample_id')}")
        profile_hash = str(read_json(profile_path).get("binary_sha256", ""))
        if profile_hash != actual:
            raise ValueError(
                f"profile binary hash mismatch for {row.get('sample_id')}: "
                f"{profile_hash} != {actual}"
            )

    dev_cves, dev_hashes = validate_unique(dev_rows, "Development")
    eval_cves, eval_hashes = validate_unique(eval_rows, "Evaluation")
    if dev_cves & eval_cves:
        raise ValueError(f"CVE overlap: {sorted(dev_cves & eval_cves)}")
    if dev_hashes & eval_hashes:
        raise ValueError(f"ELF hash overlap: {sorted(dev_hashes & eval_hashes)}")
    if len(dev_hashes) < 30 or len(dev_cves) < 30:
        raise ValueError("Development Set does not meet the 30-CVE/30-ELF gate")
    if len(eval_hashes) < 20 or len(eval_cves) < 20:
        raise ValueError("Evaluation Set does not meet the 20-CVE/20-ELF gate")

    distribution = Counter(str(row.get("project", "")) for row in evaluation_additions)
    if len(distribution) < 3 or max(distribution.values(), default=0) > 3:
        raise ValueError(f"Evaluation replacement distribution failed: {distribution}")
    for row in evaluation_additions:
        forbidden = {"decompiled_c_path", "program_facts_path"} & set(row)
        if forbidden:
            raise ValueError(f"sealed Evaluation artifact leakage: {row['sample_id']}")

    development = {
        "schema_version": "ct-mini-public-cve-dataset-v3",
        "manifest_name": "development_cve",
        "set_role": "development",
        "freeze_date": "2026-08-06",
        "description": "Canonical in-scope public-CVE Development Set; pure parser-load/walk CVEs are audited separately.",
        "source_manifests": [
            str(args.development_base),
            str(args.replacements),
            str(args.development_prepared),
        ],
        "samples": dev_rows,
    }
    evaluation = {
        "schema_version": "ct-mini-public-cve-dataset-v3",
        "manifest_name": "evaluation_cve",
        "set_role": "evaluation_sealed",
        "freeze_date": "2026-08-06",
        "description": "Canonical in-scope public-CVE Evaluation Set; analyzer execution is prohibited until the rule freeze.",
        "source_manifests": [str(args.evaluation_base), str(args.replacements)],
        "samples": eval_rows,
    }
    write_json(args.development_out, development)
    write_json(args.evaluation_out, evaluation)

    verification = {
        "schema_version": "ct-mini-public-cve-dataset-verification-v1",
        "status": "PASS",
        "development": {
            "cves": len(dev_cves),
            "samples": len(dev_rows),
            "unique_elf_hashes": len(dev_hashes),
        },
        "evaluation": {
            "cves": len(eval_cves),
            "samples": len(eval_rows),
            "unique_elf_hashes": len(eval_hashes),
            "status": "SEALED_ANALYSIS_NOT_RUN",
            "sample_statuses": dict(
                sorted(Counter(str(row["analysis_status"]) for row in eval_rows).items())
            ),
        },
        "set_overlap": {"cves": 0, "elf_hashes": 0},
        "evaluation_replacement_projects": dict(sorted(distribution.items())),
        "artifacts": {
            str(args.development_out): sha256(args.development_out),
            str(args.evaluation_out): sha256(args.evaluation_out),
            str(args.replacements): sha256(args.replacements),
        },
    }
    write_json(args.verification_out, verification)
    print(json.dumps(verification, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
