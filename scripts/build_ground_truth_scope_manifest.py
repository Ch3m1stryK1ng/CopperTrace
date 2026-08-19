#!/usr/bin/env python3
"""Freeze public-CVE scope without consulting CopperTrace results."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFESTS = (
    ROOT / "datasets/development_cve.json",
    ROOT / "datasets/evaluation_cve.json",
)
DEFAULT_OUTPUT = ROOT / "datasets/ground_truth_scope_manifest.json"
IN_SCOPE_LABELS = {
    "COPY_SINK": "COPY",
    "MEMSET_SINK": "FILL",
    "BUFFER_STATE_SINK": "BUFFER_STATE",
    "FORMAT_STRING_SINK": "FORMAT",
}


def read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path}: expected JSON object")
    return payload


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify_sample(sample: dict[str, Any], *, subset: str) -> dict[str, Any]:
    profile_path = Path(str(sample.get("expected_profile_path", "")))
    if not profile_path.is_file():
        raise ValueError(
            f"{sample.get('sample_id')}: missing public endpoint profile {profile_path}"
        )
    profile = read_json(profile_path)
    cve = str(sample.get("cve", "")).strip()
    if cve != str(profile.get("cve", "")).strip():
        raise ValueError(f"{sample.get('sample_id')}: CVE/profile mismatch")
    references = [
        str(value).strip()
        for value in list(profile.get("public_references", []) or [])
        if str(value).strip()
    ]
    if not references:
        raise ValueError(f"{sample.get('sample_id')}: public references are required")
    sinks = [dict(value) for value in list(profile.get("sinks", []) or [])]
    if not sinks:
        raise ValueError(f"{sample.get('sample_id')}: public Sink endpoints are required")
    labels = sorted({str(row.get("label", "")).strip() for row in sinks})
    if any(not label for label in labels):
        raise ValueError(f"{sample.get('sample_id')}: every endpoint needs a label")
    supported = sorted({IN_SCOPE_LABELS[label] for label in labels if label in IN_SCOPE_LABELS})
    declared_scope = str(profile.get("evaluation_scope", "")).strip()
    if declared_scope and declared_scope not in {"IN_SCOPE", "OUT_OF_SCOPE"}:
        raise ValueError(f"{sample.get('sample_id')}: invalid evaluation_scope")
    scope = declared_scope or ("IN_SCOPE" if supported else "OUT_OF_SCOPE")
    declared_reason = str(profile.get("evaluation_scope_reason", "")).strip()
    if declared_scope and not declared_reason:
        raise ValueError(
            f"{sample.get('sample_id')}: evaluation_scope requires a reason"
        )
    if declared_reason:
        reason = declared_reason
    elif scope == "IN_SCOPE":
        reason = (
            "At least one public vulnerability endpoint uses a currently enabled "
            f"Sink form: {', '.join(supported)}."
        )
    else:
        reason = (
            "All public vulnerability endpoints use Sink forms outside the frozen "
            f"default Pipeline: {', '.join(labels)}."
        )
    validity = str(sample.get("sample_validity", "VALID")).strip() or "VALID"
    if validity not in {"VALID", "INVALID_FIRMWARE_SAMPLE"}:
        raise ValueError(f"{sample.get('sample_id')}: invalid sample_validity")
    row = {
        "sample_id": str(sample.get("sample_id", "")),
        "cve": cve,
        "subset": subset,
        "elf_sha256": str(sample.get("sha256", "")),
        "scope": scope,
        "public_sink_forms": supported if supported else labels,
        "public_sink_labels": labels,
        "reason": reason,
        "ground_truth_basis": str(profile.get("ground_truth_basis", "")).strip(),
        "public_evidence": references,
        "profile_path": str(profile_path.resolve()),
        "profile_sha256": file_sha256(profile_path),
    }
    if validity != "VALID":
        row["sample_validity"] = validity
        row["sample_validity_reason"] = str(
            sample.get("sample_validity_reason", "")
        ).strip()
    return row


def build_scope_manifest(manifest_paths: list[Path]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    seen_cves: set[str] = set()
    input_manifests: list[dict[str, str]] = []
    for manifest_path in manifest_paths:
        manifest = read_json(manifest_path)
        subset = str(manifest.get("set_role", manifest_path.stem)).strip()
        input_manifests.append(
            {
                "path": str(manifest_path.resolve()),
                "sha256": file_sha256(manifest_path),
            }
        )
        for raw_sample in list(manifest.get("samples", []) or []):
            sample = dict(raw_sample)
            row = classify_sample(sample, subset=subset)
            if row["cve"] in seen_cves:
                raise ValueError(f"duplicate CVE across manifests: {row['cve']}")
            seen_cves.add(row["cve"])
            rows.append(row)
    rows.sort(key=lambda row: row["cve"])
    in_scope = sum(row["scope"] == "IN_SCOPE" for row in rows)
    invalid = sum(
        row.get("sample_validity") == "INVALID_FIRMWARE_SAMPLE" for row in rows
    )
    evaluated_in_scope = sum(
        row["scope"] == "IN_SCOPE"
        and row.get("sample_validity", "VALID") == "VALID"
        for row in rows
    )
    return {
        "schema_version": "ct-mini-ground-truth-scope-v2",
        "policy": {
            "classification_basis": "public_advisory_patch_and_vulnerable_source_only",
            "in_scope_sink_labels": sorted(IN_SCOPE_LABELS),
            "in_scope_sink_forms": [
                "STANDARD_COPY_OR_FILL",
                "BODY_PROVED_COPY_OR_FILL_WRAPPER",
                "FORMAT_STRING",
                "PAIRED_BUFFER_STATE",
            ],
            "requires_supported_attacker_influenced_vulnerable_parameter": True,
            "invalid_sample_handling": (
                "exclude_from_evaluated_in_scope_denominator_until_replaced"
            ),
            "analyzer_results_consulted": False,
            "llm_results_consulted": False,
        },
        "input_manifests": input_manifests,
        "counts": {
            "cves": len(rows),
            "in_scope": in_scope,
            "out_of_scope": len(rows) - in_scope,
            "invalid_firmware_samples": invalid,
            "evaluated_in_scope": evaluated_in_scope,
            "unique_elfs": len({row["elf_sha256"] for row in rows}),
        },
        "cves": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", action="append", type=Path)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    manifest_paths = list(args.manifest or DEFAULT_MANIFESTS)
    payload = build_scope_manifest(manifest_paths)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
