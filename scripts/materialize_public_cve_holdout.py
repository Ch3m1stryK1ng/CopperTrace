#!/usr/bin/env python3
"""Materialize frozen public-CVE evaluation profiles from an audited catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--ready-binaries", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--source-profiles", required=True, type=Path)
    parser.add_argument("--sink-profile-dir", required=True, type=Path)
    args = parser.parse_args()

    catalog = read_json(args.catalog)
    ready = read_json(args.ready_binaries)
    binary_rows = {
        str(row.get("sample_id", "")): row
        for row in list(ready.get("samples", []) or [])
    }
    source_templates = dict(catalog.get("source_templates", {}) or {})
    manifest_rows: list[dict[str, Any]] = []
    source_rows: dict[str, dict[str, Any]] = {}

    for case in list(catalog.get("cves", []) or []):
        sample_id = str(case["sample_id"])
        cve = str(case["cve"])
        binary = binary_rows.get(str(case["binary_id"]))
        if binary is None:
            raise SystemExit(f"missing prepared binary {case['binary_id']} for {sample_id}")
        binary_path = Path(str(binary["binary_path"]))
        profile_path = args.sink_profile_dir / f"{sample_id}.json"
        sinks = []
        for sink in list(case.get("sinks", []) or []):
            row = dict(sink)
            row.setdefault("pipeline_label_hint", row.get("label", ""))
            sinks.append(row)
        sink_profile = {
            "profile_schema_version": "public-cve-endpoint-v2",
            "evaluation_role": "post_analysis_answer_key_only",
            "profile_frozen_before_static_analysis": True,
            "sample_id": sample_id,
            "cve": cve,
            "binary_sha256": sha256_path(binary_path),
            "ground_truth_basis": str(case.get("ground_truth_basis", "")),
            "public_references": list(case.get("public_references", []) or []),
            "sinks": sinks,
            "chains": [
                {
                    "chain_id": f"public_chain_{cve.lower().replace('-', '_')}_{index}",
                    "sink_id": str(sink["sink_id"]),
                    "expected_verdict": "CONFIRMED",
                    "expected_final_verdict": "CONFIRMED",
                }
                for index, sink in enumerate(sinks, start=1)
            ],
        }
        write_json(profile_path, sink_profile)

        template_name = str(case["source_template"])
        template = dict(source_templates[template_name])
        source_id = f"PUBLIC_{cve.replace('CVE-', '').replace('-', '_')}_SOURCE"
        template["source_id"] = source_id
        source_rows[sample_id] = {
            "sample_id": sample_id,
            "cve": cve,
            "profile_status": "public_source_boundary_frozen_before_analysis",
            "sources": [template],
            "chains": [
                {
                    "chain_id": f"public_source_chain_{cve.lower().replace('-', '_')}",
                    "source_id": source_id,
                }
            ],
        }
        manifest_rows.append(
            {
                "sample_id": sample_id,
                "cve": cve,
                "provider": "reproducible_official_release_build",
                "expected_profile_path": str(profile_path.resolve()),
                "decompiled_c_path": str(Path(str(binary["decompiled_c_path"])).resolve()),
                "program_facts_path": str(
                    Path(str(binary["program_facts_path"])).resolve()
                ),
                "binary_path": str(binary_path.resolve()),
            }
        )

    write_json(
        args.manifest,
        {
            "schema_version": "ct-mini-source-mining-dataset-v1",
            "manifest_name": "holdout_public_cve20_v1",
            "description": "Twenty sealed public CVEs represented by seven reproducibly built vulnerable ARM ELF images. Profiles are post-analysis answer keys only.",
            "catalog_sha256": sha256_path(args.catalog),
            "samples": manifest_rows,
        },
    )
    write_json(
        args.source_profiles,
        {
            "schema_version": "ct-mini-public-source-profile-v1",
            "evaluation_role": "post_analysis_answer_key_only",
            "catalog_sha256": sha256_path(args.catalog),
            "profiles": source_rows,
        },
    )
    print(json.dumps({"cves": len(manifest_rows), "binaries": len(binary_rows)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
