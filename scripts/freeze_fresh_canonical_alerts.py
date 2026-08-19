#!/usr/bin/env python3
"""Freeze a corpus' complete A2 canonical Alert input for LLM review."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ct-mini-frozen-canonical-review-input-v1"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_rows(a2_doc: dict[str, Any]) -> list[dict[str, Any]]:
    if "canonical_alerts" in a2_doc:
        rows = [dict(row) for row in list(a2_doc.get("canonical_alerts", []) or [])]
    else:
        rows = [
            *[dict(row) for row in list(a2_doc.get("selected", []) or [])],
            *[dict(row) for row in list(a2_doc.get("deferred", []) or [])],
            *[dict(row) for row in list(a2_doc.get("dropped", []) or [])],
        ]
    rows.sort(key=lambda row: (int(row.get("rank", 1 << 30) or 1 << 30), str(row.get("alert_id", ""))))
    ids = [str(row.get("alert_id", "") or "") for row in rows]
    if not all(ids):
        raise ValueError("canonical Alerts must have nonempty alert_id")
    if len(ids) != len(set(ids)):
        raise ValueError("canonical Alerts must have unique alert_id within a firmware")
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--static-summary", required=True, type=Path)
    parser.add_argument("--a2-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    manifest = read_json(args.manifest)
    static_summary = read_json(args.static_summary)
    manifest_by_id = {
        str(row.get("sample_id", "")): dict(row)
        for row in list(manifest.get("samples", []) or [])
    }
    summary_by_id = {
        str(row.get("sample_id", "")): dict(row)
        for row in list(static_summary.get("samples", []) or [])
    }
    if set(manifest_by_id) != set(summary_by_id):
        raise RuntimeError("manifest and static summary sample sets differ")

    frozen_samples: list[dict[str, Any]] = []
    frozen_entries: list[dict[str, Any]] = []
    total = 0
    for sample_id in manifest_by_id:
        sample = dict(manifest_by_id[sample_id])
        summary_row = summary_by_id[sample_id]
        source_a2 = args.a2_root / "per_sample" / sample_id / "alert_filter.json"
        a2_doc = read_json(source_a2)
        rows = canonical_rows(a2_doc)
        expected = int(dict(a2_doc.get("counts", {}) or {}).get("canonical_alerts", len(rows)) or 0)
        if len(rows) != expected:
            raise RuntimeError(f"{sample_id}: canonical count {len(rows)} != {expected}")

        artifact_path = Path(str(summary_row.get("artifact_path", "")))
        static_dir = artifact_path.parent
        facts_path = Path(str(summary_row.get("program_facts", "")))
        decompiled_path = Path(str(sample.get("decompiled_c_path", "")))
        binary_path = Path(str(sample.get("binary_path", "")))
        required = {
            "binary": binary_path,
            "program_facts": facts_path,
            "decompiled_c": decompiled_path,
            "chains": static_dir / "chains.json",
            "sinks": static_dir / "sinks.json",
            "sources": static_dir / "sources.json",
            "channel_graph": static_dir / "channel_graph.json",
            "public_match": static_dir / "public_match.json",
            "a2": source_a2,
        }
        missing = [f"{name}:{path}" for name, path in required.items() if not path.is_file()]
        if missing:
            raise FileNotFoundError(f"{sample_id}: " + ", ".join(missing))

        binary_sha = sha256_file(binary_path)
        expected_binary_sha = str(sample.get("binary_sha256", "") or "")
        if expected_binary_sha and binary_sha != expected_binary_sha:
            raise RuntimeError(f"{sample_id}: binary hash changed")

        frozen_a2 = {
            "schema_version": "ct-mini-frozen-a2-canonical-alerts-v1",
            "sample_id": sample_id,
            "source_a2_path": str(source_a2.resolve()),
            "source_a2_sha256": sha256_file(source_a2),
            "counts": {"canonical_alerts": len(rows)},
            "canonical_alerts": rows,
        }
        frozen_a2_path = args.out / "a2" / "per_sample" / sample_id / "alert_filter.json"
        write_json(frozen_a2_path, frozen_a2)

        sample.update(
            {
                "sha256": binary_sha,
                "static_artifact_dir": str(static_dir.resolve()),
                "a2_artifact_path": str(frozen_a2_path.resolve()),
            }
        )
        frozen_samples.append(sample)
        alert_ids = [str(row["alert_id"]) for row in rows]
        alert_digest = hashlib.sha256("\n".join(alert_ids).encode()).hexdigest()
        frozen_entries.append(
            {
                "sample_id": sample_id,
                "binary_sha256": binary_sha,
                "canonical_alerts": len(rows),
                "alert_ids_sha256": alert_digest,
                "inputs": {name: {"path": str(path.resolve()), "sha256": sha256_file(path)} for name, path in required.items()},
                "frozen_a2_path": str(frozen_a2_path.resolve()),
                "frozen_a2_sha256": sha256_file(frozen_a2_path),
            }
        )
        total += len(rows)

    frozen_manifest = dict(manifest)
    frozen_manifest["schema_version"] = SCHEMA_VERSION
    frozen_manifest["source_manifest"] = str(args.manifest.resolve())
    frozen_manifest["samples"] = frozen_samples
    manifest_path = args.out / "manifest.json"
    summary_path = args.out / "static_summary.json"
    write_json(manifest_path, frozen_manifest)
    write_json(summary_path, static_summary)
    freeze = {
        "schema_version": SCHEMA_VERSION,
        "status": "FROZEN",
        "samples": len(frozen_samples),
        "canonical_alerts": total,
        "source_manifest": {"path": str(args.manifest.resolve()), "sha256": sha256_file(args.manifest)},
        "source_static_summary": {"path": str(args.static_summary.resolve()), "sha256": sha256_file(args.static_summary)},
        "frozen_manifest": {"path": str(manifest_path.resolve()), "sha256": sha256_file(manifest_path)},
        "frozen_static_summary": {"path": str(summary_path.resolve()), "sha256": sha256_file(summary_path)},
        "firmwares": frozen_entries,
    }
    write_json(args.out / "freeze.json", freeze)
    print(json.dumps({"status": "FROZEN", "samples": len(frozen_samples), "canonical_alerts": total}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
