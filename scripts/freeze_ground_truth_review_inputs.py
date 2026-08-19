#!/usr/bin/env python3
"""Freeze one canonical-Alert review input per unique Ground-Truth ELF."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ct-mini-ground-truth-unique-review-input-v1"


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
    rows = [dict(row) for row in list(a2_doc.get("canonical_alerts", []) or [])]
    if not rows:
        rows = [
            *[dict(row) for row in list(a2_doc.get("selected", []) or [])],
            *[dict(row) for row in list(a2_doc.get("deferred", []) or [])],
            *[dict(row) for row in list(a2_doc.get("dropped", []) or [])],
        ]
    rows.sort(
        key=lambda row: (
            int(row.get("rank", 1 << 30) or 1 << 30),
            str(row.get("alert_id", "")),
        )
    )
    ids = [str(row.get("alert_id", "") or "") for row in rows]
    if not all(ids):
        raise ValueError("canonical Alerts must have alert_id")
    if len(ids) != len(set(ids)):
        raise ValueError("canonical alert_id values must be unique within a firmware")
    return rows


def alert_identity(rows: list[dict[str, Any]]) -> tuple[str, ...]:
    return tuple(sorted(str(row["alert_id"]) for row in rows))


def resolve_decompiled_path(
    sample: dict[str, Any], facts_path: Path, static_dir: Path | None = None
) -> Path:
    direct = Path(str(sample.get("decompiled_c_path", "") or ""))
    if direct.is_file():
        return direct
    facts = read_json(facts_path)
    candidates = [
        facts.get("decompiled_c_path"),
        dict(facts.get("provenance", {}) or {}).get("decompiled_c_path"),
        dict(facts.get("input", {}) or {}).get("decompiled_c_path"),
        static_dir / "plain_decompiled.c" if static_dir is not None else None,
    ]
    for value in candidates:
        path = Path(str(value or ""))
        if path.is_file():
            return path
    raise FileNotFoundError(f"no Decompiled C for {sample.get('sample_id')}")


def corpus_rows(
    *,
    corpus: str,
    manifest_path: Path,
    static_summary_path: Path,
    static_root: Path,
    a2_root: Path,
) -> list[dict[str, Any]]:
    manifest = read_json(manifest_path)
    summary = read_json(static_summary_path)
    summaries = {
        str(row.get("sample_id", "")): dict(row)
        for row in list(summary.get("samples", []) or [])
    }
    output: list[dict[str, Any]] = []
    for sample in list(manifest.get("samples", []) or []):
        sample = dict(sample)
        sample_id = str(sample.get("sample_id", ""))
        if sample_id not in summaries:
            raise KeyError(f"{corpus}:{sample_id}: missing static summary row")
        summary_row = summaries[sample_id]
        binary_path = Path(str(sample.get("binary_path", "")))
        facts_path = Path(str(summary_row.get("program_facts", "")))
        static_dir = static_root / "per_sample" / sample_id
        a2_path = a2_root / "per_sample" / sample_id / "alert_filter.json"
        required = {
            "binary": binary_path,
            "program_facts": facts_path,
            "chains": static_dir / "chains.json",
            "sinks": static_dir / "sinks.json",
            "sources": static_dir / "sources.json",
            "channel_graph": static_dir / "channel_graph.json",
            "public_match": static_dir / "public_match.json",
            "a2": a2_path,
        }
        missing = [f"{name}:{path}" for name, path in required.items() if not path.is_file()]
        if missing:
            raise FileNotFoundError(f"{corpus}:{sample_id}: " + ", ".join(missing))
        binary_sha = sha256_file(binary_path)
        declared_sha = str(sample.get("sha256", "") or sample.get("binary_sha256", "") or "")
        if declared_sha and binary_sha != declared_sha:
            raise RuntimeError(f"{corpus}:{sample_id}: binary SHA-256 changed")
        decompiled_path = resolve_decompiled_path(sample, facts_path, static_dir)
        rows = canonical_rows(read_json(a2_path))
        output.append(
            {
                "corpus": corpus,
                "sample": sample,
                "summary": summary_row,
                "sample_id": sample_id,
                "cve": str(sample.get("cve", "")),
                "binary_sha256": binary_sha,
                "binary_path": binary_path,
                "decompiled_c_path": decompiled_path,
                "program_facts_path": facts_path,
                "static_dir": static_dir,
                "a2_path": a2_path,
                "canonical_rows": rows,
            }
        )
    return output


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--development-manifest", type=Path, required=True)
    parser.add_argument("--development-static-summary", type=Path, required=True)
    parser.add_argument("--development-static-root", type=Path, required=True)
    parser.add_argument("--development-a2-root", type=Path, required=True)
    parser.add_argument("--evaluation-manifest", type=Path, required=True)
    parser.add_argument("--evaluation-static-summary", type=Path, required=True)
    parser.add_argument("--evaluation-static-root", type=Path, required=True)
    parser.add_argument("--evaluation-a2-root", type=Path, required=True)
    parser.add_argument("--scope-manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    records = [
        *corpus_rows(
            corpus="development",
            manifest_path=args.development_manifest,
            static_summary_path=args.development_static_summary,
            static_root=args.development_static_root,
            a2_root=args.development_a2_root,
        ),
        *corpus_rows(
            corpus="evaluation",
            manifest_path=args.evaluation_manifest,
            static_summary_path=args.evaluation_static_summary,
            static_root=args.evaluation_static_root,
            a2_root=args.evaluation_a2_root,
        ),
    ]
    scope = read_json(args.scope_manifest)
    scope_by_key = {
        (str(row.get("sample_id", "")), str(row.get("cve", ""))): dict(row)
        for row in list(scope.get("samples", []) or scope.get("cves", []) or [])
    }
    if len(scope_by_key) != len(records):
        raise RuntimeError("scope manifest and Ground-Truth records differ")

    by_sha: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_sha[record["binary_sha256"]].append(record)
    if len(by_sha) != 50:
        raise RuntimeError(f"expected 50 unique ELFs, found {len(by_sha)}")

    frozen_samples: list[dict[str, Any]] = []
    frozen_summary_rows: list[dict[str, Any]] = []
    cve_views: list[dict[str, Any]] = []
    freeze_entries: list[dict[str, Any]] = []
    total_alerts = 0
    for index, binary_sha in enumerate(sorted(by_sha), start=1):
        views = sorted(
            by_sha[binary_sha],
            key=lambda row: (0 if row["corpus"] == "development" else 1, row["sample_id"], row["cve"]),
        )
        identities = {alert_identity(view["canonical_rows"]) for view in views}
        if len(identities) != 1:
            detail = {view["sample_id"]: len(view["canonical_rows"]) for view in views}
            raise RuntimeError(f"{binary_sha}: duplicate ELF has inconsistent canonical Alerts: {detail}")
        selected = views[0]
        neutral_id = f"GTELF{index:03d}"
        frozen_a2 = {
            "schema_version": "ct-mini-frozen-a2-canonical-alerts-v1",
            "sample_id": neutral_id,
            "binary_sha256": binary_sha,
            "counts": {"canonical_alerts": len(selected["canonical_rows"])},
            "canonical_alerts": selected["canonical_rows"],
        }
        frozen_a2_path = args.out / "a2" / "per_sample" / neutral_id / "alert_filter.json"
        write_json(frozen_a2_path, frozen_a2)
        sample = {
            "sample_id": neutral_id,
            "sha256": binary_sha,
            "binary_path": str(selected["binary_path"].resolve()),
            "decompiled_c_path": str(selected["decompiled_c_path"].resolve()),
            "program_facts_path": str(selected["program_facts_path"].resolve()),
            "static_artifact_dir": str(selected["static_dir"].resolve()),
            "a2_artifact_path": str(frozen_a2_path.resolve()),
        }
        frozen_samples.append(sample)
        summary_row = dict(selected["summary"])
        summary_row["sample_id"] = neutral_id
        summary_row["program_facts"] = str(selected["program_facts_path"].resolve())
        summary_row["artifact_path"] = str((selected["static_dir"] / "chains.json").resolve())
        frozen_summary_rows.append(summary_row)
        total_alerts += len(selected["canonical_rows"])
        freeze_entries.append(
            {
                "sample_id": neutral_id,
                "binary_sha256": binary_sha,
                "canonical_alerts": len(selected["canonical_rows"]),
                "source_sample_id": selected["sample_id"],
                "source_corpus": selected["corpus"],
                "source_a2_sha256": sha256_file(selected["a2_path"]),
                "frozen_a2_sha256": sha256_file(frozen_a2_path),
            }
        )
        for view in views:
            key = (view["sample_id"], view["cve"])
            scope_row = scope_by_key.get(key)
            if scope_row is None:
                raise RuntimeError(f"scope row missing for {key}")
            cve_views.append(
                {
                    "corpus": view["corpus"],
                    "sample_id": view["sample_id"],
                    "cve": view["cve"],
                    "scope": scope_row.get("scope"),
                    "scope_reason": scope_row.get("reason"),
                    "sample_validity": scope_row.get("sample_validity", "VALID"),
                    "binary_sha256": binary_sha,
                    "review_sample_id": neutral_id,
                    "static_artifact_dir": str(view["static_dir"].resolve()),
                    "a2_artifact_path": str(view["a2_path"].resolve()),
                    "expected_profile_path": str(view["sample"].get("expected_profile_path", "")),
                }
            )

    write_json(
        args.out / "manifest.json",
        {
            "schema_version": SCHEMA_VERSION,
            "description": "One review input per unique ELF; contains no CVE identity.",
            "samples": frozen_samples,
        },
    )
    for corpus in ("development", "evaluation"):
        corpus_samples = [
            sample
            for sample, entry in zip(frozen_samples, freeze_entries)
            if entry["source_corpus"] == corpus
        ]
        write_json(
            args.out / f"{corpus}_manifest.json",
            {
                "schema_version": SCHEMA_VERSION,
                "description": f"Neutral unique-ELF {corpus} subset for LLM-only evaluation.",
                "samples": corpus_samples,
            },
        )
    write_json(
        args.out / "static_summary.json",
        {
            "schema_version": SCHEMA_VERSION,
            "counts": {"samples": len(frozen_summary_rows)},
            "samples": frozen_summary_rows,
        },
    )
    write_json(
        args.out / "cve_views.json",
        {
            "schema_version": SCHEMA_VERSION,
            "counts": {"cves": len(cve_views), "unique_elfs": len(frozen_samples)},
            "cve_views": cve_views,
        },
    )
    write_json(
        args.out / "freeze.json",
        {
            "schema_version": SCHEMA_VERSION,
            "status": "FROZEN",
            "counts": {
                "cves": len(cve_views),
                "unique_elfs": len(frozen_samples),
                "canonical_alerts": total_alerts,
            },
            "inputs": {
                "development_manifest": str(args.development_manifest.resolve()),
                "evaluation_manifest": str(args.evaluation_manifest.resolve()),
                "scope_manifest": str(args.scope_manifest.resolve()),
            },
            "firmwares": freeze_entries,
        },
    )
    print(json.dumps({"status": "FROZEN", "cves": len(cve_views), "unique_elfs": len(frozen_samples), "canonical_alerts": total_alerts}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
