#!/usr/bin/env python3
"""Prepare a reproducible Fresh Discovery Audit subset for Check/LLM review."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rank_key(row: dict[str, Any]) -> tuple[int, str]:
    return int(row.get("rank", 2**31 - 1) or 2**31 - 1), str(
        row.get("alert_id", "")
    )


def rankable_alerts(a2_doc: dict[str, Any]) -> list[dict[str, Any]]:
    if "canonical_alerts" in a2_doc:
        rows = list(a2_doc.get("canonical_alerts", []) or [])
    else:
        rows = [
            *list(a2_doc.get("selected", []) or []),
            *list(a2_doc.get("deferred", []) or []),
        ]
    return sorted(
        (dict(row) for row in rows if not bool(row.get("hard_drop", False))),
        key=rank_key,
    )


def select_alerts(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Prefer distinct Sink boundaries, then fill with alternate lineages."""

    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    seen_boundaries: set[str] = set()
    for row in rows:
        boundary = str(
            row.get("sink_boundary_site_id")
            or row.get("sink_effect_site_id")
            or row.get("sink_id")
            or ""
        )
        if not boundary or boundary in seen_boundaries:
            continue
        selected.append(row)
        selected_ids.add(str(row.get("alert_id", "")))
        seen_boundaries.add(boundary)
        if len(selected) == limit:
            return selected

    for row in rows:
        alert_id = str(row.get("alert_id", ""))
        if alert_id in selected_ids:
            continue
        selected.append(row)
        selected_ids.add(alert_id)
        if len(selected) == limit:
            return selected
    return selected


def static_dir(summary_row: dict[str, Any]) -> Path:
    artifact_path = str(summary_row.get("artifact_path", "") or "")
    if not artifact_path:
        raise ValueError(f"{summary_row.get('sample_id')}: artifact_path is missing")
    path = Path(artifact_path)
    if not path.is_absolute():
        path = ROOT / path
    return path.resolve().parent


def prepare(
    *,
    selection: dict[str, Any],
    fresh_manifest: dict[str, Any],
    static_summary: dict[str, Any],
    a2_root: Path,
    output_root: Path,
) -> dict[str, Any]:
    policy = dict(selection.get("policy", {}) or {})
    per_firmware = int(policy.get("alerts_per_firmware", 5) or 5)
    selected_specs = list(selection.get("samples", []) or [])
    manifest_by_id = {
        str(row.get("sample_id", "")): dict(row)
        for row in list(fresh_manifest.get("samples", []) or [])
    }
    summary_by_id = {
        str(row.get("sample_id", "")): dict(row)
        for row in list(static_summary.get("samples", []) or [])
    }
    sample_ids = [str(row.get("sample_id", "")) for row in selected_specs]
    if len(sample_ids) != len(set(sample_ids)):
        raise ValueError("selection contains duplicate sample_id values")

    project_counts = Counter(str(row.get("project", "")) for row in selected_specs)
    expected_projects = int(policy.get("projects", 0) or 0)
    expected_per_project = int(policy.get("firmware_per_project", 0) or 0)
    if expected_projects and len(project_counts) != expected_projects:
        raise ValueError("selection project count does not match policy")
    if expected_per_project and any(
        count != expected_per_project for count in project_counts.values()
    ):
        raise ValueError("selection is not balanced across projects")

    output_manifest_rows: list[dict[str, Any]] = []
    output_summary_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    flat_alerts: list[dict[str, Any]] = []
    for spec in selected_specs:
        sample_id = str(spec.get("sample_id", ""))
        if sample_id not in manifest_by_id or sample_id not in summary_by_id:
            raise ValueError(f"{sample_id}: missing Fresh manifest or static summary row")
        source_manifest = manifest_by_id[sample_id]
        summary_row = summary_by_id[sample_id]
        source_a2 = a2_root / "per_sample" / sample_id / "alert_filter.json"
        if not source_a2.is_file():
            raise ValueError(f"{sample_id}: A2 artifact is missing: {source_a2}")
        a2_doc = read_json(source_a2)
        candidates = rankable_alerts(a2_doc)
        chosen = select_alerts(candidates, per_firmware)
        if len(chosen) != per_firmware:
            raise ValueError(
                f"{sample_id}: expected {per_firmware} selected Alerts, got {len(chosen)}"
            )

        output_a2 = output_root / "a2" / "per_sample" / sample_id / "alert_filter.json"
        subset_a2 = {
            "schema_version": "ct-mini-fresh-discovery-audit-a2-subset-v1",
            "policy": {
                "source_schema_version": str(a2_doc.get("schema_version", "")),
                "source_a2_sha256": sha256_file(source_a2),
                "selection": "frozen_a2_rank_distinct_sink_boundary_first",
                "alerts_per_firmware": per_firmware,
                "public_profiles_used": False,
                "manual_alert_inspection_used": False,
            },
            "counts": {
                "source_rankable_alerts": len(candidates),
                "canonical_alerts": len(chosen),
                "distinct_sink_boundaries": len(
                    {
                        str(row.get("sink_boundary_site_id", ""))
                        for row in chosen
                    }
                ),
            },
            "canonical_alerts": chosen,
        }
        write_json(output_a2, subset_a2)

        source_static_dir = static_dir(summary_row)
        binary_sha256 = str(
            source_manifest.get("binary_sha256")
            or summary_row.get("provenance", {}).get("binary_sha256")
            or ""
        )
        output_manifest_rows.append(
            {
                **source_manifest,
                "sha256": binary_sha256,
                "project": str(spec.get("project", "")),
                "application_input": str(spec.get("application_input", "")),
                "static_artifact_dir": str(source_static_dir),
                "a2_artifact_path": str(output_a2.resolve()),
            }
        )
        output_summary_rows.append(summary_row)

        alert_rows = []
        for audit_rank, row in enumerate(chosen, start=1):
            alert = {
                "sample_id": sample_id,
                "project": str(spec.get("project", "")),
                "application_input": str(spec.get("application_input", "")),
                "audit_rank": audit_rank,
                "source_a2_rank": int(row.get("rank", 0) or 0),
                "alert_id": str(row.get("alert_id", "")),
                "sink_id": str(row.get("sink_id", "")),
                "sink_label": str(row.get("sink_label", "")),
                "sink_boundary_site_id": str(row.get("sink_boundary_site_id", "")),
                "source_lineage_count": len(list(row.get("source_lineages", []) or [])),
            }
            alert_rows.append(alert)
            flat_alerts.append(alert)
        audit_rows.append(
            {
                "sample_id": sample_id,
                "project": str(spec.get("project", "")),
                "application_input": str(spec.get("application_input", "")),
                "binary_sha256": binary_sha256,
                "source_rankable_alerts": len(candidates),
                "selected_alerts": len(chosen),
                "selected_distinct_sink_boundaries": len(
                    {row["sink_boundary_site_id"] for row in alert_rows}
                ),
                "alerts": alert_rows,
            }
        )

    total_alerts = sum(int(row["selected_alerts"]) for row in audit_rows)
    expected_total = len(selected_specs) * per_firmware
    if total_alerts != expected_total:
        raise AssertionError(f"selected {total_alerts} Alerts, expected {expected_total}")

    manifest_path = output_root / "manifest.json"
    summary_path = output_root / "static_summary.json"
    write_json(
        manifest_path,
        {
            "schema_version": "ct-mini-fresh-discovery-audit-manifest-v1",
            "policy": policy,
            "samples": output_manifest_rows,
        },
    )
    write_json(
        summary_path,
        {
            "schema_version": "ct-mini-fresh-discovery-audit-static-summary-v1",
            "samples_requested": len(output_summary_rows),
            "samples_ok": len(output_summary_rows),
            "samples": output_summary_rows,
        },
    )
    report = {
        "schema_version": "ct-mini-fresh-discovery-audit-selection-report-v1",
        "policy": policy,
        "source_artifacts": {
            "selection_sha256": sha256_file(args_path(selection, output_root, "selection")),
            "fresh_manifest_sha256": sha256_file(args_path(fresh_manifest, output_root, "fresh_manifest")),
            "static_summary_sha256": sha256_file(args_path(static_summary, output_root, "static_summary_source")),
        },
        "counts": {
            "projects": len(project_counts),
            "firmwares": len(audit_rows),
            "alerts": total_alerts,
            "distinct_sink_boundaries": len(
                {(row["sample_id"], row["sink_boundary_site_id"]) for row in flat_alerts}
            ),
        },
        "projects": dict(sorted(project_counts.items())),
        "samples": audit_rows,
    }
    write_json(output_root / "selection_report.json", report)
    write_json(output_root / "selected_alerts.json", {"alerts": flat_alerts})
    with (output_root / "selected_alerts.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(flat_alerts[0]))
        writer.writeheader()
        writer.writerows(flat_alerts)
    return report


def args_path(value: dict[str, Any], output_root: Path, name: str) -> Path:
    """Return the source path recorded by main without leaking it into prepare args."""

    path = value.get("_ct_source_path")
    if not path:
        raise ValueError(f"{name} source path was not recorded")
    return Path(str(path))


def load_with_source(path: Path) -> dict[str, Any]:
    value = read_json(path)
    value["_ct_source_path"] = str(path.resolve())
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--selection",
        type=Path,
        default=ROOT / "datasets/fresh_discovery_audit_100.selection.json",
    )
    parser.add_argument(
        "--fresh-manifest",
        type=Path,
        default=ROOT / "datasets/fresh_discovery_v1.ready.json",
    )
    parser.add_argument(
        "--static-summary",
        type=Path,
        default=ROOT / "artifacts/graph_store_round1/fresh_merged/summary.json",
    )
    parser.add_argument(
        "--a2-root",
        type=Path,
        default=ROOT / "artifacts/graph_store_round1/fresh_a2",
    )
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    report = prepare(
        selection=load_with_source(args.selection),
        fresh_manifest=load_with_source(args.fresh_manifest),
        static_summary=load_with_source(args.static_summary),
        a2_root=args.a2_root,
        output_root=args.out,
    )
    print(json.dumps(report["counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
