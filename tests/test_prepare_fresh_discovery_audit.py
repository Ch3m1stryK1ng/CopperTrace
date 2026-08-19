import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_fresh_discovery_audit.py"
SPEC = importlib.util.spec_from_file_location("prepare_fresh_discovery_audit", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_distinct_sink_boundaries_are_selected_before_alternate_lineages():
    rows = [
        {"rank": 1, "alert_id": "A1", "sink_boundary_site_id": "S1"},
        {"rank": 2, "alert_id": "A2", "sink_boundary_site_id": "S1"},
        {"rank": 3, "alert_id": "A3", "sink_boundary_site_id": "S2"},
        {"rank": 4, "alert_id": "A4", "sink_boundary_site_id": "S3"},
    ]

    selected = MODULE.select_alerts(rows, 3)

    assert [row["alert_id"] for row in selected] == ["A1", "A3", "A4"]


def test_frozen_fresh_selection_materializes_exactly_one_hundred_alerts(tmp_path):
    if not (ROOT / "datasets" / "fresh_discovery_audit_100.selection.json").is_file():
        pytest.skip("fresh-discovery manifests are distributed in the artifact")
    output = tmp_path / "audit"
    report = MODULE.prepare(
        selection=MODULE.load_with_source(
            ROOT / "datasets/fresh_discovery_audit_100.selection.json"
        ),
        fresh_manifest=MODULE.load_with_source(
            ROOT / "datasets/fresh_discovery_v1.ready.json"
        ),
        static_summary=MODULE.load_with_source(
            ROOT / "artifacts/graph_store_round1/fresh_merged/summary.json"
        ),
        a2_root=ROOT / "artifacts/graph_store_round1/fresh_a2",
        output_root=output,
    )

    assert report["counts"] == {
        "projects": 5,
        "firmwares": 20,
        "alerts": 100,
        "distinct_sink_boundaries": 100,
    }
    assert set(report["projects"].values()) == {4}
    assert all(row["selected_alerts"] == 5 for row in report["samples"])
    assert all(
        row["selected_distinct_sink_boundaries"] == 5 for row in report["samples"]
    )

    manifest = json.loads((output / "manifest.json").read_text())
    assert len(manifest["samples"]) == 20
    assert all(row["sha256"] for row in manifest["samples"])
    assert all(Path(row["static_artifact_dir"]).is_dir() for row in manifest["samples"])
    assert sum(
        len(
            json.loads(
                Path(row["a2_artifact_path"]).read_text()
            )["canonical_alerts"]
        )
        for row in manifest["samples"]
    ) == 100
