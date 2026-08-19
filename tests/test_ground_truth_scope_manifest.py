from pathlib import Path

import pytest

from scripts.build_ground_truth_scope_manifest import build_scope_manifest


ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(
    not (ROOT / "datasets" / "development_cve.json").is_file(),
    reason="public-CVE manifests are distributed in the artifact",
)


def test_scope_manifest_is_public_only_and_complete() -> None:
    payload = build_scope_manifest(
        [ROOT / "datasets/development_cve.json", ROOT / "datasets/evaluation_cve.json"]
    )
    assert payload["counts"]["cves"] == 57
    assert payload["counts"]["unique_elfs"] == 50
    assert payload["counts"]["in_scope"] == 43
    assert payload["counts"]["out_of_scope"] == 14
    assert payload["counts"]["invalid_firmware_samples"] == 1
    assert payload["counts"]["evaluated_in_scope"] == 42
    assert payload["policy"]["analyzer_results_consulted"] is False
    assert payload["policy"]["llm_results_consulted"] is False
    assert payload["counts"]["in_scope"] + payload["counts"]["out_of_scope"] == 57


def test_scope_uses_enabled_sink_forms() -> None:
    payload = build_scope_manifest(
        [ROOT / "datasets/development_cve.json", ROOT / "datasets/evaluation_cve.json"]
    )
    by_cve = {row["cve"]: row for row in payload["cves"]}
    assert by_cve["CVE-2020-12140"]["scope"] == "IN_SCOPE"
    assert by_cve["CVE-2022-41972"]["scope"] == "OUT_OF_SCOPE"
    assert by_cve["CVE-2021-3319"]["scope"] == "OUT_OF_SCOPE"
    assert by_cve["CVE-2024-5931"]["scope"] == "IN_SCOPE"
    assert by_cve["CVE-2021-21281"]["scope"] == "OUT_OF_SCOPE"
    assert by_cve["CVE-2024-6442"]["scope"] == "OUT_OF_SCOPE"
    assert by_cve["CVE-2024-6135"]["sample_validity"] == "INVALID_FIRMWARE_SAMPLE"
