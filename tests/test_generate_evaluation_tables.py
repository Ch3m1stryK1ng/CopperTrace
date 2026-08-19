import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_evaluation_tables.py"
SPEC = importlib.util.spec_from_file_location("generate_evaluation_tables", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)

pytestmark = pytest.mark.skipif(
    not (Path(__file__).resolve().parents[1] / "datasets").is_dir(),
    reason="paper evaluation data is distributed in the artifact",
)


def by_key(rows, key):
    return {row[key]: row for row in rows}


def test_evaluation_table_generator_matches_frozen_artifacts(tmp_path, monkeypatch):
    output = tmp_path / "tables"
    markdown = tmp_path / "tables.md"
    monkeypatch.setattr(
        "sys.argv",
        [
            str(SCRIPT),
            "--output-dir",
            str(output),
            "--markdown",
            str(markdown),
        ],
    )

    assert MODULE.main() == 0

    summary = json.loads((output / "summary.json").read_text())
    tables = summary["tables"]

    datasets = by_key(tables["dataset_overview"], "dataset")
    assert datasets["Development CVE Set"]["cves"] == 33
    assert datasets["Development CVE Set"]["unique_elfs"] == 30
    assert datasets["Evaluation CVE Set"]["cves"] == 24
    assert datasets["Evaluation CVE Set"]["unique_elfs"] == 20
    assert datasets["Fresh Discovery Set"]["unique_elfs"] == 100

    headline = by_key(tables["headline_results"], "dataset")
    assert (headline["Development"]["static_alerts"], headline["Development"]["llm_trupocs"]) == (
        2246,
        1067,
    )
    assert (headline["Evaluation"]["static_alerts"], headline["Evaluation"]["llm_trupocs"]) == (
        1285,
        711,
    )
    assert (headline["Fresh"]["static_alerts"], headline["Fresh"]["a2_canonical"]) == (
        3407,
        2626,
    )

    pipeline = by_key(tables["unique_elf_pipeline"], "dataset")
    assert (pipeline["Development"]["sources"], pipeline["Development"]["sinks"]) == (
        422,
        3249,
    )
    assert (
        pipeline["Development"]["shared_objects"],
        pipeline["Development"]["channelgraph_relations"],
    ) == (593, 7858)
    assert (pipeline["Evaluation"]["sources"], pipeline["Evaluation"]["sinks"]) == (
        540,
        1992,
    )
    assert (pipeline["Fresh"]["sources"], pipeline["Fresh"]["sinks"]) == (
        2285,
        8380,
    )

    cves = by_key(tables["cve_coverage"], "dataset")
    assert (cves["Development"]["static_cves_refound"], cves["Development"]["cves"]) == (
        21,
        33,
    )
    assert (cves["Evaluation"]["static_cves_refound"], cves["Evaluation"]["cves"]) == (
        11,
        24,
    )
    assert cves["Evaluation"]["post_review_cves_retained"] == 9

    review = by_key(tables["llm_review"], "dataset")
    for row in review.values():
        assert row["trupocs"] + row["rejected"] + row["unresolved"] == row["reviewed"]
    assert (review["Development"]["trupocs"], review["Evaluation"]["trupocs"]) == (
        1067,
        711,
    )

    mango = summary["mango_run_status"]
    assert sum(mango.values()) == 200
    failure_explanations = by_key(tables["mango_failure_explanations"], "reason")
    assert set(failure_explanations) == {
        "SINK_NOT_RECOGNIZED",
        "DATA_FLOW_INCOMPLETE",
        "ANALYSIS_FAILED",
        "SOURCE_NOT_MODELED",
        "DIAGNOSTIC_REQUIRED",
    }
    assert "not native Mango error messages" in markdown.read_text()
    mango_rows = [
        row for row in tables["baseline_comparison"] if row["system_stage"] == "Original Mango"
    ]
    assert sum(row["raw_or_static_candidates"] for row in mango_rows) == 7003
    assert sum(row["source_associated_candidates"] for row in mango_rows) == 1
    assert sum(row["final_candidates"] for row in mango_rows) == 0
    assert sum(row["public_cves_refound"] for row in mango_rows) == 0

    assert markdown.exists()
    assert "## 6. Ablations" in markdown.read_text()
