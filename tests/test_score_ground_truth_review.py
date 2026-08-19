import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "score_ground_truth_review.py"
SPEC = importlib.util.spec_from_file_location("score_ground_truth_review", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def test_expected_source_backed_sink_ids_uses_frozen_headline_boundary():
    value = {
        "public_chain_matches": [
            {"sink_id": "S1", "status": "SOURCE_REACHED_DETERMINISTIC", "matched_public_source": True},
            {"sink_id": "S2", "status": "GRAPH_INCOMPLETE", "matched_public_source": True},
            {"sink_id": "S3", "status": "SOURCE_REACHED_HEURISTIC", "matched_public_source": False},
        ]
    }
    assert MODULE.expected_source_backed_sink_ids(value) == {"S1", "S3"}


def test_partition_ids_uses_review_partitions():
    value = {
        "trupocs": [{"alert": {"sink_id": "T"}}],
        "rejected_alerts": [{"alert": {"sink_id": "R"}}],
        "unresolved_alerts": [{"alert": {"sink_id": "U"}}],
    }
    assert MODULE.partition_ids(value) == {
        "TRUPOC_RETAINED": {"T"},
        "REVIEW_UNRESOLVED": {"U"},
        "REVIEW_REJECTED": {"R"},
    }


def test_aggregate_reports_single_cve_metric():
    result = MODULE.aggregate(
        [
            {"review_status": "TRUPOC_RETAINED"},
            {"review_status": "NOT_STATICALLY_REFOUND"},
        ]
    )
    assert result["cves"] == 2
    assert result["statically_refound"] == 1
    assert result["trupoc_retained"] == 1
