import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


ROOT = Path(__file__).resolve().parents[1]


class ReviewArtifactSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        a2_schema = json.loads(
            (ROOT / "schemas/alert_filter_a2.v4.schema.json").read_text()
        )
        reviewed_schema = json.loads(
            (ROOT / "schemas/reviewed_alerts.v4.schema.json").read_text()
        )
        Draft202012Validator.check_schema(a2_schema)
        Draft202012Validator.check_schema(reviewed_schema)
        cls.a2 = Draft202012Validator(a2_schema)
        cls.reviewed = Draft202012Validator(reviewed_schema)

    def test_a2_v4_accepts_canonical_alerts_without_selection_partition(self):
        artifact = {
            "schema_version": "ct-mini-alert-filter-a2-v4",
            "policy": {
                "name": "COPPERTRACE_A2",
                "ranking_is_reference_only": True,
                "pre_review_top_k": False,
                "all_canonical_alerts_review_eligible": True,
            },
            "counts": {
                "input_static_alerts": 1,
                "canonical_alerts": 1,
                "dropped_invalid": 0,
            },
            "canonical_alerts": [
                {
                    "alert_id": "A1",
                    "sink_id": "K1",
                    "sink_boundary_site_id": "site:1",
                    "vulnerable_parameter_roles": ["len"],
                    "represented_alert_ids": ["A1"],
                    "rank": 23,
                    "rank_vector": [0, 0, 0, 1],
                }
            ],
            "merged_duplicates": [],
            "dropped_invalid": [],
            "non_alert_chains": [],
            "artifact_contradictions": [],
        }
        self.a2.validate(artifact)

        artifact["selected"] = artifact["canonical_alerts"]
        with self.assertRaises(ValidationError):
            self.a2.validate(artifact)

    def test_reviewed_v4_requires_post_review_validation_queue(self):
        artifact = {
            "schema_version": "ct-mini-reviewed-alerts-v4",
            "counts": {
                "reviewed": 1,
                "trupocs": 1,
                "rejected": 0,
                "unresolved": 0,
                "validation_queue": 1,
            },
            "trupocs": [],
            "rejected_alerts": [],
            "unresolved_alerts": [],
            "validation_queue": [
                {
                    "queue_rank": 1,
                    "queue_round": "DISTINCT_SINK_CALLSITE",
                    "alert_id": "A1",
                    "sink_callsite_ids": ["site:1"],
                    "a2_reference_rank": 23,
                }
            ],
        }
        self.reviewed.validate(artifact)


if __name__ == "__main__":
    unittest.main()
