import asyncio
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

STORE_SPEC = importlib.util.spec_from_file_location(
    "review_evidence_store", SCRIPTS / "review_evidence_store.py"
)
STORE = importlib.util.module_from_spec(STORE_SPEC)
assert STORE_SPEC.loader
sys.modules[STORE_SPEC.name] = STORE
STORE_SPEC.loader.exec_module(STORE)

REVIEW_SPEC = importlib.util.spec_from_file_location(
    "review_alerts_llm", SCRIPTS / "review_alerts_llm.py"
)
REVIEW = importlib.util.module_from_spec(REVIEW_SPEC)
assert REVIEW_SPEC.loader
sys.modules[REVIEW_SPEC.name] = REVIEW
REVIEW_SPEC.loader.exec_module(REVIEW)


def enriched(alert_id="A1", *, checks=True):
    candidates = (
        [
            {
                "check_id": f"check:{alert_id}",
                "kind": "BRANCH_GATED_CHECK",
                "site_id": f"site:check:{alert_id}",
                "evidence_level": "deterministic",
            }
        ]
        if checks
        else []
    )
    return {
        "alert": {
            "alert_id": alert_id,
            "sink_id": f"sink:{alert_id}",
            "sink_label": "COPY_SINK",
            "sink_boundary_site_id": f"site:sink:{alert_id}",
            "selection": "SELECTED",
        },
        "sink_review_question": {
            "question": "Can the copy exceed its destination?",
            "destination": {
                "value_id": f"value:dst:{alert_id}",
                "object_id": f"object:dst:{alert_id}",
            },
        },
        "check_evidence": {
            "collection_status": "COMPLETE",
            "check_candidate_count": len(candidates),
            "represented_alerts": [
                {
                    "alert_id": alert_id,
                    "parameters": [
                        {"role": "len", "check_candidates": candidates}
                    ],
                }
            ],
            "destination_capacity_evidence": [],
        },
    }


def response(rows):
    return {
        "schema_version": REVIEW.REVIEW_SCHEMA_VERSION,
        "decisions": rows,
    }


def decision(alert_id="A1", semantic="TRUPOC", *, refs=None):
    return {
        "alert_id": alert_id,
        "decision": semantic,
        "dangerous_condition": "copy range exceeds destination",
        "blocking_relation": "bound governs copy" if semantic == "REJECT" else "",
        "evidence_refs": refs if refs is not None else [f"site:sink:{alert_id}"],
        "missing_evidence": ["destination extent"] if semantic == "UNRESOLVED" else [],
        "reason": "fixture decision",
    }


class ReviewAlertsLLMTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        code = Path(self.temp.name) / "decompiled.c"
        code.write_text("void f(void) {}\n", encoding="utf-8")
        self.base_store = STORE.ReviewEvidenceStore(
            neutral_firmware_id="FW0001",
            decompiled_c_path=code,
            program_facts={"functions": []},
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_batch(self, batch, invocation, *, scoped=True):
        async def invoke(_batch, _store):
            return invocation

        store = self.base_store.fork(
            allowed_references_by_alert=(
                REVIEW.alert_namespaces(batch) if scoped else None
            )
        )
        return asyncio.run(
            REVIEW.review_enriched_batch(
                batch, evidence_store=store, reviewer=invoke
            )
        )

    def test_no_check_alert_still_reaches_whole_alert_reviewer(self):
        rows = self.run_batch(
            [enriched(checks=False)],
            REVIEW.StageInvocation(
                response([decision()]), {"stage": "whole_alert", "model_requests": 1}
            ),
        )

        self.assertEqual((rows[0]["review_action"], rows[0]["review_status"]), ("RETAIN", "RESOLVED"))
        self.assertEqual(rows[0]["whole_review"]["decision"], "TRUPOC")
        self.assertEqual(rows[0]["review_provenance"]["llm_calls"], 1)

    def test_prompt_does_not_extend_entry_checks_across_state_mutation(self):
        self.assertIn(
            "remains valid after relevant state mutation",
            REVIEW.WHOLE_ALERT_SYSTEM_PROMPT,
        )
        self.assertIn("repeated list traversal", REVIEW.WHOLE_ALERT_SYSTEM_PROMPT)

    def test_prompt_requires_positive_impact_evidence(self):
        self.assertIn("security-relevant consequence", REVIEW.WHOLE_ALERT_SYSTEM_PROMPT)
        self.assertIn(
            "Missing Check or object-capacity evidence alone",
            REVIEW.WHOLE_ALERT_SYSTEM_PROMPT,
        )

    def test_single_review_can_reject_with_bound_evidence(self):
        rows = self.run_batch(
            [enriched()],
            REVIEW.StageInvocation(
                response([decision(semantic="REJECT", refs=["check:A1"])]),
                {"stage": "whole_alert", "model_requests": 1},
            ),
        )
        grouped = REVIEW.group_reviewed_alerts(rows)

        self.assertEqual(grouped["counts"]["rejected"], 1)
        self.assertEqual(grouped["counts"]["reviewer_stage_invocations"], 1)

    def test_semantic_uncertainty_is_retained_unresolved(self):
        rows = self.run_batch(
            [enriched()],
            REVIEW.StageInvocation(
                response([decision(semantic="UNRESOLVED", refs=[])]),
                {"stage": "whole_alert", "model_requests": 1},
            ),
        )
        self.assertEqual((rows[0]["review_action"], rows[0]["review_status"]), ("RETAIN", "UNRESOLVED"))

    def test_hallucinated_evidence_makes_atomic_batch_unresolved(self):
        rows = self.run_batch(
            [enriched()],
            REVIEW.StageInvocation(
                response([decision(refs=["invented:evidence"])]),
                {"stage": "whole_alert", "model_requests": 1},
            ),
        )

        self.assertEqual(rows[0]["review_status"], "UNRESOLVED")
        self.assertEqual(rows[0]["review_reason"], "whole_alert_review_protocol_invalid")

    def test_source_lineage_fingerprint_is_inside_alert_namespace(self):
        row = enriched()
        row["alert"]["source_lineage_fingerprints"] = ["lineage:source-A1"]
        rows = self.run_batch(
            [row],
            REVIEW.StageInvocation(
                response([decision(refs=["lineage:source-A1"])]),
                {"stage": "whole_alert", "model_requests": 1},
            ),
        )

        self.assertEqual(rows[0]["review_status"], "RESOLVED")
        self.assertEqual(rows[0]["whole_review"]["evidence_refs"], ["lineage:source-A1"])

    def test_execution_failure_is_not_semantic_rejection(self):
        rows = self.run_batch(
            [enriched()],
            REVIEW.StageInvocation(None, {"attempts": []}, error="timeout"),
        )
        self.assertEqual((rows[0]["review_action"], rows[0]["review_status"]), ("RETAIN", "UNRESOLVED"))

    def test_batch_requires_exactly_one_result_per_alert(self):
        batch = [enriched("A1"), enriched("A2")]
        rows = self.run_batch(
            batch,
            REVIEW.StageInvocation(
                response([decision("A1")]),
                {"stage": "whole_alert", "model_requests": 1},
            ),
        )

        self.assertEqual([row["review_status"] for row in rows], ["UNRESOLVED", "UNRESOLVED"])

    def test_cross_alert_evidence_reference_rejects_entire_batch(self):
        batch = [enriched("A1"), enriched("A2")]
        rows = self.run_batch(
            batch,
            REVIEW.StageInvocation(
                response(
                    [
                        decision("A1", refs=["site:sink:A2"]),
                        decision("A2"),
                    ]
                ),
                {"stage": "whole_alert", "model_requests": 1},
            ),
        )
        self.assertTrue(all(row["review_status"] == "UNRESOLVED" for row in rows))

    def test_batch_model_cost_is_counted_once(self):
        batch = [enriched("A1"), enriched("A2")]
        rows = self.run_batch(
            batch,
            REVIEW.StageInvocation(
                response([decision("A1"), decision("A2")]),
                {"stage": "whole_alert", "model_requests": 1},
            ),
        )
        grouped = REVIEW.group_reviewed_alerts(rows)
        self.assertEqual(grouped["counts"]["llm_calls"], 1)
        self.assertEqual(grouped["counts"]["reviewer_stage_invocations"], 1)

    def test_invalid_final_state_is_rejected_by_grouping(self):
        with self.assertRaises(REVIEW.ReviewProtocolError):
            REVIEW.group_reviewed_alerts(
                [{"review_action": "REJECT", "review_status": "UNRESOLVED"}]
            )


if __name__ == "__main__":
    unittest.main()
