import asyncio
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "run_check_review_corpus", SCRIPTS / "run_check_review_corpus.py"
)
RUNNER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class CheckReviewCorpusTests(unittest.TestCase):
    def test_incomplete_review_partition_is_rejected(self):
        enriched = [
            {"alert": {"alert_id": "A1"}},
            {"alert": {"alert_id": "A2"}},
        ]
        reviewed = {
            "trupocs": [{"alert": {"alert_id": "A1"}}],
            "rejected_alerts": [],
            "unresolved_alerts": [],
        }

        with self.assertRaisesRegex(RuntimeError, "review partition is incomplete"):
            RUNNER._assert_complete_review(enriched, reviewed)

    def test_decompiled_c_falls_back_to_program_facts_sibling(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            facts = root / "firmware.program_facts.json"
            decompiled = root / "plain_decompiled.c"
            facts.write_text("{}", encoding="utf-8")
            decompiled.write_text("void f(void) {}\n", encoding="utf-8")

            resolved = RUNNER._resolve_decompiled_c_path(
                {"sample_id": "sample-without-path"},
                {"sample_id": "sample-without-path", "program_facts": str(facts)},
                facts,
            )

            self.assertEqual(resolved, decompiled)

    def test_content_addressed_review_cache_ignores_sample_names(self):
        enriched = [{"alert": {"alert_id": "A1"}}]
        first = RUNNER._review_fingerprint(
            binary_sha256="binary",
            decompiled_sha256="code",
            program_facts_sha256="facts",
            enriched=enriched,
            mode="live",
            model="openai/gpt-5.6-sol",
        )
        second = RUNNER._review_fingerprint(
            binary_sha256="binary",
            decompiled_sha256="code",
            program_facts_sha256="facts",
            enriched=enriched,
            mode="live",
            model="openai/gpt-5.6-sol",
        )
        different = RUNNER._review_fingerprint(
            binary_sha256="different-binary",
            decompiled_sha256="code",
            program_facts_sha256="facts",
            enriched=enriched,
            mode="live",
            model="openai/gpt-5.6-sol",
        )

        self.assertEqual(first, second)
        self.assertNotEqual(first, different)

    def test_reused_review_has_zero_incremental_model_cost(self):
        original = {
            "counts": {"reviewed": 1, "trupocs": 1, "rejected": 0, "unresolved": 0,
                       "llm_calls": 2, "reviewer_stage_invocations": 1},
            "trupocs": [
                {
                    "alert": {"alert_id": "A1"},
                    "review_provenance": {"llm_calls": 2, "reviewer_stage_invocations": 1},
                }
            ],
            "rejected_alerts": [],
            "unresolved_alerts": [],
        }

        reused = RUNNER._clone_reused_review(original, source_sample_id="sample-a")

        self.assertEqual(reused["counts"]["llm_calls"], 0)
        self.assertEqual(reused["counts"]["reviewer_stage_invocations"], 0)
        self.assertTrue(
            reused["trupocs"][0]["review_provenance"]["equivalent_review_reused"]
        )
        self.assertEqual(original["counts"]["llm_calls"], 2)

    def test_execution_failure_retry_replaces_only_failed_row(self):
        retained = {
            "alert": {"alert_id": "A1"},
            "review_status": "RESOLVED",
            "review_provenance": {"llm_calls": 1, "reviewer_stage_invocations": 1},
            "whole_review": {"missing_evidence": []},
        }
        failed = {
            "alert": {"alert_id": "A2"},
            "review_status": "UNRESOLVED",
            "review_provenance": {"llm_calls": 4, "reviewer_stage_invocations": 1},
            "whole_review": {"missing_evidence": ["REVIEW_EXECUTION_FAILED"]},
        }
        retried = {
            "alert": {"alert_id": "A2"},
            "review_status": "RESOLVED",
            "review_provenance": {"llm_calls": 1, "reviewer_stage_invocations": 1},
            "whole_review": {"missing_evidence": []},
        }

        merged = RUNNER._merge_execution_failure_retries(
            [retained, failed], [retried]
        )

        self.assertEqual([row["alert"]["alert_id"] for row in merged], ["A1", "A2"])
        self.assertEqual(merged[1]["review_provenance"]["llm_calls"], 5)
        self.assertEqual(
            merged[1]["review_provenance"]["execution_failure_repair"][
                "prior_failed_alerts"
            ],
            1,
        )

    def test_execution_failed_batch_is_split_without_changing_semantics(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            code = root / "decompiled.c"
            code.write_text("void f(void) {}\n", encoding="utf-8")
            store = RUNNER.ReviewEvidenceStore(
                neutral_firmware_id="FW0001",
                decompiled_c_path=code,
                program_facts={"functions": []},
            )
            enriched = [
                {
                    "alert": {"alert_id": f"A{index}"},
                    "sink_review_question": {},
                    "check_evidence": {},
                }
                for index in range(4)
            ]
            calls = []

            async def reviewer(batch, _evidence_store):
                calls.append(len(batch))
                if len(batch) > 1:
                    return RUNNER.StageInvocation(
                        response=None,
                        provenance={"stage": "whole_alert", "model_requests": 2},
                        error="synthetic batch failure",
                    )
                alert_id = batch[0]["alert"]["alert_id"]
                return RUNNER.StageInvocation(
                    response={
                        "schema_version": RUNNER.REVIEW_SCHEMA_VERSION,
                        "decisions": [
                            {
                                "alert_id": alert_id,
                                "decision": "UNRESOLVED",
                                "dangerous_condition": "",
                                "blocking_relation": "",
                                "evidence_refs": [],
                                "missing_evidence": ["OBJECT_CAPACITY_UNKNOWN"],
                                "reason": "semantic evidence remains incomplete",
                            }
                        ],
                    },
                    provenance={"stage": "whole_alert", "model_requests": 1},
                )

            rows = asyncio.run(
                RUNNER._review_rows(
                    enriched,
                    base_store=store,
                    reviewer=reviewer,
                    max_concurrency=1,
                    max_batch_size=4,
                )
            )

            self.assertEqual(calls, [4, 2, 1, 1, 2, 1, 1])
            self.assertEqual(len(rows), 4)
            self.assertTrue(
                all(row["whole_review"]["missing_evidence"] == ["OBJECT_CAPACITY_UNKNOWN"] for row in rows)
            )
            self.assertGreater(
                sum(row["review_provenance"]["llm_calls"] for row in rows), 4
            )

    def test_mock_run_preserves_alert_and_keeps_public_evidence_post_review(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            sample_id = "sample-one"
            static_root = root / "static"
            a2_root = root / "a2"
            output_root = root / "review"
            workspace = root / "workspace"
            sample_static = static_root / "per_sample" / sample_id
            sample_a2 = a2_root / "per_sample" / sample_id
            decompiled = root / "input.c"
            facts = root / "facts.json"
            decompiled.write_text("void copy(void) { return; }\n", encoding="utf-8")
            write_json(
                facts,
                {
                    "functions": [
                        {
                            "function_id": "fn:1",
                            "name": "copy",
                            "pcode_ops": [],
                            "basic_blocks": [],
                        }
                    ]
                },
            )
            chain = {
                "chain_id": "A1",
                "sink_id": "K1",
                "sink_function_id": "fn:1",
                "sink_site_id": "site:1",
                "status": "SOURCE_REACHED_DETERMINISTIC",
                "parameter_results": [
                    {"role": "len", "start_value_id": "value:len", "paths": []}
                ],
            }
            sink = {
                "id": "K1",
                "label": "COPY_SINK",
                "function_id": "fn:1",
                "site_id": "site:1",
                "vulnerable_parameters": [
                    {
                        "role": "len",
                        "value_id": "value:len",
                        "actual_expression": "len",
                    }
                ],
            }
            canonical_alert = {
                "alert_id": "A1",
                "sink_id": "K1",
                "sink_label": "COPY_SINK",
                "vulnerable_parameter_roles": ["len"],
                "represented_alert_ids": ["A1"],
                "represented_sink_boundary_site_ids": ["site:1"],
                "rank": 23,
            }
            write_json(sample_static / "chains.json", {"chains": [chain]})
            write_json(sample_static / "sinks.json", {"sink_startpoints": [sink]})
            write_json(
                sample_static / "public_match.json",
                {
                    "public_chain_matches": [
                        {
                            "sink_id": "K1",
                            "status": "SOURCE_REACHED_DETERMINISTIC",
                        }
                    ]
                },
            )
            write_json(
                sample_a2 / "alert_filter.json",
                {"canonical_alerts": [canonical_alert]},
            )
            manifest = {
                "samples": [
                    {
                        "sample_id": sample_id,
                        "sha256": "abc123",
                        "decompiled_c_path": str(decompiled),
                    }
                ]
            }
            input_summary = {
                "samples": [{"sample_id": sample_id, "program_facts": str(facts)}]
            }

            summary = asyncio.run(
                RUNNER.run_corpus(
                    manifest=manifest,
                    input_summary=input_summary,
                    static_root=static_root,
                    a2_root=a2_root,
                    output_root=output_root,
                    workspace_root=workspace,
                    mode="mock",
                    sourceagent_root=Path("/not/used"),
                    model="",
                    expected_model_alias="",
                    preflight_record=None,
                    max_concurrency=1,
                    max_context_ops=16,
                    max_check_candidates=4,
                )
            )
            reviewed_path = (
                output_root / "per_sample" / sample_id / "reviewed_alerts.json"
            )
            reviewed = json.loads(reviewed_path.read_text(encoding="utf-8"))

            self.assertEqual(summary["counts"]["samples_completed"], 1)
            self.assertEqual(summary["counts"]["a2_canonical"], 1)
            self.assertEqual(summary["status"], "COMPLETE")
            self.assertEqual(summary["counts"]["trupocs"], 0)
            self.assertEqual(summary["counts"]["unresolved"], 1)
            self.assertEqual(summary["counts"]["review_batches"], 1)
            self.assertEqual(summary["counts"]["llm_calls"], 0)
            self.assertEqual(
                reviewed["unresolved_alerts"][0]["alert"], canonical_alert
            )
            self.assertEqual(reviewed["validation_queue"], [])
            self.assertNotIn("public_match", reviewed["run"]["review_inputs"])
            self.assertFalse(summary["samples"][0]["public_cve_retained_as_trupoc"])
            self.assertTrue(
                summary["samples"][0]["public_cve_retained_after_review"]
            )
            self.assertTrue((workspace / "FW0001" / "decompiled.c").is_file())

            resumed = asyncio.run(
                RUNNER.run_corpus(
                    manifest=manifest,
                    input_summary=input_summary,
                    static_root=static_root,
                    a2_root=a2_root,
                    output_root=output_root,
                    workspace_root=workspace,
                    mode="mock",
                    sourceagent_root=Path("/not/used"),
                    model="",
                    expected_model_alias="",
                    preflight_record=None,
                    max_concurrency=1,
                    max_context_ops=16,
                    max_check_candidates=4,
                    resume=True,
                )
            )
            self.assertEqual(resumed["counts"]["samples_resumed"], 1)
            self.assertEqual(resumed["counts"]["unresolved"], 1)


if __name__ == "__main__":
    unittest.main()
