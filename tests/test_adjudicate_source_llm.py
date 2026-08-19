from __future__ import annotations

import asyncio
import json
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import adjudicate_source_llm as adjudicator  # noqa: E402


def sample_candidate() -> dict:
    return {
        "id": "U0001",
        "candidate_kind": "semantic_callsite_source_candidate",
        "function": "receive_frame",
        "function_id": "fn:00001000",
        "plain_line": 42,
        "callee": "uart_read",
        "source_site": "uart_read(dev, rx_buf, 16)",
        "candidate_source_buffer": "rx_buf",
        "candidate_source_object_id": "stack:00001000:-20:16",
        "site_id": "site:00001000:00001020:4",
        "static_bindings": {
            "call_site_id": "site:00001000:00001020:4",
            "site_binding_status": "verified_direct_call_site",
        },
        "actual_args": ["dev", "rx_buf", "16"],
        "label_hint": "BYTE_STREAM_INGRESS",
        "allowed_source_labels": ["BYTE_STREAM_INGRESS"],
        "source_kind_hint": "receive buffer",
        "known_facts": ["uart_read writes received bytes"],
        "unresolved": ["semantic confirmation required"],
        "function_slice": "void receive_frame(void) { uart_read(dev, rx_buf, 16); }",
    }


def model_decision(candidate: dict, **overrides: object) -> dict:
    decision = {
        "candidate_id": candidate["id"],
        "candidate_hash": adjudicator.candidate_hash(candidate),
        "packet_hash": adjudicator.packet_hash(candidate),
        "decision": "confirmed",
        "source_label": "BYTE_STREAM_INGRESS",
        "source_kind": "uart receive buffer",
        "source_output_binding": "candidate_source_buffer",
        "evidence_refs": ["uart_read call"],
        "notes": "The offered buffer receives UART data.",
    }
    decision.update(overrides)
    return decision


class AdjudicatorValidationTests(unittest.TestCase):
    def test_hashes_are_stable_across_key_order_and_resolution_annotations(self) -> None:
        candidate = sample_candidate()
        reordered = dict(reversed(list(candidate.items())))
        reordered.update(
            {
                "decision": "analysis_unresolved",
                "analysis_status": "blocker",
                "failure_kind": "timeout",
                "output": "source_unconfirmed.json",
            }
        )

        self.assertEqual(
            adjudicator.candidate_hash(candidate), adjudicator.candidate_hash(reordered)
        )
        self.assertEqual(
            adjudicator.packet_hash(candidate), adjudicator.packet_hash(reordered)
        )

    def test_strict_json_rejects_markdown_and_extra_schema_fields(self) -> None:
        candidate = sample_candidate()
        payload = {
            "schema_version": adjudicator.MODEL_RESPONSE_SCHEMA_VERSION,
            "decisions": [model_decision(candidate)],
        }
        with self.assertRaises(json.JSONDecodeError):
            adjudicator.extract_json_object(f"```json\n{json.dumps(payload)}\n```")

        payload["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "keys differ"):
            adjudicator.validate_model_response_shape(payload)

    def test_confirmed_decision_requires_concrete_label_and_offered_binding(self) -> None:
        candidate = sample_candidate()
        accepted = adjudicator.normalize_decision(model_decision(candidate), candidate)
        self.assertEqual(accepted["decision"], "confirmed")
        self.assertEqual(
            accepted["source_output"],
            {"binding_id": "candidate_source_buffer", "expression": "rx_buf"},
        )

        for raw, failure_kind in (
            (model_decision(candidate, source_label="UNKNOWN_SOURCE"), "invalid_confirmed_label"),
            (
                model_decision(candidate, source_output_binding="the receive buffer"),
                "invalid_source_binding",
            ),
            (model_decision(candidate, source_output_binding=None), "invalid_source_binding"),
            (model_decision(candidate, source_label="ISR_MMIO_READ"), "invalid_confirmed_label"),
        ):
            with self.subTest(failure_kind=failure_kind):
                result = adjudicator.normalize_decision(raw, candidate)
                self.assertEqual(result["decision"], "unresolved")
                self.assertEqual(result["failure_kind"], failure_kind)
                self.assertIsNone(result["source_output"])

    def test_hash_mismatch_becomes_retryable_unresolved(self) -> None:
        candidate = sample_candidate()
        raw = model_decision(candidate, packet_hash="0" * 64)
        result = adjudicator.normalize_decision(raw, candidate)
        self.assertEqual(result["decision"], "unresolved")
        self.assertEqual(result["failure_kind"], "hash_mismatch")
        self.assertTrue(adjudicator.is_retryable_adjudication_error(result))

    def test_empty_label_allowlist_or_missing_node_binding_blocks_confirmation(self) -> None:
        for mutation in (
            {"allowed_source_labels": []},
            {"site_id": ""},
            {"candidate_source_object_id": "textobj:weak"},
        ):
            candidate = sample_candidate()
            candidate.update(mutation)
            result = adjudicator.normalize_decision(model_decision(candidate), candidate)
            self.assertEqual(result["decision"], "unresolved")

    def test_retry_unresolved_becomes_analysis_unresolved_blocker(self) -> None:
        candidate = sample_candidate()
        call_count = 0

        async def fake_call(**kwargs: object) -> list[dict]:
            nonlocal call_count
            call_count += 1
            failure_kind = "timeout" if call_count == 1 else "model_unresolved"
            return [
                adjudicator.unresolved_decision(
                    candidate,
                    notes=failure_kind,
                    failure_kind=failure_kind,
                )
            ]

        with mock.patch.object(adjudicator, "call_llm_for_candidates", fake_call):
            decisions, errors = asyncio.run(
                adjudicator.adjudicate_with_batch_retry(
                    candidates=[candidate],
                    sourceagent_root=ROOT,
                    model="test-model",
                    max_code_chars=1000,
                    request_timeout_sec=0.01,
                    batch_size=1,
                )
            )

        self.assertEqual(call_count, 2)
        self.assertEqual(len(errors), 1)
        self.assertEqual(decisions[0]["decision"], "analysis_unresolved")
        self.assertEqual(decisions[0]["failure_kind"], "model_unresolved")
        self.assertNotEqual(decisions[0]["decision"], "rejected")

    def test_scalar_source_uses_value_id_instead_of_object_id(self) -> None:
        candidate = sample_candidate()
        candidate.pop("candidate_source_buffer")
        candidate.pop("candidate_source_object_id")
        candidate["candidate_source_value"] = "event_code"
        candidate["candidate_source_value_id"] = "value:00001000:event-code"
        candidate["static_bindings"]["source_value_id"] = "value:00001000:event-code"
        raw = model_decision(
            candidate,
            source_output_binding="candidate_source_value",
            source_kind="external control value",
        )
        result = adjudicator.normalize_decision(raw, candidate)
        self.assertEqual(result["decision"], "confirmed")
        binding = adjudicator.candidate_output_bindings(candidate)[0]
        self.assertEqual(binding["kind"], "scalar_value")
        self.assertEqual(binding["value_id"], "value:00001000:event-code")

    def test_semantic_slice_is_part_of_llm_packet(self) -> None:
        candidate = sample_candidate()
        candidate["semantic_slice"] = {
            "schema_version": "ct-mini-mmio-semantic-slice-v1",
            "anchor_use": {"use_classes": ["ram_store"]},
        }
        packet = adjudicator.candidate_packet_payload(candidate)
        self.assertEqual(
            packet["semantic_slice"]["anchor_use"]["use_classes"], ["ram_store"]
        )


if __name__ == "__main__":
    unittest.main()
