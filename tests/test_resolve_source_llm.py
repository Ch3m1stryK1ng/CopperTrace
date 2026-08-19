from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

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
            "memory_store_site_id": "site:00001000:00001024:5",
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


class ResolverCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.sources_path = self.root / "sources.json"
        self.unconfirmed_path = self.root / "source_unconfirmed.json"
        self.response_path = self.root / "response.json"
        self.dropped_path = self.root / "source_dropped.json"
        self.candidate = sample_candidate()
        self.sources_path.write_text(
            json.dumps({"confirmed_sources": [], "counts": {}}) + "\n"
        )
        self._write_unconfirmed()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _write_unconfirmed(self) -> None:
        self.unconfirmed_path.write_text(
            json.dumps(
                {
                    "schema_version": "ct-mini-source-unconfirmed-v1",
                    "counts": {"candidates": 1},
                    "candidates": [self.candidate],
                },
                indent=2,
            )
            + "\n"
        )

    def _provenance(self) -> dict:
        return adjudicator.build_run_provenance(
            candidates=[self.candidate],
            source_unconfirmed_json=self.unconfirmed_path,
            source_unconfirmed_text=self.unconfirmed_path.read_text(),
            model="test-model",
            max_code_chars=1000,
            request_timeout_sec=1.0,
            batch_size=1,
            attempts=[],
        )

    def _decision(self, outcome: str = "confirmed", **overrides: object) -> dict:
        decision = {
            "candidate_id": self.candidate["id"],
            "candidate_hash": adjudicator.candidate_hash(self.candidate),
            "packet_hash": adjudicator.packet_hash(self.candidate),
            "decision": outcome,
            "source_label": (
                "BYTE_STREAM_INGRESS" if outcome == "confirmed" else "UNKNOWN_SOURCE"
            ),
            "source_kind": "uart receive buffer" if outcome == "confirmed" else "",
            "source_output": (
                {"binding_id": "candidate_source_buffer", "expression": "rx_buf"}
                if outcome == "confirmed"
                else None
            ),
            "evidence_refs": ["uart_read call"],
            "notes": "test decision",
            "failure_kind": "model_unresolved" if outcome == "analysis_unresolved" else None,
        }
        decision.update(overrides)
        return decision

    def _write_response(self, decisions: list[dict]) -> None:
        self.response_path.write_text(
            adjudicator.format_response(decisions, self._provenance())
        )

    def _run_resolver(self, *, drop_unresolved: bool = True) -> subprocess.CompletedProcess:
        command = [
            sys.executable,
            str(SCRIPTS / "resolve_source_llm.py"),
            "--sources-json",
            str(self.sources_path),
            "--source-unconfirmed-json",
            str(self.unconfirmed_path),
            "--response",
            str(self.response_path),
            "--source-dropped-json",
            str(self.dropped_path),
        ]
        if drop_unresolved:
            command.append("--drop-unresolved")
        return subprocess.run(command, check=True, capture_output=True, text=True)

    def _assert_blocked_not_rejected(self, expected_failure: str) -> None:
        sources = json.loads(self.sources_path.read_text())
        unconfirmed = json.loads(self.unconfirmed_path.read_text())
        dropped = json.loads(self.dropped_path.read_text())
        self.assertEqual(sources["confirmed_sources"], [])
        self.assertFalse(sources["next_stage_ready"])
        self.assertEqual(sources["resolution"]["rejected_total"], 0)
        self.assertEqual(sources["resolution"]["analysis_unresolved_blockers"], 1)
        self.assertEqual(dropped["dropped_sources"], [])
        candidate = unconfirmed["candidates"][0]
        self.assertEqual(candidate["decision"], "analysis_unresolved")
        self.assertEqual(candidate["analysis_status"], "blocker")
        self.assertEqual(candidate["failure_kind"], expected_failure)

    def test_valid_confirmed_output_is_exact_candidate_binding(self) -> None:
        self._write_response([self._decision()])
        self._run_resolver()

        sources = json.loads(self.sources_path.read_text())
        self.assertTrue(sources["next_stage_ready"])
        self.assertEqual(sources["resolution"]["llm_confirmed_total"], 1)
        confirmed = sources["confirmed_sources"][0]
        self.assertEqual(confirmed["label"], "BYTE_STREAM_INGRESS")
        self.assertEqual(confirmed["source_buffer"], "rx_buf")
        self.assertEqual(confirmed["value_expr"], "rx_buf")
        self.assertEqual(confirmed["source_output_binding"], "candidate_source_buffer")
        self.assertEqual(confirmed["source_object_id"], "stack:00001000:-20:16")
        self.assertEqual(confirmed["site_id"], "site:00001000:00001020:4")
        self.assertEqual(confirmed["llm_provenance"]["model"]["requested"], "test-model")
        self.assertRegex(confirmed["llm_provenance"]["packet_hash"], r"^[0-9a-f]{64}$")

    def test_missing_response_is_blocker_even_with_drop_unresolved(self) -> None:
        self._run_resolver()
        self._assert_blocked_not_rejected("missing_response")

    def test_parse_error_is_blocker_even_with_drop_unresolved(self) -> None:
        self.response_path.write_text("not json\n")
        self._run_resolver()
        self._assert_blocked_not_rejected("response_parse_or_schema_error")

    def test_missing_decision_is_blocker_even_with_drop_unresolved(self) -> None:
        self._write_response([])
        self._run_resolver()
        self._assert_blocked_not_rejected("missing_decision")

    def test_analysis_unresolved_is_never_dropped(self) -> None:
        self._write_response([self._decision("analysis_unresolved")])
        self._run_resolver()
        self._assert_blocked_not_rejected("model_unresolved")

    def test_hash_mismatch_blocks_confirmed_decision(self) -> None:
        self._write_response([self._decision(packet_hash="0" * 64)])
        self._run_resolver()
        self._assert_blocked_not_rejected("packet_hash_mismatch")

    def test_natural_language_source_output_blocks_confirmed_decision(self) -> None:
        self._write_response(
            [
                self._decision(
                    source_output={
                        "binding_id": "candidate_source_buffer",
                        "expression": "the bytes returned by uart_read",
                    }
                )
            ]
        )
        self._run_resolver()
        self._assert_blocked_not_rejected("invalid_source_output")

    def test_unknown_label_blocks_confirmed_decision(self) -> None:
        self._write_response([self._decision(source_label="UNKNOWN_SOURCE")])
        self._run_resolver()
        self._assert_blocked_not_rejected("invalid_confirmed_label")

    def test_site_id_must_belong_to_function_id(self) -> None:
        self.candidate["function_id"] = "fn:00002000"
        self._write_unconfirmed()
        self._write_response([self._decision()])
        self._run_resolver()
        self._assert_blocked_not_rejected("missing_static_node_binding")

    def test_verified_status_requires_bound_pcode_site(self) -> None:
        self.candidate["static_bindings"].pop("call_site_id")
        self._write_unconfirmed()
        self._write_response([self._decision()])
        self._run_resolver()
        self._assert_blocked_not_rejected("missing_static_node_binding")

    def test_only_valid_explicit_rejection_is_dropped(self) -> None:
        self._write_response([self._decision("rejected")])
        self._run_resolver()

        sources = json.loads(self.sources_path.read_text())
        unconfirmed = json.loads(self.unconfirmed_path.read_text())
        dropped = json.loads(self.dropped_path.read_text())
        self.assertTrue(sources["next_stage_ready"])
        self.assertEqual(sources["resolution"]["rejected_total"], 1)
        self.assertEqual(sources["resolution"]["analysis_unresolved_blockers"], 0)
        self.assertEqual(len(dropped["dropped_sources"]), 1)
        self.assertEqual(dropped["dropped_sources"][0]["drop_kind"], "llm_semantic_rejected")
        self.assertEqual(unconfirmed["candidates"][0]["decision"], "rejected")

    def test_invalid_response_removes_stale_llm_confirmation(self) -> None:
        stale = {
            "id": "SO0007",
            "confirmation_source": "llm_review",
            "source_candidate_id": self.candidate["id"],
            "source_buffer": "rx_buf",
        }
        self.sources_path.write_text(
            json.dumps({"confirmed_sources": [stale], "counts": {}}) + "\n"
        )
        self.response_path.write_text("{}\n")
        self._run_resolver()
        self._assert_blocked_not_rejected("response_parse_or_schema_error")

    def test_removed_candidate_stale_confirmation_is_never_retained(self) -> None:
        stale = {
            "id": "SO0099",
            "confirmation_source": "llm_review",
            "source_candidate_id": "REMOVED",
            "source_buffer": "old_buf",
        }
        self.sources_path.write_text(
            json.dumps({"confirmed_sources": [stale], "counts": {}}) + "\n"
        )
        self._write_response([self._decision()])
        self._run_resolver()
        sources = json.loads(self.sources_path.read_text())
        self.assertEqual(len(sources["confirmed_sources"]), 1)
        self.assertEqual(sources["confirmed_sources"][0]["source_candidate_id"], "U0001")

    def test_partial_response_is_fail_closed(self) -> None:
        second = dict(self.candidate)
        second.update(
            {
                "id": "U0002",
                "source_site": "uart_read(dev, second_buf, 16)",
                "candidate_source_buffer": "second_buf",
                "candidate_source_object_id": "stack:00001000:-40:16",
                "site_id": "site:00001000:00001040:4",
            }
        )
        self.unconfirmed_path.write_text(
            json.dumps({"candidates": [self.candidate, second], "counts": {"candidates": 2}})
            + "\n"
        )
        provenance = adjudicator.build_run_provenance(
            candidates=[self.candidate],
            source_unconfirmed_json=self.unconfirmed_path,
            source_unconfirmed_text=self.unconfirmed_path.read_text(),
            model="test-model",
            max_code_chars=1000,
            request_timeout_sec=1.0,
            batch_size=1,
            attempts=[],
        )
        self.response_path.write_text(
            adjudicator.format_response([self._decision()], provenance)
        )
        self._run_resolver()
        sources = json.loads(self.sources_path.read_text())
        self.assertFalse(sources["next_stage_ready"])
        self.assertEqual(sources["confirmed_sources"], [])
        self.assertEqual(sources["resolution"]["unresolved_blockers"], 2)
        self.assertEqual(
            sources["resolution"]["response_error"]["kind"],
            "partial_response_not_allowed",
        )


if __name__ == "__main__":
    unittest.main()
