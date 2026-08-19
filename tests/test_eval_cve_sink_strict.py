from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import eval_cve_sink_mining as evaluator  # noqa: E402


class StrictSinkEvaluatorTests(unittest.TestCase):
    def test_only_deterministic_effects_and_boundaries_are_exposed(self) -> None:
        rows = [
            {
                "id": "sink:1",
                "decision": "ACCEPT_DETERMINISTIC",
                "label": "COPY_SINK",
                "function": "inner",
                "callee": "memcpy",
                "site_id": "site:inner",
                "boundary_callsites": [{
                    "function": "caller",
                    "callee": "random_wrapper",
                    "site_id": "site:caller",
                    "expr": "random_wrapper(dst, src, len)",
                }],
            },
            {
                "id": "sink:2",
                "decision": "ACCEPT_HEURISTIC",
                "label": "STORE_SINK",
                "function": "ignored",
                "boundary_callsites": [],
            },
        ]
        views = evaluator.deterministic_sink_views(rows)
        self.assertEqual(len(views), 2)
        self.assertEqual(views[1]["function"], "caller")
        self.assertEqual(views[1]["label"], "COPY_SINK")
        self.assertEqual(views[1]["id"], "sink:1")

    def test_expected_site_id_is_checked(self) -> None:
        expected = {
            "callee": "memcpy",
            "site_id_regex": r"^site:2000:",
        }
        self.assertTrue(evaluator.row_matches_expected_site(
            expected, {"callee": "memcpy", "site_id": "site:2000:2010:1"}
        ))
        self.assertFalse(evaluator.row_matches_expected_site(
            expected, {"callee": "memcpy", "site_id": "site:3000:3010:1"}
        ))


if __name__ == "__main__":
    unittest.main()
