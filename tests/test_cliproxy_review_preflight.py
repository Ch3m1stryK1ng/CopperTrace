import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location(
    "cliproxy_review_preflight", SCRIPTS / "cliproxy_review_preflight.py"
)
PREFLIGHT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = PREFLIGHT
SPEC.loader.exec_module(PREFLIGHT)


class CLIProxyReviewPreflightTests(unittest.TestCase):
    def test_requires_the_exact_requested_model(self):
        with mock.patch.object(
            PREFLIGHT,
            "fetch_models",
            return_value={"data": [{"id": "gpt-5.6-sol"}, {"id": "other"}]},
        ), mock.patch.object(
            PREFLIGHT,
            "probe_model",
            return_value={"resolved_model": "gpt-5.6-sol", "choice_count": 1},
        ):
            record = PREFLIGHT.build_preflight_record(
                base_url="http://127.0.0.1:8318/v1",
                api_key="local",
                expected_model_alias="gpt-5.6-sol",
                timeout=1,
            )

        self.assertEqual(record["status"], "READY")
        self.assertTrue(record["exact_model_available"])
        self.assertTrue(record["exact_model_callable"])
        self.assertFalse(record["fallback_allowed"])

    def test_does_not_fallback_to_another_available_model(self):
        with mock.patch.object(
            PREFLIGHT,
            "fetch_models",
            return_value={"data": [{"id": "gpt-5.4"}]},
        ):
            record = PREFLIGHT.build_preflight_record(
                base_url="http://127.0.0.1:8318/v1",
                api_key="local",
                expected_model_alias="gpt-5.6-sol",
                timeout=1,
            )

        self.assertEqual(record["status"], "MODEL_UNAVAILABLE")
        self.assertFalse(record["exact_model_available"])
        self.assertEqual(record["available_model_ids"], ["gpt-5.4"])

    def test_listed_but_uncallable_model_is_not_ready(self):
        with mock.patch.object(
            PREFLIGHT,
            "fetch_models",
            return_value={"data": [{"id": "gpt-5.6-sol"}]},
        ), mock.patch.object(
            PREFLIGHT,
            "probe_model",
            side_effect=OSError("upstream stream closed"),
        ):
            record = PREFLIGHT.build_preflight_record(
                base_url="http://127.0.0.1:8318/v1",
                api_key="local",
                expected_model_alias="gpt-5.6-sol",
                timeout=1,
            )

        self.assertEqual(record["status"], "MODEL_UNCALLABLE")
        self.assertTrue(record["exact_model_available"])
        self.assertFalse(record["exact_model_callable"])

    def test_proxy_failure_is_explicit(self):
        with mock.patch.object(
            PREFLIGHT,
            "fetch_models",
            side_effect=OSError("connection refused"),
        ):
            record = PREFLIGHT.build_preflight_record(
                base_url="http://127.0.0.1:8318/v1",
                api_key="local",
                expected_model_alias="gpt-5.6-sol",
                timeout=1,
            )

        self.assertEqual(record["status"], "PROXY_UNAVAILABLE")
        self.assertIn("connection refused", record["error"])


if __name__ == "__main__":
    unittest.main()
