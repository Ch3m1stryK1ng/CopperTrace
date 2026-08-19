import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location(
    "freeze_fresh_canonical_alerts",
    SCRIPTS / "freeze_fresh_canonical_alerts.py",
)
FREEZE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = FREEZE
SPEC.loader.exec_module(FREEZE)


class FreezeFreshCanonicalAlertsTests(unittest.TestCase):
    def test_legacy_a2_partitions_are_frozen_in_rank_order(self):
        rows = FREEZE.canonical_rows(
            {
                "selected": [{"alert_id": "A2", "rank": 2}],
                "deferred": [{"alert_id": "A3", "rank": 3}],
                "dropped": [{"alert_id": "A1", "rank": 1}],
            }
        )
        self.assertEqual([row["alert_id"] for row in rows], ["A1", "A2", "A3"])

    def test_duplicate_alert_ids_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "unique alert_id"):
            FREEZE.canonical_rows(
                {
                    "selected": [{"alert_id": "A1", "rank": 1}],
                    "deferred": [{"alert_id": "A1", "rank": 2}],
                }
            )


if __name__ == "__main__":
    unittest.main()
