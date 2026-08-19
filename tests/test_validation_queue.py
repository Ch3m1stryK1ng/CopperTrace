import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "build_validation_queue", SCRIPTS / "build_validation_queue.py"
)
QUEUE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(QUEUE)
COMMON_SPEC = importlib.util.spec_from_file_location(
    "validation_common", SCRIPTS / "validation_common.py"
)
COMMON = importlib.util.module_from_spec(COMMON_SPEC)
assert COMMON_SPEC.loader
COMMON_SPEC.loader.exec_module(COMMON)


def trupoc(alert_id: str, site: str, rank: int):
    return {
        "alert": {
            "alert_id": alert_id,
            "sink_boundary_site_id": site,
            "represented_sink_boundary_site_ids": [site],
            "rank": rank,
        }
    }


class ValidationQueueTests(unittest.TestCase):
    def test_distinct_callsites_are_selected_before_extra_lineages(self):
        rows = [
            trupoc("A1", "site:one", 1),
            trupoc("A2", "site:one", 2),
            trupoc("A3", "site:two", 20),
        ]

        queue = QUEUE.build_validation_queue(rows, limit=2)

        self.assertEqual([row["alert_id"] for row in queue], ["A1", "A3"])
        self.assertTrue(
            all(row["queue_round"] == "DISTINCT_SINK_CALLSITE" for row in queue)
        )

    def test_second_round_adds_more_lineages_without_modifying_trupocs(self):
        rows = [
            trupoc("A1", "site:one", 1),
            trupoc("A2", "site:one", 2),
            trupoc("A3", "site:two", 3),
        ]

        queue = QUEUE.build_validation_queue(rows, limit=3)

        self.assertEqual([row["alert_id"] for row in queue], ["A1", "A3", "A2"])
        self.assertEqual(queue[-1]["queue_round"], "ADDITIONAL_SOURCE_LINEAGE")
        self.assertNotIn("queue_rank", rows[0]["alert"])

    def test_rank_never_removes_trupocs_from_input(self):
        rows = [trupoc(f"A{index}", f"site:{index}", index) for index in range(1, 5)]

        queue = QUEUE.build_validation_queue(rows, limit=2)

        self.assertEqual(len(queue), 2)
        self.assertEqual(len(rows), 4)

    def test_queue_resolves_only_to_reviewed_trupocs(self):
        reviewed = {
            "trupocs": [trupoc("A1", "site:one", 1)],
            "validation_queue": [
                {"queue_rank": 1, "alert_id": "A1", "queue_round": "FIRST"}
            ],
        }

        entries = COMMON.reviewed_validation_entries(reviewed)

        self.assertEqual(entries[0][0]["queue_rank"], 1)
        self.assertEqual(entries[0][1]["alert_id"], "A1")

    def test_queue_rejects_non_trupoc_reference(self):
        reviewed = {
            "trupocs": [trupoc("A1", "site:one", 1)],
            "validation_queue": [{"queue_rank": 1, "alert_id": "A2"}],
        }

        with self.assertRaisesRegex(ValueError, "non-TruPoC"):
            COMMON.reviewed_validation_entries(reviewed)


if __name__ == "__main__":
    unittest.main()
