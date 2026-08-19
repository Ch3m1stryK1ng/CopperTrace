import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "filter_alerts_for_validation", SCRIPTS / "filter_alerts_for_validation.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class ValidationFilterTests(unittest.TestCase):
    def test_selects_source_backed_supported_alert_without_rewriting_it(self):
        chains = {
            "chains": [
                {
                    "chain_id": "chain:1",
                    "sink_id": "sink:1",
                    "sink_site_id": "site:sink",
                    "sink_label": "COPY_SINK",
                    "status": "SOURCE_REACHED_DETERMINISTIC",
                    "parameter_results": [
                        {
                            "status": "SOURCE_REACHED_DETERMINISTIC",
                            "paths": [
                                {
                                    "source_id": "SO1",
                                    "path_precision": "EXACT",
                                    "path": [
                                        {
                                            "kind": "ACTUAL_FORMAL",
                                            "site_id": "site:caller",
                                        }
                                    ],
                                }
                            ],
                            "blockers": [],
                        }
                    ],
                }
            ]
        }
        sinks = {"sink_startpoints": [{"id": "sink:1", "label": "COPY_SINK"}]}
        result = MODULE.filter_alerts(chains, sinks, max_selected=1)
        self.assertEqual(result["counts"]["selected"], 1)
        self.assertEqual(
            set(result["selected"][0]),
            {
                "alert_id",
                "sink_id",
                "sink_site_id",
                "source_ids",
                "source_backed_callsite_ids",
                "reason",
            },
        )
        self.assertEqual(result["selected"][0]["source_backed_callsite_ids"], ["site:caller"])

    def test_runtime_incompleteness_is_deferred_not_non_poc(self):
        chains = {
            "chains": [
                {
                    "chain_id": "chain:1",
                    "sink_id": "sink:1",
                    "sink_label": "COPY_SINK",
                    "status": "GRAPH_INCOMPLETE",
                }
            ]
        }
        sinks = {"sink_startpoints": [{"id": "sink:1", "label": "COPY_SINK"}]}
        result = MODULE.filter_alerts(chains, sinks, max_selected=1)
        self.assertEqual(result["counts"]["selected"], 0)
        self.assertEqual(result["deferred"][0]["reason"], "SOURCE_NOT_REACHED_BY_STATIC_ALERT")
        self.assertEqual(result["deterministic_contradictions"], [])


if __name__ == "__main__":
    unittest.main()
