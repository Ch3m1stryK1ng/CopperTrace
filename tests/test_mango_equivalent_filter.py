import copy
import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "filter_static_alerts", SCRIPTS / "filter_static_alerts.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)

RUNNER_SPEC = importlib.util.spec_from_file_location(
    "run_mango_filter_corpus", SCRIPTS / "run_mango_filter_corpus.py"
)
RUNNER = importlib.util.module_from_spec(RUNNER_SPEC)
assert RUNNER_SPEC.loader
RUNNER_SPEC.loader.exec_module(RUNNER)


def source(source_id, *, label="BYTE_STREAM_INGRESS", callee="", proof=None):
    return {
        "id": source_id,
        "label": label,
        "callee": callee,
        "proof": proof or {},
    }


def chain(chain_id, sink_id, source_ids, *, site="site:boundary", role="len"):
    return {
        "chain_id": chain_id,
        "sink_id": sink_id,
        "sink_label": "COPY_SINK",
        "sink_site_id": site,
        "status": "SOURCE_REACHED_HEURISTIC",
        "parameter_results": [
            {
                "role": role,
                "status": "SOURCE_REACHED_HEURISTIC",
                "paths": [
                    {
                        "source_id": source_id,
                        "source_label": "BYTE_STREAM_INGRESS",
                        "path_precision": "MAY",
                        "path": [],
                    }
                    for source_id in source_ids
                ],
            }
        ],
    }


class MangoEquivalentFilterTests(unittest.TestCase):
    def test_uses_original_mango_source_categories(self):
        network = MODULE.classify_mango_source(source("S1", callee="recv"))
        file_source = MODULE.classify_mango_source(
            source("S2", callee="_read", proof={"summary_id": "mango-compat.read"})
        )
        mmio = MODULE.classify_mango_source(
            source("S3", label="MMIO_READ", callee="recv")
        )

        self.assertEqual((network["category"], network["weight"]), ("network", 0.6))
        self.assertEqual((file_source["category"], file_source["weight"]), ("file", 0.5))
        self.assertEqual((mmio["category"], mmio["weight"]), ("unknown", 0.0))

    def test_source_set_subsumption_is_non_destructive_and_auditable(self):
        chains = {
            "chains": [
                chain("A", "KA", ["S_NET"]),
                chain("B", "KB", ["S_NET", "S_FILE"]),
                chain("C", "KC", ["S_FILE"]),
                chain("D", "KD", ["S_MMIO"], site="site:mmio"),
            ]
        }
        original = copy.deepcopy(chains)
        sinks = {
            "sink_startpoints": [
                {"id": "KA", "label": "COPY_SINK", "effect_site_id": "site:effect:1"},
                {"id": "KB", "label": "COPY_SINK", "effect_site_id": "site:effect:1"},
                {"id": "KC", "label": "COPY_SINK", "effect_site_id": "site:effect:1"},
                {"id": "KD", "label": "COPY_SINK", "effect_site_id": "site:effect:2"},
            ]
        }
        sources = {
            "source_sites": [
                source("S_NET", callee="recv"),
                source("S_FILE", callee="read"),
                source("S_MMIO", label="MMIO_READ"),
            ]
        }

        result = MODULE.filter_static_alerts(chains, sinks, sources, max_selected=2)

        self.assertEqual(chains, original)
        self.assertEqual(result["counts"]["input_static_alerts"], 4)
        self.assertEqual(result["counts"]["canonical_alerts"], 3)
        self.assertEqual(result["counts"]["source_set_subsumed"], 1)
        self.assertEqual(result["merged_duplicates"][0]["canonical_alert_id"], "A")
        self.assertEqual(result["merged_duplicates"][0]["subsumed_alert_id"], "B")
        self.assertEqual([row["alert_id"] for row in result["selected"]], ["A", "C"])
        self.assertEqual([row["alert_id"] for row in result["deferred"]], ["D"])
        self.assertEqual(result["selected"][0]["represented_alert_ids"], ["A", "B"])

    def test_different_sink_effect_sites_are_not_subsumed(self):
        chains = {
            "chains": [
                chain("A", "KA", ["S1"]),
                chain("B", "KB", ["S1"]),
            ]
        }
        sinks = {
            "sink_startpoints": [
                {"id": "KA", "label": "COPY_SINK", "effect_site_id": "effect:1"},
                {"id": "KB", "label": "COPY_SINK", "effect_site_id": "effect:2"},
            ]
        }
        sources = {"source_sites": [source("S1", callee="recv")]}

        result = MODULE.filter_static_alerts(chains, sinks, sources, max_selected=10)

        self.assertEqual(result["counts"]["canonical_alerts"], 2)
        self.assertEqual(result["counts"]["source_set_subsumed"], 0)

    def test_source_unreached_chain_is_not_mislabeled_as_alert(self):
        row = chain("A", "KA", ["S1"])
        row["status"] = "GRAPH_INCOMPLETE"
        result = MODULE.filter_static_alerts(
            {"chains": [row]},
            {"sink_startpoints": [{"id": "KA", "effect_site_id": "effect:1"}]},
            {"source_sites": [source("S1", callee="recv")]},
            max_selected=10,
        )

        self.assertEqual(result["counts"]["input_static_alerts"], 0)
        self.assertEqual(result["counts"]["non_alert_chains"], 1)
        self.assertEqual(result["selected"], [])

    def test_public_filter_evaluation_reuses_frozen_reproduction_boundary(self):
        chains = {
            "chains": [
                {"chain_id": "A", "sink_id": "KA"},
                {"chain_id": "B", "sink_id": "KB"},
            ]
        }
        public_match = {
            "public_chain_matches": [
                {
                    "sink_id": "KA",
                    "status": "SOURCE_REACHED_HEURISTIC",
                    "matched_public_source": False,
                },
                {
                    "sink_id": "KB",
                    "status": "GRAPH_INCOMPLETE",
                    "matched_public_source": True,
                },
            ]
        }

        self.assertEqual(
            RUNNER._public_reproduction_ids(chains, public_match), {"A"}
        )

    def test_public_alert_rank_includes_deferred_rows(self):
        filter_doc = {
            "selected": [
                {"rank": 1, "represented_alert_ids": ["A"]},
            ],
            "deferred": [
                {"rank": 27, "represented_alert_ids": ["B", "C"]},
            ],
        }

        self.assertEqual(RUNNER._public_alert_rank(filter_doc, {"C"}), 27)


if __name__ == "__main__":
    unittest.main()
