from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from render_pipeline_run import render  # noqa: E402


def test_render_uses_cve_as_primary_unit() -> None:
    summary = {
        "samples_ok": 2,
        "samples_requested": 2,
        "public_sources": {"DETERMINISTIC_HIT": 1, "HEURISTIC_HIT": 1},
        "public_sinks": {"DETERMINISTIC_HIT": 2},
        "public_chain_status": {
            "SOURCE_REACHED_DETERMINISTIC": 1,
            "GRAPH_INCOMPLETE": 1,
        },
        "pipeline_totals": {
            "source_sites": 4,
            "sink_startpoints": 8,
            "source_write_candidates": 2,
            "shared_objects": 1,
            "channel_edges": 2,
            "chain_reverse_bfs_runs": 8,
            "chain_candidate_traces": 12,
            "chain_parameter_rda_runs": 10,
            "chains": 8,
        },
        "samples": [
            {
                "status": "OK",
                "counts": {
                    "graph": {
                        "source_associations": 3,
                        "channel_write_edges": 1,
                        "channel_read_edges": 1,
                    },
                    "chains": {
                        "serialized_trace_witnesses": 4,
                        "status": {"SOURCE_REACHED_DETERMINISTIC": 1},
                    },
                },
                "public_chain_matches": [
                    {
                        "status": "SOURCE_REACHED_DETERMINISTIC",
                        "matched_public_source": True,
                    }
                ]
            },
            {
                "status": "OK",
                "counts": {
                    "graph": {"source_associations": 2},
                    "chains": {
                        "serialized_trace_witnesses": 3,
                        "status": {"GRAPH_INCOMPLETE": 1},
                    },
                },
                "public_chain_matches": [
                    {"status": "GRAPH_INCOMPLETE", "matched_public_source": False}
                ]
            },
        ],
    }

    text = render(summary)

    assert "ELF (2/2 CVE samples)" in text
    assert "Static CVE Reproduction [1/2]" in text
    assert "Channelgraph [relations=2, WRITE=1, READ=1]" in text
    assert "Source Association [associations=5" in text
    assert "Static Alerts [Source-backed=1]" in text
