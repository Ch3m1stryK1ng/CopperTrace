import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

CHECK_SPEC = importlib.util.spec_from_file_location(
    "check_binding", SCRIPTS / "check_binding.py"
)
CHECKS = importlib.util.module_from_spec(CHECK_SPEC)
assert CHECK_SPEC.loader
CHECK_SPEC.loader.exec_module(CHECKS)

FILTER_SPEC = importlib.util.spec_from_file_location(
    "filter_static_alerts_v2", SCRIPTS / "filter_static_alerts_v2.py"
)
FILTER = importlib.util.module_from_spec(FILTER_SPEC)
assert FILTER_SPEC.loader
FILTER_SPEC.loader.exec_module(FILTER)

CORPUS_SPEC = importlib.util.spec_from_file_location(
    "run_coppertrace_filter_corpus",
    SCRIPTS / "run_coppertrace_filter_corpus.py",
)
CORPUS = importlib.util.module_from_spec(CORPUS_SPEC)
assert CORPUS_SPEC.loader
CORPUS_SPEC.loader.exec_module(CORPUS)


def var(
    value_id,
    *,
    constant=False,
    offset="0x0",
    name="",
    object_id=None,
    size=4,
    space="",
    is_address=False,
):
    return {
        "value_id": value_id,
        "object_id": object_id or value_id.replace("value:", "object:"),
        "is_constant": constant,
        "offset": offset,
        "high_name": name,
        "size": size,
        "space": space,
        "is_address": is_address,
    }


def op(site, mnemonic, block, *, output=None, inputs=None):
    return {
        "site_id": site,
        "mnemonic": mnemonic,
        "block_id": block,
        "output": output,
        "inputs": inputs or [],
    }


def program_with_gating_check(*, checked_value="value:len", lower_bound=False):
    function_id = "fn:00001000"
    branch_site = "site:00001000:00001004:2"
    sink_site = "site:00001000:00001020:5"
    if lower_bound:
        comparison_inputs = [
            var("const:10:4", constant=True, offset="0x10"),
            var(checked_value),
        ]
    else:
        comparison_inputs = [
            var(checked_value),
            var("const:10:4", constant=True, offset="0x10"),
        ]
    return {
        "functions": [
            {
                "function_id": function_id,
                "pcode_ops": [
                    op(
                        "site:00001000:00001004:1",
                        "INT_LESS",
                        "block:entry",
                        output=var("value:cmp"),
                        inputs=comparison_inputs,
                    ),
                    op(
                        branch_site,
                        "CBRANCH",
                        "block:entry",
                        inputs=[var("value:target"), var("value:cmp")],
                    ),
                    op(sink_site, "CALL", "block:sink", inputs=[var("value:len")]),
                    op(
                        "site:00001000:00001030:6",
                        "RETURN",
                        "block:return",
                    ),
                ],
                "basic_blocks": [
                    {
                        "block_id": "block:entry",
                        "index": 0,
                        "predecessor_block_ids": [],
                        "successor_block_ids": ["block:sink", "block:return"],
                        "true_successor_block_id": "block:sink",
                        "false_successor_block_id": "block:return",
                    },
                    {
                        "block_id": "block:sink",
                        "index": 1,
                        "predecessor_block_ids": ["block:entry"],
                        "successor_block_ids": ["block:return"],
                        "true_successor_block_id": "",
                        "false_successor_block_id": "",
                    },
                    {
                        "block_id": "block:return",
                        "index": 2,
                        "predecessor_block_ids": ["block:entry", "block:sink"],
                        "successor_block_ids": [],
                        "true_successor_block_id": "",
                        "false_successor_block_id": "",
                    },
                ],
            }
        ]
    }


def program_with_capacity_check(
    *,
    bound=0x21,
    extent=32,
    include_static_object=True,
    transformed_length=False,
    signed_comparison=False,
    symbolic_bound=False,
):
    function_id = "fn:00001000"
    ptr_site = "site:00001000:00001002:1"
    compare_site = "site:00001000:00001004:2"
    branch_site = "site:00001000:00001008:3"
    sink_site = "site:00001000:00001020:5"
    dst = var("value:dst", object_id="unique:00001000:100:4")
    length = var("value:len")
    ops = [
        op(
            ptr_site,
            "PTRSUB",
            "block:entry",
            output=dst,
            inputs=[
                var(
                    "value:sp",
                    object_id="reg:00001000:54:4",
                    offset="0x54",
                    space="register",
                ),
                var(
                    "const:ffffffe0:4",
                    constant=True,
                    offset="0xffffffe0",
                    name="dst",
                ),
            ],
        )
    ]
    sink_length = length
    if transformed_length:
        sink_length = var("value:copy_len")
        ops.append(
            op(
                "site:00001000:00001003:4",
                "INT_ADD",
                "block:entry",
                output=sink_length,
                inputs=[length, var("const:64:4", constant=True, offset="0x64")],
            )
        )
    bound_node = (
        var("value:remaining")
        if symbolic_bound
        else var(f"const:{bound:x}:4", constant=True, offset=hex(bound))
    )
    if symbolic_bound:
        ops.append(
            op(
                "site:00001000:00001003:5",
                "INT_SUB",
                "block:entry",
                output=bound_node,
                inputs=[
                    var("const:20:4", constant=True, offset="0x20"),
                    var("value:offset"),
                ],
            )
        )
    ops.extend(
        [
            op(
                compare_site,
                "INT_SLESS" if signed_comparison else "INT_LESS",
                "block:entry",
                output=var("value:cmp"),
                inputs=[length, bound_node],
            ),
            op(
                branch_site,
                "CBRANCH",
                "block:entry",
                inputs=[var("value:target"), var("value:cmp")],
            ),
            op(
                sink_site,
                "CALL",
                "block:sink",
                inputs=[
                    var("value:memcpy", object_id="global:00002000:4"),
                    dst,
                    var("value:src"),
                    sink_length,
                ],
            ),
            op("site:00001000:00001030:6", "RETURN", "block:return"),
        ]
    )
    static_objects = []
    if include_static_object:
        static_objects.append(
            {
                "object_id": f"stack:00001000:-20:{extent}",
                "kind": "STACK_ARRAY",
                "function_id": function_id,
                "name": "dst",
                "storage_space": "stack",
                "base_offset": -32,
                "extent": extent,
                "writable": True,
                "extent_evidence": "ghidra_high_symbol_array_datatype",
            }
        )
    return {
        "architecture": {"stack_pointer": {"offset": 0x54}},
        "static_objects": static_objects,
        "functions": [
            {
                "function_id": function_id,
                "pcode_ops": ops,
                "basic_blocks": [
                    {
                        "block_id": "block:entry",
                        "index": 0,
                        "predecessor_block_ids": [],
                        "successor_block_ids": ["block:sink", "block:return"],
                        "true_successor_block_id": "block:sink",
                        "false_successor_block_id": "block:return",
                    },
                    {
                        "block_id": "block:sink",
                        "index": 1,
                        "predecessor_block_ids": ["block:entry"],
                        "successor_block_ids": ["block:return"],
                        "true_successor_block_id": "",
                        "false_successor_block_id": "",
                    },
                    {
                        "block_id": "block:return",
                        "index": 2,
                        "predecessor_block_ids": ["block:entry", "block:sink"],
                        "successor_block_ids": [],
                        "true_successor_block_id": "",
                        "false_successor_block_id": "",
                    },
                ],
            }
        ],
    }


def sink(
    sink_id="K1",
    *,
    site="site:00001000:00001020:5",
    effect_site=None,
    recognition="deterministic",
    role="len",
):
    return {
        "id": sink_id,
        "function_id": "fn:00001000",
        "site_id": site,
        "effect_site_id": effect_site or site,
        "label": "COPY_SINK",
        "recognition": recognition,
        "vulnerable_parameters": [
            {
                "role": role,
                "value_id": "value:len",
                "object_id": "object:len",
                "constant": False,
            }
        ],
    }


def capacity_sink(sink_id="K1", *, length_value_id="value:len", label="COPY_SINK"):
    return {
        "id": sink_id,
        "function_id": "fn:00001000",
        "site_id": "site:00001000:00001020:5",
        "effect_site_id": "site:00001000:00001020:5",
        "label": label,
        "recognition": "deterministic",
        "roles": {"dst": "dst", "src": "src", "len": "copy_len"},
        "vulnerable_parameters": [
            {
                "role": "len",
                "index": 2,
                "value_id": length_value_id,
                "object_id": "object:len",
                "constant": False,
            }
        ],
        "proof": {
            "argument_value_ids": ["value:dst", "value:src", length_value_id],
            "argument_object_ids": [
                "unique:00001000:100:4",
                "object:src",
                "object:len",
            ],
        },
    }


def source(source_id, site, *, address=""):
    proof = {"register_addresses": [address]} if address else {}
    return {
        "id": source_id,
        "label": "MMIO_READ",
        "site_id": site,
        "function_id": "fn:source",
        "decision": "ACCEPT_DETERMINISTIC",
        "proof": proof,
        "source_output": {"role": "buffer", "object_id": f"obj:{source_id}"},
    }


def chain(
    chain_id,
    sink_id,
    source_id,
    source_site,
    *,
    channel_edge="",
    role="len",
):
    path_edges = []
    if channel_edge:
        path_edges = [
            {
                "kind": "CHANNEL_READ",
                "graph_edge_id": channel_edge,
                "object_id": "obj:shared",
                "region": {"start": "0x0", "end": "0x3", "precision": "EXACT"},
                "evidence": {"analysis_precision": "EXACT"},
            }
        ]
    return {
        "chain_id": chain_id,
        "sink_id": sink_id,
        "sink_site_id": "site:00001000:00001020:5",
        "sink_label": "COPY_SINK",
        "status": "SOURCE_REACHED_DETERMINISTIC",
        "parameter_results": [
            {
                "role": role,
                "status": "SOURCE_REACHED_DETERMINISTIC",
                "paths": [
                    {
                        "source_id": source_id,
                        "source_lineage_ids": [source_id],
                        "source_site_id": source_site,
                        "source_decision": "ACCEPT_DETERMINISTIC",
                        "path_precision": "EXACT",
                        "path": path_edges,
                    }
                ],
                "blockers": [],
            }
        ],
    }


class CheckBindingTests(unittest.TestCase):
    def test_upper_bound_branch_gating_sink_is_parameter_bounded(self):
        result = CHECKS.ProgramCheckIndex(program_with_gating_check()).bind_sink(sink())

        self.assertEqual(result["status"], "PARAMETER_BOUNDED")
        self.assertEqual(
            result["parameter_checks"][0]["reason"],
            "ordered_comparison_upper_bounds_sink_parameter_on_sink_path",
        )
        self.assertFalse(result["hard_drop"])

    def test_static_array_and_exact_length_bound_are_capacity_safe(self):
        result = CHECKS.ProgramCheckIndex(program_with_capacity_check()).bind_sink(
            capacity_sink()
        )

        self.assertEqual(result["status"], "CAPACITY_SAFE")
        self.assertFalse(result["hard_drop"])
        self.assertFalse(result["offline_filter_eligible"])
        self.assertEqual(result["capacity_proof"]["destination_extent"], 32)
        self.assertEqual(result["capacity_proof"]["maximum_sink_length"], 32)
        self.assertEqual(
            result["capacity_proof"]["destination_resolution"],
            "stack_pointer_ptrsub",
        )

    def test_bound_larger_than_capacity_is_not_dropped(self):
        result = CHECKS.ProgramCheckIndex(
            program_with_capacity_check(bound=101)
        ).bind_sink(capacity_sink())

        self.assertEqual(result["status"], "PARAMETER_BOUNDED")
        self.assertFalse(result["hard_drop"])
        self.assertEqual(
            result["capacity_blocker"],
            "check_bound_exceeds_remaining_destination_capacity",
        )

    def test_arithmetic_related_length_is_not_value_equivalent(self):
        result = CHECKS.ProgramCheckIndex(
            program_with_capacity_check(transformed_length=True)
        ).bind_sink(capacity_sink(length_value_id="value:copy_len"))

        self.assertEqual(result["status"], "PARAMETER_BOUNDED")
        self.assertFalse(result["hard_drop"])
        self.assertFalse(result["parameter_checks"][0]["value_equivalent"])
        self.assertEqual(
            result["capacity_blocker"],
            "checked_value_not_equivalent_to_sink_length",
        )

    def test_dynamic_destination_is_not_dropped(self):
        result = CHECKS.ProgramCheckIndex(
            program_with_capacity_check(include_static_object=False)
        ).bind_sink(capacity_sink())

        self.assertEqual(result["status"], "PARAMETER_BOUNDED")
        self.assertFalse(result["hard_drop"])
        self.assertEqual(
            result["capacity_blocker"], "static_destination_object_unresolved"
        )

    def test_symbolic_remaining_capacity_is_not_dropped(self):
        result = CHECKS.ProgramCheckIndex(
            program_with_capacity_check(symbolic_bound=True)
        ).bind_sink(capacity_sink())

        self.assertEqual(result["status"], "PARAMETER_BOUNDED")
        self.assertFalse(result["hard_drop"])
        self.assertEqual(
            result["capacity_blocker"], "capacity_bound_not_constant"
        )

    def test_signed_comparison_is_not_capacity_safe(self):
        result = CHECKS.ProgramCheckIndex(
            program_with_capacity_check(signed_comparison=True)
        ).bind_sink(capacity_sink())

        self.assertEqual(result["status"], "PARAMETER_BOUNDED")
        self.assertFalse(result["hard_drop"])
        self.assertEqual(
            result["capacity_blocker"], "signed_comparison_not_capacity_proof"
        )

    def test_unrelated_check_does_not_bind_sink_parameter(self):
        result = CHECKS.ProgramCheckIndex(
            program_with_gating_check(checked_value="value:other")
        ).bind_sink(sink())

        self.assertEqual(result["status"], "UNKNOWN")

    def test_lower_bound_check_is_observed_but_not_effective(self):
        result = CHECKS.ProgramCheckIndex(
            program_with_gating_check(lower_bound=True)
        ).bind_sink(sink())

        self.assertEqual(result["status"], "OBSERVED_NOT_BOUND")


class CopperTraceFilterA2Tests(unittest.TestCase):
    def _run(self, chains, sinks, sources):
        return FILTER.filter_static_alerts_v2(
            {"chains": chains},
            {"sink_startpoints": sinks},
            {"source_sites": sources},
        )

    def test_exact_same_sink_and_source_lineage_is_deduplicated(self):
        chains = [
            chain("A", "K1", "S1", "site:source:1"),
            chain("B", "K2", "S1", "site:source:1"),
        ]
        result = self._run(
            chains,
            [sink("K1"), sink("K2")],
            [source("S1", "site:source:1", address="0x40000000")],
        )

        self.assertEqual(result["counts"]["canonical_alerts"], 1)
        self.assertEqual(result["counts"]["exact_lineage_duplicates"], 1)
        self.assertEqual(
            result["canonical_alerts"][0]["represented_alert_ids"], ["A", "B"]
        )

    def test_different_mmio_boundaries_are_not_deduplicated(self):
        chains = [
            chain("A", "K1", "S1", "site:source:1"),
            chain("B", "K2", "S2", "site:source:2"),
        ]
        result = self._run(
            chains,
            [sink("K1"), sink("K2")],
            [
                source("S1", "site:source:1", address="0x40000000"),
                source("S2", "site:source:2", address="0x40000004"),
            ],
        )

        self.assertEqual(result["counts"]["canonical_alerts"], 2)
        self.assertEqual(result["counts"]["exact_lineage_duplicates"], 0)

    def test_different_channelgraph_routes_are_not_deduplicated(self):
        chains = [
            chain("A", "K1", "S1", "site:source:1", channel_edge="channel:1"),
            chain("B", "K2", "S1", "site:source:1", channel_edge="channel:2"),
        ]
        result = self._run(
            chains,
            [sink("K1"), sink("K2")],
            [source("S1", "site:source:1")],
        )

        self.assertEqual(result["counts"]["canonical_alerts"], 2)

    def test_same_effect_and_lineage_preserves_distinct_sink_boundaries(self):
        first_site = "site:00001000:00001020:5"
        second_site = "site:00001000:00001030:6"
        effect_site = "site:00002000:00002010:7"
        result = self._run(
            [
                chain("A", "K1", "S1", "site:source:1"),
                chain("B", "K2", "S1", "site:source:1"),
            ],
            [
                sink("K1", site=first_site, effect_site=effect_site),
                sink("K2", site=second_site, effect_site=effect_site),
            ],
            [source("S1", "site:source:1")],
        )

        self.assertEqual(result["counts"]["canonical_alerts"], 2)
        self.assertEqual(result["counts"]["exact_lineage_duplicates"], 0)
        self.assertEqual(
            sorted(
                row["represented_sink_boundary_site_ids"][0]
                for row in result["canonical_alerts"]
            ),
            [first_site, second_site],
        )

    def test_heuristic_scalar_control_is_not_buried_by_confidence_label(self):
        result = self._run(
            [
                chain("scalar", "K1", "S1", "site:source:1", role="len"),
                chain("content", "K2", "S1", "site:source:1", role="src"),
            ],
            [
                sink(
                    "K1",
                    site="site:00001000:00001030:6",
                    recognition="heuristic",
                    role="len",
                ),
                sink(
                    "K2",
                    site="site:00001000:00001030:6",
                    recognition="deterministic",
                    role="src",
                ),
            ],
            [source("S1", "site:source:1")],
        )

        self.assertEqual(result["canonical_alerts"][0]["alert_id"], "scalar")

    def test_filter_does_not_modify_input_alerts(self):
        chains = {"chains": [chain("A", "K1", "S1", "site:source:1")]}
        original = copy.deepcopy(chains)
        FILTER.filter_static_alerts_v2(
            chains,
            {"sink_startpoints": [sink("K1")]},
            {"source_sites": [source("S1", "site:source:1")]},
        )

        self.assertEqual(chains, original)

    def test_a2_ranking_does_not_read_check_evidence(self):
        checked = chain("checked", "K1", "S1", "site:source:1")
        unchecked = chain("unchecked", "K2", "S1", "site:source:1")
        unchecked_sink = sink("K2", site="site:00001000:00001030:6")
        result = self._run(
            [checked, unchecked],
            [sink("K1"), unchecked_sink],
            [source("S1", "site:source:1")],
        )

        self.assertEqual(
            [row["alert_id"] for row in result["canonical_alerts"]],
            ["checked", "unchecked"],
        )
        self.assertEqual(result["counts"]["input_static_alerts"], 2)
        self.assertNotIn("check_evidence", result["canonical_alerts"][0])
        self.assertNotIn("selected", result)
        self.assertNotIn("deferred", result)

    def test_capacity_like_shape_is_not_dropped_by_a2(self):
        result = self._run(
            [chain("safe", "K1", "S1", "site:source:1", role="len")],
            [capacity_sink("K1")],
            [source("S1", "site:source:1")],
        )

        self.assertEqual(result["counts"]["dropped_invalid"], 0)
        self.assertEqual(result["canonical_alerts"][0]["alert_id"], "safe")
        self.assertEqual(result["dropped_invalid"], [])
        self.assertNotIn("dropped", result)


class CopperTraceFilterCorpusTests(unittest.TestCase):
    def test_fresh_sample_does_not_require_public_match_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample_root = root / "input" / "fresh-sample"
            sample_root.mkdir(parents=True)
            static_sample_root = root / "static" / "fresh-sample"
            static_sample_root.mkdir(parents=True)
            (sample_root / "chains.json").write_text(
                json.dumps(
                    {
                        "chains": [
                            chain("A", "K1", "S1", "site:source:1")
                        ]
                    }
                )
            )
            (static_sample_root / "sinks.json").write_text(
                json.dumps({"sink_startpoints": [sink("K1")]})
            )
            (static_sample_root / "sources.json").write_text(
                json.dumps(
                    {"source_sites": [source("S1", "site:source:1")]}
                )
            )

            result = CORPUS.run_corpus(
                {"samples": [{"sample_id": "fresh-sample"}]},
                {},
                root / "input",
                root / "output",
                root / "static",
            )

            self.assertEqual(result["counts"]["samples"], 1)
            self.assertEqual(result["counts"]["canonical_alerts"], 1)
            self.assertEqual(
                result["counts"]["public_cves_reproduced_before_filter"], 0
            )


if __name__ == "__main__":
    unittest.main()
