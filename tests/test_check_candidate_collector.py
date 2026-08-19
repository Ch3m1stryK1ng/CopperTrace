import copy
import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "check_candidate_collector", SCRIPTS / "check_candidate_collector.py"
)
COLLECTOR = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(COLLECTOR)


def node(value_id, *, constant=False, offset=""):
    return {
        "value_id": value_id,
        "object_id": value_id.replace("value:", "object:"),
        "is_constant": constant,
        "offset": offset,
        "size": 4,
    }


def op(site, mnemonic, block, *, output=None, inputs=None):
    return {
        "site_id": site,
        "mnemonic": mnemonic,
        "block_id": block,
        "output": output,
        "inputs": inputs or [],
    }


def blocks():
    return [
        {
            "block_id": "block:entry",
            "predecessor_block_ids": [],
            "successor_block_ids": ["block:sink", "block:return"],
        },
        {
            "block_id": "block:sink",
            "predecessor_block_ids": ["block:entry"],
            "successor_block_ids": ["block:return"],
        },
        {
            "block_id": "block:return",
            "predecessor_block_ids": ["block:entry", "block:sink"],
            "successor_block_ids": [],
        },
    ]


def program(*, checked_atom="value:len", limiter=False, extra_checks=0):
    rows = []
    if limiter:
        rows.append(
            op(
                "site:00001000:00001002:1",
                "INT_AND",
                "block:entry",
                output=node("value:len"),
                inputs=[node("value:raw"), node("const:ff", constant=True, offset="0xff")],
            )
        )
    rows.extend(
        [
            op(
                "site:00001000:00001004:2",
                "INT_LESS",
                "block:entry",
                output=node("value:cmp"),
                inputs=[node(checked_atom), node("value:capacity")],
            ),
            op(
                "site:00001000:00001008:3",
                "CBRANCH",
                "block:entry",
                inputs=[node("const:target", constant=True), node("value:cmp")],
            ),
        ]
    )
    for index in range(extra_checks):
        rows.extend(
            [
                op(
                    f"site:00001000:000010{10 + index * 2:02x}:4",
                    "INT_NOTEQUAL",
                    "block:entry",
                    output=node(f"value:cmp{index}"),
                    inputs=[node(checked_atom), node(f"const:{index}", constant=True)],
                ),
                op(
                    f"site:00001000:000010{11 + index * 2:02x}:5",
                    "CBRANCH",
                    "block:entry",
                    inputs=[node("const:target", constant=True), node(f"value:cmp{index}")],
                ),
            ]
        )
    rows.append(
        op(
            "site:00001000:00001020:9",
            "CALL",
            "block:sink",
            inputs=[node("value:memcpy"), node("value:dst"), node("value:src"), node("value:len")],
        )
    )
    return {
        "functions": [
            {
                "function_id": "fn:00001000",
                "name": "copy_packet",
                "decompiled_c": "void copy_packet(void *dst, void *src, int len) { /* fixture */ }",
                "pcode_ops": rows,
                "basic_blocks": blocks(),
            }
        ]
    }


def sink():
    return {
        "id": "K1",
        "label": "COPY_SINK",
        "function_id": "fn:00001000",
        "site_id": "site:00001000:00001020:9",
        "roles": {"dst": "dst", "src": "src", "len": "len"},
        "role_bindings": {
            "dst": {"value_id": "value:dst", "object_id": "object:dst"},
            "src": {"value_id": "value:src", "object_id": "object:src"},
            "len": {"value_id": "value:len", "object_id": "object:len"},
        },
        "vulnerable_parameters": [
            {
                "role": "len",
                "value_id": "value:len",
                "expr": "len",
            }
        ],
    }


def chain(*, limiter=False):
    path = []
    if limiter:
        path.append(
            {
                "kind": "LOCAL_DEF_USE",
                "mnemonic": "INT_AND",
                "site_id": "site:00001000:00001002:1",
                "consumer_binding": {"atom_id": "value:len", "value_id": "value:len"},
                "predecessor_binding": {"atom_id": "value:raw", "value_id": "value:raw"},
            }
        )
    return {
        "chain_id": "A1",
        "sink_id": "K1",
        "sink_site_id": "site:00001000:00001020:9",
        "sink_function_id": "fn:00001000",
        "parameter_results": [
            {
                "role": "len",
                "start_value_id": "value:len",
                "paths": [{"path": path}],
            }
        ],
    }


def alert():
    return {
        "alert_id": "A1",
        "sink_id": "K1",
        "sink_label": "COPY_SINK",
        "vulnerable_parameter_roles": ["len"],
        "represented_alert_ids": ["A1"],
        "selection": "SELECTED",
    }


class CheckCandidateCollectorTests(unittest.TestCase):
    def collect(self, *, facts=None, chain_row=None, alert_row=None, max_candidates=16):
        return COLLECTOR.collect_alert_checks(
            alert_row or alert(),
            chains_doc={"chains": [chain_row or chain()]},
            sinks_doc={"sink_startpoints": [sink()]},
            program_facts=facts or program(),
            max_context_ops=128,
            max_check_candidates=max_candidates,
        )

    def candidates(self, result):
        return result["check_evidence"]["represented_alerts"][0]["parameters"][0][
            "check_candidates"
        ]

    def test_collects_cfg_gated_comparison_for_vulnerable_parameter(self):
        result = self.collect()
        candidates = self.candidates(result)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["kind"], "BRANCH_GATED_CHECK")
        self.assertEqual(
            candidates[0]["branch_relation"]["relation"],
            "ONE_BRANCH_SUCCESSOR_REACHES_TARGET",
        )
        self.assertEqual(candidates[0]["evidence_level"], "deterministic")
        self.assertEqual(candidates[0]["parameter_relation"], "BINDS")
        self.assertEqual(result["check_evidence"]["semantic_decision"], "NOT_PERFORMED")

    def test_unrelated_comparison_is_not_collected(self):
        result = self.collect(facts=program(checked_atom="value:other"))
        self.assertEqual(self.candidates(result), [])

    def test_collects_body_derived_value_limiting_effect(self):
        result = self.collect(facts=program(limiter=True), chain_row=chain(limiter=True))
        kinds = {row["kind"] for row in self.candidates(result)}
        self.assertIn("VALUE_LIMITING_CHECK", kinds)
        limiting = next(row for row in self.candidates(result) if row["kind"] == "VALUE_LIMITING_CHECK")
        self.assertEqual(limiting["mnemonic"], "INT_AND")

    def test_candidate_budget_is_explicit(self):
        result = self.collect(facts=program(extra_checks=3), max_candidates=1)
        parameter = result["check_evidence"]["represented_alerts"][0]["parameters"][0]

        self.assertEqual(len(parameter["check_candidates"]), 1)
        self.assertEqual(parameter["collection_status"], "TRUNCATED")
        self.assertIn("max_check_candidates", parameter["truncation_reasons"])

    def test_missing_represented_alert_is_not_silently_retained(self):
        row = alert()
        row["represented_alert_ids"] = ["missing"]
        result = self.collect(alert_row=row)

        self.assertEqual(result["check_evidence"]["collection_status"], "TRUNCATED")
        self.assertEqual(
            result["check_evidence"]["represented_alerts"][0]["collection_status"],
            "ERROR",
        )

    def test_original_a2_alert_is_unchanged(self):
        original = alert()
        frozen = copy.deepcopy(original)
        result = self.collect(alert_row=original)

        self.assertEqual(original, frozen)
        self.assertEqual(result["alert"], frozen)
        self.assertNotIn("check_evidence", result["alert"])

    def test_review_question_preserves_sink_roles_and_destination_binding(self):
        result = self.collect()
        question = result["sink_review_question"]

        self.assertEqual(question["vulnerable_parameter_expressions"]["len"], "len")
        self.assertEqual(question["sink_roles"]["dst"], "dst")
        self.assertEqual(question["destination"]["value_id"], "value:dst")
        self.assertTrue(question["requires_destination_validity"])
        self.assertTrue(question["reject_only_if_all_conditions_blocked"])
        self.assertFalse(question["requires_source_validity"])
        self.assertEqual(question["source_validity_scope"], "NOT_APPLICABLE")
        self.assertIn("requested extent", " ".join(question["dangerous_conditions"]))

    def test_review_question_distinguishes_source_data_from_address_control(self):
        sink_row = sink()
        sink_row["vulnerable_parameters"].insert(
            0,
            {
                "role": "src",
                "value_id": "value:src",
                "expr": "src + offset",
            },
        )

        question = COLLECTOR._sink_review_question(sink_row)

        self.assertTrue(question["requires_source_validity"])
        self.assertEqual(
            question["source_validity_scope"],
            "REQUIRED_IF_ADDRESS_INDEX_OFFSET_OR_EXTENT_IS_ATTACKER_INFLUENCED",
        )
        self.assertIn(
            "if the source address",
            " ".join(question["dangerous_conditions"]),
        )

    def test_static_destination_extent_is_collected_as_evidence_not_verdict(self):
        facts = program()
        facts["static_objects"] = [
            {
                "object_id": "object:dst",
                "kind": "STACK_ARRAY",
                "function_id": "fn:00001000",
                "storage_space": "stack",
                "extent": 64,
                "extent_evidence": "ghidra_stack_variable_extent",
            }
        ]
        result = self.collect(facts=facts)
        capacity = result["check_evidence"]["destination_capacity_evidence"]

        self.assertEqual(len(capacity), 1)
        self.assertEqual(capacity[0]["kind"], "STATIC_OBJECT_EXTENT")
        self.assertEqual(capacity[0]["evidence_level"], "deterministic")
        self.assertEqual(capacity[0]["semantic_decision"], "NOT_PERFORMED")

    def test_decompiled_structural_check_requires_control_structure(self):
        facts = program()
        function = facts["functions"][0]
        function["pcode_ops"] = [function["pcode_ops"][-1]]
        function["decompiled_c"] = (
            "void copy_packet(void *dst, void *src, int len) {\n"
            "  if (len > 32) { return; }\n"
            "  memcpy(dst, src, len);\n"
            "}"
        )
        for value in function["pcode_ops"][0]["inputs"]:
            if value.get("value_id") == "value:len":
                value["high_name"] = "len"
        result = self.collect(facts=facts)
        candidates = self.candidates(result)

        self.assertEqual([row["kind"] for row in candidates], ["DECOMPILED_BRANCH_CHECK"])
        self.assertEqual(candidates[0]["evidence_level"], "heuristic")

        function["decompiled_c"] = (
            "void copy_packet(void *dst, void *src, int len) {\n"
            "  int len_limit = 32;\n"
            "  memcpy(dst, src, len);\n"
            "}"
        )
        negative = self.collect(facts=facts)
        self.assertEqual(self.candidates(negative), [])

    def test_caller_check_uses_exact_actual_formal_binding_on_alert_path(self):
        formal_len = node("value:formal_len")
        formal_len.update({"is_parameter": True, "parameter_slot": 2, "high_name": "len"})
        callee = {
            "function_id": "fn:00001000",
            "name": "copy_packet",
            "parameters": [
                {"index": 2, "name": "len", "object_id": formal_len["object_id"]}
            ],
            "decompiled_c": "void copy_packet(void *d, void *s, int len) { memcpy(d,s,len); }",
            "basic_blocks": [
                {
                    "block_id": "block:callee",
                    "predecessor_block_ids": [],
                    "successor_block_ids": [],
                }
            ],
            "pcode_ops": [
                op(
                    "site:00001000:00001020:9",
                    "CALL",
                    "block:callee",
                    inputs=[node("value:memcpy"), node("value:dst"), node("value:src"), formal_len],
                )
            ],
        }
        actual_len = node("value:caller_len")
        compare = op(
            "site:00002000:00002004:1",
            "INT_LESSEQUAL",
            "block:caller_entry",
            output=node("value:caller_cmp"),
            inputs=[actual_len, node("value:caller_capacity")],
        )
        branch = op(
            "site:00002000:00002008:2",
            "CBRANCH",
            "block:caller_entry",
            inputs=[node("const:target", constant=True), node("value:caller_cmp")],
        )
        call = op(
            "site:00002000:00002020:3",
            "CALL",
            "block:caller_call",
            inputs=[node("value:copy_packet"), node("value:d"), node("value:s"), actual_len],
        )
        call["call"] = {
            "target_function_id": "fn:00001000",
            "argument_value_ids": ["value:d", "value:s", "value:caller_len"],
        }
        caller = {
            "function_id": "fn:00002000",
            "name": "caller",
            "parameters": [],
            "decompiled_c": "void caller(int n) { if (n <= 32) copy_packet(d,s,n); }",
            "basic_blocks": [
                {
                    "block_id": "block:caller_entry",
                    "predecessor_block_ids": [],
                    "successor_block_ids": ["block:caller_call", "block:caller_exit"],
                },
                {
                    "block_id": "block:caller_call",
                    "predecessor_block_ids": ["block:caller_entry"],
                    "successor_block_ids": ["block:caller_exit"],
                },
                {
                    "block_id": "block:caller_exit",
                    "predecessor_block_ids": ["block:caller_entry", "block:caller_call"],
                    "successor_block_ids": [],
                },
            ],
            "pcode_ops": [compare, branch, call],
        }
        chain_row = chain()
        chain_row["parameter_results"][0]["start_value_id"] = "value:formal_len"
        chain_row["parameter_results"][0]["paths"] = [
            {
                "path": [
                    {
                        "kind": "CALL_ACTUAL_FORMAL",
                        "call_site_id": call["site_id"],
                        "from_function_id": "fn:00002000",
                        "to_function_id": "fn:00001000",
                        "consumer_binding": {"value_id": "value:formal_len"},
                        "predecessor_binding": {"value_id": "value:caller_len"},
                    }
                ]
            }
        ]
        result = self.collect(
            facts={"functions": [callee, caller]}, chain_row=chain_row
        )
        candidates = self.candidates(result)

        self.assertTrue(
            any(
                row["function_id"] == "fn:00002000"
                and row["kind"] == "BRANCH_GATED_CHECK"
                for row in candidates
            )
        )
        bindings = result["check_evidence"]["represented_alerts"][0]["parameters"][0][
            "interprocedural_bindings"
        ]
        self.assertTrue(any(row["kind"] == "CALL_ACTUAL_FORMAL" for row in bindings))

    def test_equivalent_represented_paths_reuse_same_check_evidence(self):
        row = alert()
        row["represented_alert_ids"] = ["A1", "A2"]
        second = copy.deepcopy(chain())
        second["chain_id"] = "A2"
        result = COLLECTOR.collect_alert_checks(
            row,
            chains_doc={"chains": [chain(), second]},
            sinks_doc={"sink_startpoints": [sink()]},
            program_facts=program(),
        )

        represented = result["check_evidence"]["represented_alerts"]
        first = represented[0]["parameters"][0]
        second_parameter = represented[1]["parameters"][0]
        self.assertEqual(len(first["check_candidates"]), 1)
        self.assertEqual(second_parameter["check_candidates"], [])
        self.assertEqual(
            second_parameter["reused_check_ids"],
            [first["check_candidates"][0]["check_id"]],
        )
        self.assertEqual(result["check_evidence"]["check_candidate_count"], 1)


if __name__ == "__main__":
    unittest.main()
