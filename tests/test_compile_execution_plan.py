import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "compile_execution_plan", SCRIPTS / "compile_execution_plan.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class CompileExecutionPlanTests(unittest.TestCase):
    def test_compiles_ordered_bounded_variants(self):
        plan = {
            "input_templates": [
                {
                    "template_id": "header",
                    "byte_length": 2,
                    "fill_byte": 0,
                    "concretization_limit": 1,
                    "fields": [
                        {
                            "name": "next_len",
                            "role": "header",
                            "offset": 1,
                            "size": 1,
                            "encoding": "uint_le",
                            "candidates": [3],
                            "evidence_ref": "fact:header",
                        }
                    ],
                },
                {
                    "template_id": "packet",
                    "byte_length": 3,
                    "fill_byte": 0xAA,
                    "concretization_limit": 2,
                    "fields": [
                        {
                            "name": "length",
                            "role": "len",
                            "offset": 0,
                            "size": 2,
                            "encoding": "uint_le",
                            "candidates": [0x1234, 0xFFFF],
                            "evidence_ref": "fact:len",
                        }
                    ],
                },
            ],
            "events": [
                {
                    "event_id": "packet-event",
                    "kind": "SOURCE_PAYLOAD",
                    "order": 1,
                    "template_id": "packet",
                    "register_address": "0x40000000",
                },
                {
                    "event_id": "header-event",
                    "kind": "SOURCE_PAYLOAD",
                    "order": 0,
                    "template_id": "header",
                    "register_address": "0x40000000",
                },
            ],
        }
        variants = MODULE.compile_plan(plan)
        self.assertEqual(len(variants), 2)
        self.assertEqual(variants[0]["semantic_stream"], b"\x00\x03\x34\x12\xaa")
        self.assertEqual(variants[1]["semantic_stream"], b"\x00\x03\xff\xff\xaa")

    def test_preserves_call_and_transaction_identity(self):
        plan = {
            "input_templates": [
                {
                    "template_id": "prefix",
                    "byte_length": 1,
                    "fill_byte": 1,
                    "concretization_limit": 1,
                    "fields": [],
                },
                {
                    "template_id": "body",
                    "byte_length": 2,
                    "fill_byte": 2,
                    "concretization_limit": 1,
                    "fields": [],
                },
            ],
            "events": [
                {
                    "event_id": f"group-{group}-{call}",
                    "kind": "SOURCE_PAYLOAD",
                    "order": group * 2 + call,
                    "template_id": "prefix" if call == 0 else "body",
                    "call_index": call,
                    "transaction_group": group,
                    "register_address": "0x40000000",
                }
                for group in range(2)
                for call in range(2)
            ],
        }
        variant = MODULE.compile_plan(plan)[0]
        self.assertEqual(variant["semantic_stream"], b"\x01\x02\x02\x01\x02\x02")
        self.assertEqual(
            [
                (event["call_index"], event["transaction_group"])
                for event in variant["events"]
            ],
            [(0, 0), (1, 0), (0, 1), (1, 1)],
        )

    def test_global_variant_budget_is_eight(self):
        plan = {
            "input_templates": [
                {
                    "template_id": "packet",
                    "byte_length": 1,
                    "fill_byte": 0,
                    "concretization_limit": 16,
                    "fields": [
                        {
                            "name": "value",
                            "role": "other",
                            "offset": 0,
                            "size": 1,
                            "encoding": "uint_le",
                            "candidates": list(range(16)),
                            "evidence_ref": "fact:value",
                        }
                    ],
                }
            ],
            "events": [
                {
                    "event_id": "packet-event",
                    "kind": "SOURCE_PAYLOAD",
                    "order": 0,
                    "template_id": "packet",
                    "register_address": "0x40000000",
                }
            ],
        }
        self.assertEqual(len(MODULE.compile_plan(plan)), 8)


if __name__ == "__main__":
    unittest.main()
