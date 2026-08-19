import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "plan_alert_execution", SCRIPTS / "plan_alert_execution.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class ExecutionPlanTests(unittest.TestCase):
    def test_recovers_affine_constant_through_transparent_pcode(self):
        by_output = {
            "sum": {
                "mnemonic": "INT_ADD",
                "inputs": [
                    {"value_id": "cast", "is_constant": False},
                    {
                        "value_id": "const:5",
                        "is_constant": True,
                        "offset": "0x5",
                        "size": 1,
                    },
                ],
            },
            "cast": {
                "mnemonic": "INT_ZEXT",
                "inputs": [{"value_id": "source-byte", "is_constant": False}],
            },
        }
        self.assertEqual(
            MODULE._affine_deltas_to_value(
                "sum", {"source-byte"}, by_output
            ),
            {5},
        )

    def test_parses_bare_hex_numbers_without_changing_strings(self):
        value = MODULE.parse_model_json(
            '{"fill_byte": 0x2a, "register": "0x40008008"}'
        )
        self.assertEqual(value["fill_byte"], 42)
        self.assertEqual(value["register"], "0x40008008")

    def test_collects_direct_and_nested_source_provenance(self):
        source_map = {
            "SO1": {
                "id": "SO1",
                "proof": {
                    "provenance": [
                        {"kind": "underlying_source", "source_id": "SO2"}
                    ]
                },
            },
            "SO2": {
                "id": "SO2",
                "proof": {"provenance": [{"underlying_source_ids": ["SO3"]}]},
            },
            "SO3": {"id": "SO3", "proof": {}},
        }
        self.assertEqual(
            MODULE.collect_underlying_source_ids([source_map["SO1"]], source_map),
            ["SO2", "SO3"],
        )

    def test_merges_runtime_context_without_replacing_alert(self):
        packet = {
            "unchanged_alert": {"chain_id": "chain:1"},
            "decompiled_functions": [
                {"function_id": "fn:1", "name": "sink", "body": "sink"}
            ],
        }
        context = {
            "unchanged_alert": {"chain_id": "forbidden-replacement"},
            "execution_context": {"runtime_frontier": {"sink_observed": False}},
            "decompiled_functions": [
                {"function_id": "fn:2", "name": "frontier", "body": "frontier"}
            ],
        }
        merged = MODULE.merge_execution_context(packet, context)
        self.assertEqual(merged["unchanged_alert"]["chain_id"], "chain:1")
        self.assertEqual(
            [row["function_id"] for row in merged["decompiled_functions"]],
            ["fn:1", "fn:2"],
        )

    def test_runtime_hardware_sources_use_general_register_identity(self):
        source_map = {
            "slow": {
                "id": "slow",
                "label": "MMIO_READ",
                "decision": "ACCEPT_DETERMINISTIC",
                "site_id": "site:100:110:1",
                "proof": {"register_address": "0x4000000c"},
            },
            "fast": {
                "id": "fast",
                "label": "MMIO_READ",
                "decision": "ACCEPT_DETERMINISTIC",
                "site_id": "site:200:210:1",
                "proof": {"register_address": "0x4000000c"},
            },
            "status": {
                "id": "status",
                "label": "MMIO_READ",
                "decision": "ACCEPT_DETERMINISTIC",
                "site_id": "site:300:310:1",
                "proof": {"register_address": "0x40000008"},
            },
        }
        rows = MODULE.runtime_hardware_sources(source_map, ["0x4000000c"])
        self.assertEqual([row["id"] for row in rows], ["slow", "fast"])

    def packet(self):
        return {
            "unchanged_alert": {"chain_id": "chain:1"},
            "selection_references": {
                "sink_id": "sink:1",
                "sink_site_id": "site:sink",
                "source_backed_callsite_ids": ["site:caller"],
            },
            "sink_definition": {
                "id": "sink:1",
                "instruction_address": "0x8001000",
                "vulnerable_parameter_roles": ["src", "len"],
            },
            "source_definitions": [{"id": "SO1", "site_id": "site:source"}],
            "upstream_hardware_sources": [
                {
                    "id": "SO2",
                    "site_id": "site:mmio",
                    "proof": {"register_address": "0x40000000"},
                }
            ],
            "allowed_register_addresses": ["0x40000000"],
            "payload_layout_facts": [
                {"fact_id": "layout:len", "role": "len", "offset": 0, "size": 2},
                {"fact_id": "layout:src", "role": "src", "offset_candidates": [2]},
            ],
        }

    def plan(self):
        return {
            "schema_version": "ct-mini-execution-plan-v1",
            "plan_id": "plan:chain:1",
            "alert_id": "chain:1",
            "binary_sha256": "a" * 64,
            "source_binding": {
                "source_id": "SO2",
                "source_site_id": "site:mmio",
                "delivery": "MMIO",
                "hardware_source_ids": ["SO2"],
                "register_addresses": ["0x40000000"],
            },
            "input_templates": [
                {
                    "template_id": "packet",
                    "byte_length": 257,
                    "fill_byte": 0,
                    "payload_start": 2,
                    "payload_start_evidence_ref": "layout:src",
                    "concretization_limit": 2,
                    "fields": [
                        {
                            "name": "length",
                            "role": "len",
                            "offset": 0,
                            "size": 2,
                            "encoding": "uint_le",
                            "candidates": [4, 255],
                            "evidence_ref": "layout:len",
                        }
                    ],
                }
            ],
            "events": [
                {
                    "event_id": "payload",
                    "kind": "SOURCE_PAYLOAD",
                    "order": 0,
                    "template_id": "packet",
                    "register_address": "0x40000000",
                    "irq": None,
                    "trigger_address": None,
                }
            ],
            "ordering_constraints": [],
            "sink_checkpoint": {
                "sink_id": "sink:1",
                "effect_site_id": "site:sink",
                "effect_address": "0x8001000",
                "boundary_site_ids": ["site:caller"],
                "vulnerable_parameter_roles": ["src", "len"],
            },
            "expected_invalid_effects": ["INVALID_WRITE", "CRASH"],
            "replay_count": 2,
            "unresolved_assumptions": [],
            "evidence_refs": ["site:caller"],
        }

    def test_accepts_evidence_bound_plan(self):
        MODULE.validate_plan(self.plan(), packet=self.packet(), binary_sha256="a" * 64)

    def test_rejects_invented_mmio_address(self):
        plan = self.plan()
        plan["source_binding"]["register_addresses"] = ["0x50000000"]
        with self.assertRaisesRegex(ValueError, "unverified MMIO"):
            MODULE.validate_plan(plan, packet=self.packet(), binary_sha256="a" * 64)

    def test_rejects_plan_above_frozen_input_budget(self):
        plan = self.plan()
        plan["input_templates"][0]["concretization_limit"] = 9
        with self.assertRaisesRegex(ValueError, "outside v1 limit"):
            MODULE.validate_plan(plan, packet=self.packet(), binary_sha256="a" * 64)

    def test_rejects_template_that_violates_constant_receive_extent(self):
        packet = self.packet()
        packet["source_call_sequence"] = [
            {
                "calls_in_instruction_order": [
                    {
                        "arguments": [
                            {
                                "index": 2,
                                "name": "",
                                "formal_name": "length",
                                "constant": 2,
                            }
                        ]
                    }
                ],
                "inter_transaction_dependencies": [],
            }
        ]
        with self.assertRaisesRegex(ValueError, "exact call extent"):
            MODULE.validate_plan(
                self.plan(), packet=packet, binary_sha256="a" * 64
            )

    def test_resolver_only_binds_unique_facts_and_removes_unsupported_role(self):
        plan = self.plan()
        plan["input_templates"][0]["payload_start_evidence_ref"] = "site:wrong"
        plan["input_templates"][0]["fields"].extend(
            [
                {
                    "name": "unsupported-src",
                    "role": "src",
                    "offset": 2,
                    "size": 1,
                    "encoding": "uint_le",
                    "candidates": [0],
                    "evidence_ref": "site:wrong",
                }
            ]
        )
        resolved = MODULE.resolve_plan_evidence(plan, self.packet())
        template = resolved["input_templates"][0]
        self.assertEqual(template["payload_start_evidence_ref"], "layout:src")
        self.assertEqual([field["role"] for field in template["fields"]], ["len"])
        self.assertEqual(template["concretization_limit"], 2)
        MODULE.validate_plan(resolved, packet=self.packet(), binary_sha256="a" * 64)

    def test_resolver_drops_unbound_semantic_fields_and_binds_unique_mmio(self):
        packet = self.packet()
        plan = self.plan()
        plan["source_binding"]["source_id"] = "SO1"
        plan["source_binding"]["source_site_id"] = "invented"
        plan["source_binding"]["hardware_source_ids"] = []
        plan["source_binding"]["register_addresses"] = ["0x50000000"]
        plan["events"][0]["register_address"] = "0x50000000"
        plan["input_templates"][0]["payload_start"] = 99
        plan["input_templates"][0]["fields"][0]["offset"] = 99
        resolved = MODULE.resolve_plan_evidence(plan, packet)
        self.assertEqual(resolved["source_binding"]["source_site_id"], "site:source")
        self.assertEqual(resolved["source_binding"]["hardware_source_ids"], ["SO2"])
        self.assertEqual(
            resolved["source_binding"]["register_addresses"], ["0x40000000"]
        )
        self.assertIsNone(resolved["input_templates"][0]["payload_start"])
        self.assertEqual(resolved["input_templates"][0]["fields"], [])

    def test_resolver_normalizes_nullable_source_event_keys(self):
        plan = self.plan()
        del plan["events"][0]["irq"]
        del plan["events"][0]["trigger_address"]
        resolved = MODULE.resolve_plan_evidence(plan, self.packet())
        self.assertIsNone(resolved["events"][0]["irq"])
        self.assertIsNone(resolved["events"][0]["trigger_address"])
        MODULE.validate_plan(
            resolved, packet=self.packet(), binary_sha256="a" * 64
        )

    def test_accepts_repeated_receive_sequence_groups(self):
        packet = self.packet()
        packet["source_call_sequence"] = [
            {
                "calls_in_instruction_order": [
                    {
                        "arguments": [
                            {
                                "index": 2,
                                "formal_name": "length",
                                "constant": 257,
                            }
                        ]
                    }
                ],
                "inter_transaction_dependencies": [],
            }
        ]
        plan = self.plan()
        plan["events"] = [
            {
                **plan["events"][0],
                "event_id": f"payload-{group}",
                "order": group,
                "call_index": 0,
                "transaction_group": group,
            }
            for group in range(2)
        ]
        MODULE.validate_plan(plan, packet=packet, binary_sha256="a" * 64)

    def test_rejects_duplicate_call_inside_transaction_group(self):
        packet = self.packet()
        packet["source_call_sequence"] = [
            {
                "calls_in_instruction_order": [{"arguments": []}],
                "inter_transaction_dependencies": [],
            }
        ]
        plan = self.plan()
        plan["events"] = [
            {
                **plan["events"][0],
                "event_id": f"payload-{ordinal}",
                "order": ordinal,
                "call_index": 0,
                "transaction_group": 0,
            }
            for ordinal in range(2)
        ]
        with self.assertRaisesRegex(ValueError, "repeats a static receive call"):
            MODULE.validate_plan(
                plan, packet=packet, binary_sha256="a" * 64
            )

    def test_rejects_incomplete_repeated_receive_sequence_group(self):
        packet = self.packet()
        packet["source_call_sequence"] = [
            {
                "calls_in_instruction_order": [
                    {"arguments": []},
                    {"arguments": []},
                ],
                "inter_transaction_dependencies": [],
            }
        ]
        plan = self.plan()
        plan["events"] = [
            {
                **plan["events"][0],
                "event_id": f"payload-{group}",
                "order": group,
                "call_index": 0,
                "transaction_group": group,
            }
            for group in range(2)
        ]
        with self.assertRaisesRegex(ValueError, "complete static receive sequence"):
            MODULE.validate_plan(
                plan, packet=packet, binary_sha256="a" * 64
            )

    def test_resolver_canonicalizes_llm_event_grouping_from_static_call_order(self):
        packet = self.packet()
        packet["source_call_sequence"] = [
            {
                "calls_in_instruction_order": [
                    {"arguments": []},
                    {"arguments": []},
                ],
                "inter_transaction_dependencies": [],
            }
        ]
        plan = self.plan()
        plan["events"] = [
            {
                **plan["events"][0],
                "event_id": f"payload-{ordinal}",
                "order": ordinal,
                "call_index": 0,
                "transaction_group": ordinal,
            }
            for ordinal in range(2)
        ]
        resolved = MODULE.resolve_plan_evidence(plan, packet)
        self.assertEqual(
            [
                (row["transaction_group"], row["call_index"])
                for row in resolved["events"]
            ],
            [(0, 0), (0, 1)],
        )
        MODULE.validate_plan(
            resolved, packet=packet, binary_sha256="a" * 64
        )

    def test_resolver_enforces_exact_constant_receive_extent(self):
        packet = self.packet()
        packet["source_call_sequence"] = [
            {
                "calls_in_instruction_order": [
                    {
                        "arguments": [
                            {
                                "index": 2,
                                "formal_name": "length",
                                "constant": 2,
                            }
                        ]
                    }
                ],
                "inter_transaction_dependencies": [],
            }
        ]
        plan = self.plan()
        plan["input_templates"][0]["byte_length"] = 132
        resolved = MODULE.resolve_plan_evidence(plan, packet)
        self.assertEqual(resolved["input_templates"][0]["byte_length"], 2)
        MODULE.validate_plan(
            resolved, packet=packet, binary_sha256="a" * 64
        )


if __name__ == "__main__":
    unittest.main()
