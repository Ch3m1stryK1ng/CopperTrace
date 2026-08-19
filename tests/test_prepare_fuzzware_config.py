import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "prepare_fuzzware_config", SCRIPTS / "prepare_fuzzware_config.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class PrepareFuzzwareConfigTests(unittest.TestCase):
    def test_external_irq_uses_cortex_m_exception_number(self):
        self.assertEqual(MODULE.cortex_m_external_irq_to_exception(12), 28)
        with self.assertRaisesRegex(ValueError, "nonnegative"):
            MODULE.cortex_m_external_irq_to_exception(-1)

    def test_merges_official_generated_models_by_kind(self):
        base = {"mmio_models": {"constant": {"a": {"pc": 1}}}}
        generated = {
            "mmio_models": {
                "constant": {"b": {"pc": 2}},
                "set": {"c": {"pc": 3}},
            }
        }
        result = MODULE.merge_generated_models(base, generated)
        self.assertEqual(set(result["mmio_models"]["constant"]), {"a", "b"})
        self.assertEqual(set(result["mmio_models"]["set"]), {"c"})

    def test_source_context_is_forced_unmodeled_without_other_changes(self):
        base = {
            "memory_map": {"text": {"base_addr": 0x08000000}},
            "mmio_models": {
                "constant": {
                    "source": {"pc": 0x08000100, "addr": 0x4000000C, "val": 0},
                    "status": {"pc": 0x08000110, "addr": 0x40000008, "val": 1},
                }
            },
        }
        evidence = {
            "allowed_register_addresses": ["0x4000000c"],
            "upstream_hardware_sources": [
                {
                    "site_id": "site:08000080:08000100:7",
                    "proof": {"register_address": "0x4000000c"},
                }
            ],
            "runtime_hardware_sources": [
                {
                    "site_id": "site:08000080:08000120:8",
                    "proof": {"register_address": "0x4000000c"},
                }
            ],
        }
        result, changes = MODULE.prepare_config(base, evidence, irq=35, irq_interval=64)
        self.assertNotIn("source", result["mmio_models"]["constant"])
        self.assertIn("status", result["mmio_models"]["constant"])
        source = result["mmio_models"]["unmodeled"][
            "ct_source_pc_08000100_mmio_4000000c"
        ]
        self.assertEqual(source, {"pc": 0x08000100, "addr": 0x4000000C})
        self.assertEqual(
            result["mmio_models"]["unmodeled"][
                "ct_source_pc_08000120_mmio_4000000c"
            ],
            {"pc": 0x08000120, "addr": 0x4000000C},
        )
        self.assertEqual(changes[0]["removed_models"][0]["kind"], "constant")
        self.assertEqual(
            result["interrupt_triggers"]["ct_source_irq"],
            {"every_nth_tick": 64, "irq": 35},
        )

    def test_readiness_manifest_restricts_runtime_source_context(self):
        base = {
            "mmio_models": {
                "constant": {
                    "first": {"pc": 0x100, "addr": 0x4000000C, "val": 0},
                    "second": {"pc": 0x200, "addr": 0x4000000C, "val": 0},
                }
            }
        }
        evidence = {
            "runtime_hardware_sources": [
                {
                    "site_id": "site:80:100:1",
                    "proof": {"register_address": "0x4000000c"},
                },
                {
                    "site_id": "site:80:200:2",
                    "proof": {"register_address": "0x4000000c"},
                },
            ]
        }
        readiness = {
            "active_source_contexts": [
                {"pc": "0x100", "register_address": "0x4000000c"}
            ]
        }
        result, _ = MODULE.prepare_config(
            base, evidence, readiness_manifest=readiness
        )
        self.assertIn("second", result["mmio_models"]["constant"])
        self.assertNotIn("first", result["mmio_models"]["constant"])
        self.assertEqual(
            set(result["mmio_models"]["unmodeled"]),
            {"ct_source_pc_00000100_mmio_4000000c"},
        )

    def test_readiness_context_must_exist_in_static_evidence(self):
        evidence = {
            "runtime_hardware_sources": [
                {
                    "site_id": "site:80:100:1",
                    "proof": {"register_address": "0x4000000c"},
                }
            ]
        }
        readiness = {
            "active_source_contexts": [
                {"pc": "0x200", "register_address": "0x4000000c"}
            ]
        }
        with self.assertRaisesRegex(ValueError, "non-evidence"):
            MODULE.prepare_config({}, evidence, readiness_manifest=readiness)


if __name__ == "__main__":
    unittest.main()
