import importlib.util
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
TRACE_SPEC = importlib.util.spec_from_file_location(
    "fuzzware_trace", SCRIPTS / "fuzzware_trace.py"
)
TRACE = importlib.util.module_from_spec(TRACE_SPEC)
sys.modules["fuzzware_trace"] = TRACE
assert TRACE_SPEC.loader
TRACE_SPEC.loader.exec_module(TRACE)
SPEC = importlib.util.spec_from_file_location(
    "calibrate_fuzzware_input", SCRIPTS / "calibrate_fuzzware_input.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules["calibrate_fuzzware_input"] = MODULE
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class FuzzwareCalibrationTests(unittest.TestCase):
    def test_source_contexts_include_runtime_driver_alternatives(self):
        evidence = {
            "upstream_hardware_sources": [
                {
                    "site_id": "site:100:110:1",
                    "proof": {"register_address": "0x4000000c"},
                }
            ],
            "runtime_hardware_sources": [
                {
                    "site_id": "site:200:210:1",
                    "proof": {"register_address": "0x4000000c"},
                }
            ],
        }
        self.assertEqual(
            MODULE.source_contexts(evidence),
            {(0x110, 0x4000000C), (0x210, 0x4000000C)},
        )

    def test_source_call_specs_choose_longest_proved_sequence(self):
        evidence = {
            "source_call_sequence": [
                {
                    "calls_in_instruction_order": [
                        {
                            "site_id": "site:a",
                            "instruction_address": "0x100",
                            "callee": "receive",
                        }
                    ]
                },
                {
                    "calls_in_instruction_order": [
                        {
                            "site_id": "site:a",
                            "instruction_address": "0x100",
                            "callee": "receive",
                        },
                        {
                            "site_id": "site:b",
                            "instruction_address": "0x120",
                            "callee": "receive",
                        },
                    ]
                },
            ]
        }
        with patch.object(MODULE, "symbol_address", return_value=0x200):
            specs = MODULE.source_call_specs(evidence, Path("unused.elf"))
        self.assertEqual([row["call_index"] for row in specs], [0, 1])
        self.assertEqual([row["return_address"] for row in specs], [0x104, 0x124])
    def test_patches_only_low_byte_at_source_read_offsets(self):
        events = [
            TRACE.MMIOEvent(1, 0x100, 0, "r", 4, 8, 4, 0x4000000C, 0),
            TRACE.MMIOEvent(2, 0x100, 0, "r", 4, 16, 4, 0x4000000C, 0),
        ]
        reads = MODULE.eligible_source_reads(events, {(0x100, 0x4000000C)})
        patched, mapping = MODULE.patch_semantic_stream(
            bytes(range(32)), b"\xaa\xbb", reads
        )
        self.assertEqual(patched[8], 0xAA)
        self.assertEqual(patched[16], 0xBB)
        self.assertEqual(patched[9], 9)
        self.assertEqual([row["fuzz_offset"] for row in mapping], [8, 16])

    def test_rejects_trace_without_enough_source_reads(self):
        with self.assertRaisesRegex(ValueError, "only 0 injectable"):
            MODULE.patch_semantic_stream(b"\x00" * 8, b"\x01", [])

    def test_binds_reads_to_the_matching_receive_call_window(self):
        bb_events = [
            TRACE.BBEvent(10, 0x200, 1),
            TRACE.BBEvent(20, 0x104, 1),
            TRACE.BBEvent(30, 0x200, 1),
            TRACE.BBEvent(50, 0x124, 1),
        ]
        reads = [
            TRACE.MMIOEvent(12, 0x300, 0, "r", 4, 8, 4, 0x4000000C, 0),
            TRACE.MMIOEvent(16, 0x300, 0, "r", 4, 12, 4, 0x4000000C, 0),
            TRACE.MMIOEvent(25, 0x300, 0, "r", 4, 16, 4, 0x4000000C, 0),
            TRACE.MMIOEvent(35, 0x300, 0, "r", 4, 20, 4, 0x4000000C, 0),
        ]
        specs = [
            {
                "call_index": 0,
                "call_site_id": "site:first",
                "callee_entry": 0x200,
                "return_address": 0x104,
            },
            {
                "call_index": 1,
                "call_site_id": "site:second",
                "callee_entry": 0x200,
                "return_address": 0x124,
            },
        ]

        windows = MODULE.transaction_windows(bb_events, reads, specs)

        self.assertEqual(len(windows), 2)
        self.assertEqual(windows[0].call_index, 0)
        self.assertEqual(
            [event.fuzz_index for event in windows[0].source_reads], [8, 12]
        )
        self.assertEqual(windows[1].call_index, 1)
        self.assertEqual(
            [event.fuzz_index for event in windows[1].source_reads], [20]
        )

    def test_transaction_selection_requires_exact_size_and_anchor(self):
        read = lambda event_id, offset: TRACE.MMIOEvent(  # noqa: E731
            event_id, 0x300, 0, "r", 4, offset, 4, 0x4000000C, 0
        )
        windows = [
            MODULE.TransactionWindow(0, "site:a", 10, 20, (read(11, 4),)),
            MODULE.TransactionWindow(
                0, "site:a", 30, 40, (read(31, 8), read(32, 12))
            ),
        ]

        selected = MODULE.select_transaction_window(
            windows,
            call_index=0,
            byte_length=2,
            required_fuzz_offsets=[8, 12],
        )

        self.assertEqual(selected.entry_event_id, 30)

    def test_transaction_selection_distinguishes_missing_call_and_size(self):
        read = TRACE.MMIOEvent(11, 0x300, 0, "r", 4, 4, 4, 0x4000000C, 0)
        window = MODULE.TransactionWindow(0, "site:a", 10, 20, (read,))
        with self.assertRaises(MODULE.SourceCallNotObserved):
            MODULE.select_transaction_window([], call_index=0, byte_length=1)
        with self.assertRaises(MODULE.SourceTransactionSizeMismatch):
            MODULE.select_transaction_window([window], call_index=0, byte_length=2)


if __name__ == "__main__":
    unittest.main()
