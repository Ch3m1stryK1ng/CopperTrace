import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "calibrate_peripheral_readiness",
    SCRIPTS / "calibrate_peripheral_readiness.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


class PeripheralReadinessTests(unittest.TestCase):
    def test_seed_extension_repeats_only_existing_tail(self):
        self.assertEqual(
            MODULE.extend_input(b"abcdef", extra_bytes=5, tail_bytes=2),
            b"abcdefefefe",
        )

    def test_empty_seed_cannot_be_extended(self):
        with self.assertRaisesRegex(ValueError, "empty readiness seed"):
            MODULE.extend_input(b"", extra_bytes=1, tail_bytes=4)

    def test_checkpoint_observation_uses_thumb_canonical_address(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "bb.txt"
            trace.write_text("0001 4021bc 0\n", encoding="utf-8")
            self.assertTrue(MODULE.checkpoint_observed(trace, 0x4021BD))
            self.assertFalse(MODULE.checkpoint_observed(trace, 0x4021A0))

    def test_observed_source_contexts_are_unique(self):
        from fuzzware_trace import MMIOEvent

        window = type(
            "Window",
            (),
            {
                "source_reads": (
                    MMIOEvent(1, 0x101, 0, "r", 4, 0, 4, 0x4000000C, 1),
                    MMIOEvent(2, 0x100, 0, "r", 4, 4, 4, 0x4000000C, 2),
                )
            },
        )()
        self.assertEqual(
            MODULE.observed_source_contexts(window),
            [{"pc": "0x100", "register_address": "0x4000000c"}],
        )

    def test_checkpoint_is_scoped_before_next_repeated_invocation(self):
        from calibrate_fuzzware_input import TransactionWindow
        from fuzzware_trace import BBEvent

        windows = [
            TransactionWindow(0, "site:x", 10, 20, ()),
            TransactionWindow(0, "site:x", 40, 50, ()),
        ]
        blocks = [BBEvent(21, 0x200, 0), BBEvent(51, 0x300, 0)]
        with (
            patch.object(MODULE, "source_contexts", return_value=set()),
            patch.object(MODULE, "parse_mmio_trace", return_value=[]),
            patch.object(MODULE, "parse_bb_trace", return_value=blocks),
            patch.object(MODULE, "transaction_windows", return_value=windows),
        ):
            self.assertFalse(
                MODULE.checkpoint_after_invocation(
                    step={
                        "callee_entry": "0x100",
                        "return_address": "0x104",
                        "invocation_index": 0,
                    },
                    evidence={},
                    mmio_path=Path("unused-mmio"),
                    bb_path=Path("unused-bb"),
                    checkpoint=0x300,
                )
            )


if __name__ == "__main__":
    unittest.main()
