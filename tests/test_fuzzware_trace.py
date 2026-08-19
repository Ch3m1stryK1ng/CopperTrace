from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import fuzzware_trace as trace  # noqa: E402


MMIO_TEXT = "001a: 8001235 fffffff9 r 4 64 4 0x40094008:7c6e5ef4\n"
BB_TEXT = "001b 8001200 3\n"
RAM_TEXT = "727f4: 8008950 8001355 w 1 0x2000334c:0\n"


def run(*, fault: str | None, source_pc: int = 0x08001235) -> trace.TraceRun:
    return trace.TraceRun(
        mmio_events=(
            trace.MMIOEvent(
                event_id=0x1A,
                pc=source_pc,
                lr=0xFFFFFFF9,
                mode="r",
                access_size=4,
                fuzz_index=64,
                consumed_bytes=4,
                address=0x40094008,
                value=0x7C6E5EF4,
            ),
        ),
        bb_events=(trace.BBEvent(event_id=0x1B, bb_addr=0x08001200, count=3),),
        runtime_fault_signature=fault,
    )


class FuzzwareTraceTests(unittest.TestCase):
    def test_loads_valid_mmio_and_bb_traces(self) -> None:
        with TemporaryDirectory() as directory:
            mmio_path = Path(directory) / "mmio.trace"
            bb_path = Path(directory) / "bb.trace"
            mmio_path.write_text("\n" + MMIO_TEXT, encoding="utf-8")
            bb_path.write_text(BB_TEXT, encoding="utf-8")

            mmio = trace.parse_mmio_trace(mmio_path)
            blocks = trace.parse_bb_trace(bb_path)

        self.assertIsInstance(mmio, list)
        self.assertIsInstance(blocks, list)
        self.assertEqual(
            mmio[0],
            trace.MMIOEvent(
                event_id=0x1A,
                pc=0x08001235,
                lr=0xFFFFFFF9,
                mode="r",
                access_size=4,
                fuzz_index=64,
                consumed_bytes=4,
                address=0x40094008,
                value=0x7C6E5EF4,
            ),
        )
        self.assertEqual(blocks[0], trace.BBEvent(0x1B, 0x08001200, 3))

    def test_loads_ram_trace(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "ram.trace"
            path.write_text(RAM_TEXT, encoding="utf-8")
            events = trace.parse_ram_trace(path)

        self.assertEqual(
            events[0],
            trace.RAMEvent(
                event_id=0x727F4,
                pc=0x08008950,
                lr=0x08001355,
                mode="w",
                access_size=1,
                address=0x2000334C,
                value=0,
            ),
        )

    def test_loads_ram_trace_with_fuzzware_trailing_field(self) -> None:
        event = trace.parse_ram_line(
            "02d5: 40d01a 402ded w 4 0x20102004:0 0"
        )

        self.assertEqual(event.event_id, 0x2D5)
        self.assertEqual(event.address, 0x20102004)
        self.assertEqual(event.value, 0)

        shadowed = trace.parse_ram_line(
            "1f22: 40d01a 40ad31 w 4 0x20104004:aaaaaaaa aaaaaaaa"
        )
        self.assertEqual(shadowed.address, 0x20104004)
        self.assertEqual(shadowed.value, 0xAAAAAAAA)

    def test_sink_write_to_fault_predecessor_is_causal_evidence(self) -> None:
        events = [
            trace.parse_ram_line(RAM_TEXT),
            trace.parse_ram_line(
                "728ae: 800ab40 8001cc7 r 4 0x2000334c:0"
            ),
        ]

        evidence = trace.causal_sink_fault(
            events,
            fault_signature="INVALID_READ:pc=0x800ab42:addr=0x8",
            sink_effect_intervals=[(0x08008900, 0x08008956)],
            fault_function_interval=(0x0800AB40, 0x0800AB4C),
        )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence["mode"], "SINK_WRITE_TO_FAULT_PREDECESSOR")
        self.assertEqual(evidence["sink_write"]["address"], "0x2000334c")

    def test_unrelated_write_does_not_bind_fault_to_sink(self) -> None:
        events = [
            trace.parse_ram_line(
                "727f4: 8007000 8001355 w 1 0x2000334c:0"
            ),
            trace.parse_ram_line(
                "728ae: 800ab40 8001cc7 r 4 0x2000334c:0"
            ),
        ]

        evidence = trace.causal_sink_fault(
            events,
            fault_signature="INVALID_READ:pc=0x800ab42:addr=0x8",
            sink_effect_intervals=[(0x08008900, 0x08008956)],
            fault_function_interval=(0x0800AB40, 0x0800AB4C),
        )

        self.assertIsNone(evidence)

    def test_nonreturning_sink_effect_overwriting_live_stack_is_causal(self) -> None:
        ram_events = [
            trace.RAMEvent(
                event_id=13,
                pc=0x40CF80,
                lr=0x403C3D,
                mode="w",
                access_size=1,
                address=0x20105AC0,
                value=0x34,
            )
        ]
        bb_events = [
            trace.BBEvent(10, 0x403C22, 0),
            trace.BBEvent(12, 0x40CF7C, 10),
            trace.BBEvent(20, 0x402BD0, 0),
        ]

        evidence = trace.causal_nonreturning_sink_stack_fault(
            ram_events,
            bb_events,
            fault_signature="INVALID_WRITE:pc=0x402bde:addr=0x1e0ff6c",
            sink_block_interval=(0x403C22, 0x403C3C),
            sink_return_address=0x403C3C,
            sink_effect_intervals=[(0x40CF5C, 0x40CF8A)],
            stack_pointers={0x20105AC0},
        )

        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertEqual(evidence["mode"], "SINK_EFFECT_OVERWROTE_ACTIVE_STACK")

    def test_returning_sink_effect_is_not_active_at_later_fault(self) -> None:
        evidence = trace.causal_nonreturning_sink_stack_fault(
            [
                trace.RAMEvent(
                    event_id=13,
                    pc=0x40CF80,
                    lr=0x403C3D,
                    mode="w",
                    access_size=1,
                    address=0x20105AC0,
                    value=0x34,
                )
            ],
            [
                trace.BBEvent(10, 0x403C22, 0),
                trace.BBEvent(12, 0x40CF7C, 1),
                trace.BBEvent(14, 0x403C3C, 0),
                trace.BBEvent(20, 0x402BD0, 0),
            ],
            fault_signature="INVALID_WRITE:pc=0x402bde:addr=0x1e0ff6c",
            sink_block_interval=(0x403C22, 0x403C3C),
            sink_return_address=0x403C3C,
            sink_effect_intervals=[(0x40CF5C, 0x40CF8A)],
            stack_pointers={0x20105AC0},
        )

        self.assertIsNone(evidence)

    def test_source_evidence_can_be_constrained_to_allowed_pcs(self) -> None:
        events = run(fault=None).mmio_events

        self.assertTrue(trace.source_address_observed(events, 0x40094008))
        self.assertTrue(
            trace.source_address_observed(
                events, 0x40094008, allowed_pcs={0x08001234}
            )
        )
        self.assertFalse(
            trace.source_address_observed(
                events, 0x40094008, allowed_pcs={0x08009900}
            )
        )
        self.assertFalse(trace.source_address_observed(events, 0x4009400C))

    def test_sink_evidence_uses_exact_entry_or_caller_interval(self) -> None:
        events = run(fault=None).bb_events

        self.assertTrue(trace.sink_address_observed(events, 0x08001200))
        self.assertFalse(trace.sink_address_observed(events, 0x08001208))
        self.assertTrue(
            trace.sink_address_observed(
                events,
                0x08001208,
                block_intervals={0x08001200: (0x08001200, 0x08001210)},
            )
        )
        self.assertFalse(
            trace.sink_address_observed(
                events,
                0x08001210,
                block_intervals={0x08001200: (0x08001200, 0x08001210)},
            )
        )

    def test_reproducible_source_sink_fault_is_poc(self) -> None:
        signature = trace.detect_fault(
            """Execution failed with error code: 7
        >>> [ 0x08001208 ] INVALID Write: addr= 0x0000000020010000 size=4 data=0xff
Emulation crashed with signal 11
""",
            returncode=0,
        )
        rows = [
            {
                "source_observed": True,
                "sink_observed": True,
                "fault_signature": signature,
            }
            for _ in range(3)
        ]

        self.assertEqual(signature, "INVALID_WRITE:pc=0x8001208:addr=0x20010000")
        self.assertEqual(trace.classify_replays(rows), trace.POC)

    def test_sink_hit_without_fault_is_inconclusive_and_never_non_poc(self) -> None:
        result = trace.classify_replays(
            [
                trace.ReplayEvidence(True, True, None),
                trace.ReplayEvidence(True, True, None),
            ]
        )

        self.assertEqual(result, trace.INCONCLUSIVE)
        self.assertNotEqual(result, "NON_POC")

    def test_different_fault_signatures_are_inconclusive(self) -> None:
        result = trace.classify_replays(
            [
                trace.ReplayEvidence(True, True, "fault-a"),
                trace.ReplayEvidence(True, True, "fault-b"),
            ]
        )

        self.assertEqual(result, trace.INCONCLUSIVE)

    def test_missing_source_or_sink_evidence_is_inconclusive(self) -> None:
        for source_seen, sink_seen in ((False, True), (True, False)):
            with self.subTest(source_seen=source_seen, sink_seen=sink_seen):
                result = trace.classify_replays(
                    [
                        trace.ReplayEvidence(source_seen, sink_seen, "SIGNAL:11"),
                        trace.ReplayEvidence(source_seen, sink_seen, "SIGNAL:11"),
                    ]
                )
                self.assertEqual(result, trace.INCONCLUSIVE)

    def test_detect_fault_handles_signals_but_not_ordinary_failures(self) -> None:
        self.assertEqual(trace.detect_fault("", returncode=-11), "SIGNAL:11")
        self.assertEqual(
            trace.detect_fault(
                "Execution failed: UC_ERR_READ_UNMAPPED", returncode=1
            ),
            "UC_ERR_READ_UNMAPPED",
        )
        self.assertIsNone(trace.detect_fault("invalid config", returncode=2))
        self.assertIsNone(trace.detect_fault("status: UC_ERR_OK", returncode=0))

    def test_malformed_traces_report_kind_and_line_number(self) -> None:
        with self.assertRaisesRegex(trace.TraceParseError, "malformed MMIO"):
            trace.parse_mmio_line("001a: missing fields")
        with self.assertRaisesRegex(trace.TraceParseError, "malformed BB"):
            trace.parse_bb_line("001b 8001200 not-a-count")

        with TemporaryDirectory() as directory:
            path = Path(directory) / "mmio.trace"
            path.write_text(MMIO_TEXT + "bad\n", encoding="utf-8")
            with self.assertRaisesRegex(trace.TraceParseError, r"mmio\.trace:2"):
                trace.load_events(path, kind="mmio")


if __name__ == "__main__":
    unittest.main()
