#!/usr/bin/env python3
"""Map semantic Source bytes onto offsets observed in a Fuzzware MMIO trace."""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

from fuzzware_trace import BBEvent, MMIOEvent, parse_mmio_trace
from validation_common import load_json, parse_address, write_json


class SourceCallNotObserved(ValueError):
    """The baseline never executed the receive call required by the plan."""


class SourceTransactionSizeMismatch(ValueError):
    """The receive call ran, but no invocation consumed the planned size."""


@dataclass(frozen=True, slots=True)
class TransactionWindow:
    """One dynamic invocation of a receive call and its Source reads."""

    call_index: int
    call_site_id: str
    entry_event_id: int
    return_event_id: int
    source_reads: tuple[MMIOEvent, ...]


def source_contexts(evidence: dict[str, Any]) -> set[tuple[int, int]]:
    rows: set[tuple[int, int]] = set()
    sources = [
        *(evidence.get("upstream_hardware_sources", []) or []),
        *(evidence.get("runtime_hardware_sources", []) or []),
    ]
    for source in sources:
        proof = source.get("proof", {}) or {}
        address = parse_address(proof.get("register_address"))
        site = str(source.get("site_id", "")).split(":")
        pc = parse_address("0x" + site[2]) if len(site) >= 3 else None
        if address is not None and pc is not None:
            rows.add((pc & ~1, address))
    return rows


def eligible_source_reads(
    events: list[MMIOEvent], contexts: set[tuple[int, int]]
) -> list[MMIOEvent]:
    return [
        event
        for event in events
        if event.mode == "r"
        and (event.pc & ~1, event.address) in contexts
        and event.consumed_bytes > 0
    ]


def symbol_address(binary: Path, name: str) -> int | None:
    """Resolve an exact function symbol from an ELF file."""
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            if section["sh_type"] not in {"SHT_SYMTAB", "SHT_DYNSYM"}:
                continue
            for symbol in section.iter_symbols():
                if symbol.name == name and int(symbol["st_value"]):
                    return int(symbol["st_value"]) & ~1
    return None


def source_call_specs(
    evidence: dict[str, Any], binary: Path
) -> list[dict[str, Any]]:
    """Return the ordered direct receive calls used by the selected Source."""
    sequences = evidence.get("source_call_sequence", []) or []
    if not sequences:
        raise ValueError("evidence has no Source call sequence")
    sequence = max(
        sequences,
        key=lambda row: len(row.get("calls_in_instruction_order", []) or []),
    )
    calls = sequence.get("calls_in_instruction_order", []) or []
    specs: list[dict[str, Any]] = []
    for index, call in enumerate(calls):
        instruction = parse_address(call.get("instruction_address"))
        callee = str(call.get("callee", ""))
        entry = symbol_address(binary, callee) if callee else None
        if instruction is None or entry is None:
            raise ValueError(
                f"cannot bind Source call {index} to instruction and callee entry"
            )
        specs.append(
            {
                "call_index": index,
                "call_site_id": str(call.get("site_id", "")),
                "instruction_address": instruction & ~1,
                "callee_entry": entry,
                # ARM Cortex-M direct BL is a 32-bit Thumb instruction.
                "return_address": (instruction & ~1) + 4,
            }
        )
    return specs


def transaction_windows(
    bb_events: list[BBEvent],
    source_reads: list[MMIOEvent],
    call_specs: list[dict[str, Any]],
) -> list[TransactionWindow]:
    """Bind Source reads to a concrete direct-call invocation.

    Interrupt-driven reads outside a receive invocation are deliberately
    excluded. A window is accepted only when the callee entry is followed by
    the expected Thumb return address before the next invocation.
    """
    specs_by_entry: dict[int, list[dict[str, Any]]] = {}
    for spec in call_specs:
        specs_by_entry.setdefault(int(spec["callee_entry"]), []).append(spec)

    entries = [
        (index, event, specs_by_entry[event.bb_addr & ~1])
        for index, event in enumerate(bb_events)
        if (event.bb_addr & ~1) in specs_by_entry
    ]
    windows: list[TransactionWindow] = []
    for entry_number, (bb_index, entry, specs) in enumerate(entries):
        next_entry_id = (
            entries[entry_number + 1][1].event_id
            if entry_number + 1 < len(entries)
            else 1 << 63
        )
        for spec in specs:
            expected_return = int(spec["return_address"])
            returned = next(
                (
                    event
                    for event in bb_events[bb_index + 1 :]
                    if event.event_id < next_entry_id
                    and (event.bb_addr & ~1) == expected_return
                ),
                None,
            )
            if returned is None:
                continue
            reads = tuple(
                event
                for event in source_reads
                if entry.event_id < event.event_id < returned.event_id
            )
            windows.append(
                TransactionWindow(
                    call_index=int(spec["call_index"]),
                    call_site_id=str(spec["call_site_id"]),
                    entry_event_id=entry.event_id,
                    return_event_id=returned.event_id,
                    source_reads=reads,
                )
            )
    return sorted(windows, key=lambda row: row.entry_event_id)


def select_transaction_window(
    windows: list[TransactionWindow],
    *,
    call_index: int,
    byte_length: int,
    after_event_id: int = -1,
    before_event_id: int | None = None,
    required_fuzz_offsets: list[int] | None = None,
) -> TransactionWindow:
    """Select the earliest exact-size receive transaction.

    ``required_fuzz_offsets`` anchors a previously patched event after a replay.
    This lets a later event be selected from the same firmware iteration.
    """
    required = tuple(required_fuzz_offsets or ())
    for window in windows:
        if window.call_index != call_index:
            continue
        if window.entry_event_id <= after_event_id:
            continue
        if before_event_id is not None and window.entry_event_id >= before_event_id:
            continue
        offsets = tuple(event.fuzz_index for event in window.source_reads)
        if required and offsets != required:
            continue
        if len(window.source_reads) == byte_length:
            return window
    matching_calls = [
        window
        for window in windows
        if window.call_index == call_index
        and window.entry_event_id > after_event_id
        and (before_event_id is None or window.entry_event_id < before_event_id)
    ]
    if not matching_calls:
        raise SourceCallNotObserved(
            f"Source receive call index {call_index} was not observed in the baseline trace"
        )
    observed = sorted({len(window.source_reads) for window in matching_calls})
    raise SourceTransactionSizeMismatch(
        f"no exact {byte_length}-byte Source transaction for call index {call_index}; "
        f"observed sizes={observed}"
    )


def next_call_boundary(
    windows: list[TransactionWindow], window: TransactionWindow
) -> int | None:
    """Return the next invocation of the same call, delimiting one iteration."""
    return next(
        (
            candidate.entry_event_id
            for candidate in windows
            if candidate.call_index == window.call_index
            and candidate.entry_event_id > window.entry_event_id
        ),
        None,
    )


def patch_semantic_stream(
    base_input: bytes,
    semantic_stream: bytes,
    source_reads: list[MMIOEvent],
) -> tuple[bytes, list[dict[str, Any]]]:
    if len(source_reads) < len(semantic_stream):
        raise ValueError(
            f"only {len(source_reads)} injectable Source reads for "
            f"{len(semantic_stream)} semantic bytes"
        )
    result = bytearray(base_input)
    mapping: list[dict[str, Any]] = []
    for semantic_offset, (byte, event) in enumerate(
        zip(semantic_stream, source_reads)
    ):
        fuzz_offset = event.fuzz_index
        if fuzz_offset < 0 or fuzz_offset >= len(result):
            raise ValueError(f"fuzz offset {fuzz_offset} is outside base input")
        result[fuzz_offset] = byte
        mapping.append(
            {
                "semantic_offset": semantic_offset,
                "semantic_byte": byte,
                "fuzz_offset": fuzz_offset,
                "event_id": event.event_id,
                "pc": f"0x{event.pc:x}",
                "register_address": f"0x{event.address:x}",
                "access_size": event.access_size,
                "consumed_bytes": event.consumed_bytes,
            }
        )
    return bytes(result), mapping


def calibrate_manifest(
    *,
    manifest: dict[str, Any],
    semantic_root: Path,
    base_input: bytes,
    events: list[MMIOEvent],
    evidence: dict[str, Any],
    output_dir: Path,
) -> dict[str, Any]:
    reads = eligible_source_reads(events, source_contexts(evidence))
    output_dir.mkdir(parents=True, exist_ok=True)
    variants: list[dict[str, Any]] = []
    for variant in manifest.get("variants", []) or []:
        stream_path = semantic_root / str(variant["semantic_stream_file"])
        semantic_stream = stream_path.read_bytes()
        patched, mapping = patch_semantic_stream(base_input, semantic_stream, reads)
        output_path = output_dir / f"{variant['variant_id']}.bin"
        output_path.write_bytes(patched)
        variants.append(
            {
                "variant_id": variant["variant_id"],
                "input_file": str(output_path),
                "input_sha256": hashlib.sha256(patched).hexdigest(),
                "base_input_sha256": hashlib.sha256(base_input).hexdigest(),
                "semantic_stream_sha256": hashlib.sha256(semantic_stream).hexdigest(),
                "mapping": mapping,
            }
        )
    return {
        "schema_version": "ct-mini-fuzzware-calibration-v1",
        "alert_id": manifest.get("alert_id", ""),
        "eligible_source_read_count": len(reads),
        "variants": variants,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--semantic-root", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--base-input", required=True, type=Path)
    parser.add_argument("--mmio-trace", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--output-manifest", required=True, type=Path)
    args = parser.parse_args()

    result = calibrate_manifest(
        manifest=load_json(args.manifest),
        semantic_root=args.semantic_root,
        base_input=args.base_input.read_bytes(),
        events=parse_mmio_trace(args.mmio_trace),
        evidence=load_json(args.evidence),
        output_dir=args.output_dir,
    )
    write_json(args.output_manifest, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
