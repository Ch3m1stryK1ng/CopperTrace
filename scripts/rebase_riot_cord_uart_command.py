#!/usr/bin/env python3
"""Reuse calibrated RIOT UART events with a shorter shell command."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-plan", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--command", required=True)
    parser.add_argument(
        "--input-offset-shift",
        type=int,
        default=0,
        help="Apply a trace-derived shift to every calibrated UART event offset",
    )
    parser.add_argument("--quiesce-remaining-events", action="store_true")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    source_manifest = json.loads(
        (args.source_plan / "execution_plan.json").read_text(encoding="utf-8")
    )
    first_offset = source_manifest["uart"].get("input_offset")
    if first_offset is None:
        raise SystemExit("source plan does not record the first UART input offset")
    event_offsets = []
    for offset in [int(first_offset)] + [
        int(event["fr_input_offset"])
        for event in source_manifest["uart"]["calibrated_events"]
    ]:
        offset += args.input_offset_shift
        if offset < 0:
            raise SystemExit("shifted UART event offset is negative")
        if not event_offsets or event_offsets[-1] != offset:
            event_offsets.append(offset)
    command = args.command.encode("ascii")
    if len(command) > len(event_offsets):
        raise SystemExit("new command exceeds the calibrated UART event count")

    shutil.copy2(args.source_plan / "config.yml", args.out / "config.yml")
    data = bytearray((args.source_plan / "input.bin").read_bytes())
    rebased_events = []
    for index, byte in enumerate(command):
        offset = event_offsets[index]
        data[offset : offset + 3] = bytes((0x00, byte, 0x01))
        rebased_events.append(
            {
                "command_index": index,
                "character_hex": hex(byte),
                "fr_input_offset": offset,
            }
        )
    if args.quiesce_remaining_events:
        for offset in event_offsets[len(command) :]:
            data[offset : offset + 3] = b"\x01\x01\x01"
    (args.out / "input.bin").write_bytes(data)

    source_manifest["phase"] = "UART_SHORT_COMMAND_REPLAY"
    source_manifest["effective_config"] = str(args.out / "config.yml")
    source_manifest["input"] = str(args.out / "input.bin")
    source_manifest["input_sha256"] = sha256(args.out / "input.bin")
    source_manifest["uart"]["command"] = args.command
    source_manifest["uart"]["input_offset"] = event_offsets[0]
    source_manifest["uart"]["configured_prefix_length"] = len(command)
    source_manifest["uart"]["calibrated_events"] = rebased_events
    source_manifest["derivation"] = {
        "kind": "calibrated_uart_event_reuse",
        "source_plan": str(args.source_plan / "execution_plan.json"),
        "program_counter_forcing": False,
        "branch_patching": False,
        "remaining_uart_events_quiesced": args.quiesce_remaining_events,
        "input_offset_shift": args.input_offset_shift,
    }
    (args.out / "execution_plan.json").write_text(
        json.dumps(source_manifest, indent=2) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
