#!/usr/bin/env python3
"""Extend a RIOT CORD UART replay by one trace-calibrated character."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


UART_FR_PC = 0x20D528
EXCEPTION_RETURN = 0xFFFFFFFD
TRACE_RE = re.compile(
    r"^[0-9a-f]+:\s+([0-9a-f]+)\s+([0-9a-f]+)\s+r\s+\d+\s+(\d+)\s+\d+\s+"
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--trace", type=Path, required=True)
    args = parser.parse_args()

    manifest_path = args.plan / "execution_plan.json"
    input_path = args.plan / "input.bin"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    command = manifest["uart"]["command"].encode("ascii")
    configured = int(manifest["uart"].get("configured_prefix_length", 0))
    if configured >= len(command):
        print(json.dumps({"complete": True, "configured": configured}))
        return 0

    event_offsets: list[int] = []
    for line in args.trace.read_text(encoding="utf-8").splitlines():
        match = TRACE_RE.match(line)
        if not match:
            continue
        pc, lr, offset = (int(match.group(1), 16), int(match.group(2), 16), int(match.group(3)))
        if pc == UART_FR_PC and lr == EXCEPTION_RETURN:
            event_offsets.append(offset)

    if len(event_offsets) <= configured:
        raise SystemExit(
            f"trace has {len(event_offsets)} UART events; need event {configured + 1}"
        )

    offset = event_offsets[configured]
    data = bytearray(input_path.read_bytes())
    required = offset + 3
    if len(data) < required:
        data.extend(b"\0" * (required - len(data)))
    # UART_FR is a Fuzzware set-model over {0, 16}; selector 1 chooses the
    # RX-empty value 16 and terminates this interrupt after one DR byte.
    data[offset:required] = bytes((0x00, command[configured], 0x01))
    input_path.write_bytes(data)

    manifest["uart"]["configured_prefix_length"] = configured + 1
    manifest["uart"].setdefault("calibrated_events", []).append(
        {
            "command_index": configured,
            "character_hex": hex(command[configured]),
            "fr_input_offset": offset,
        }
    )
    manifest["input_sha256"] = sha256(input_path)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "complete": configured + 1 == len(command),
                "configured": configured + 1,
                "total": len(command),
                "offset": offset,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
