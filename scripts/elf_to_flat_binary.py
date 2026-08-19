#!/usr/bin/env python3
"""Materialize flash-backed ELF PT_LOAD segments as a flat binary image."""

from __future__ import annotations

import argparse
from pathlib import Path

from elftools.elf.elffile import ELFFile


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--base", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--size", type=lambda value: int(value, 0), required=True)
    args = parser.parse_args()

    # GNU objcopy's binary backend zero-fills gaps between loadable segments.
    image = bytearray(args.size)
    with args.elf.open("rb") as handle:
        elf = ELFFile(handle)
        for segment in elf.iter_segments():
            if segment["p_type"] != "PT_LOAD" or int(segment["p_filesz"]) == 0:
                continue
            address = int(segment["p_paddr"])
            data = segment.data()
            start = address - args.base
            end = start + len(data)
            if end <= 0 or start >= args.size:
                continue
            source_start = max(0, -start)
            destination_start = max(0, start)
            destination_end = min(args.size, end)
            image[destination_start:destination_end] = data[
                source_start : source_start + destination_end - destination_start
            ]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(image)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
