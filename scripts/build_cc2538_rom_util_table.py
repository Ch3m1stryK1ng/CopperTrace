#!/usr/bin/env python3
"""Build the CC2538 ROM utility API table used during firmware startup."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


def thumb(address: int) -> int:
    return address | 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--memset", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--memcpy", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--memcmp", type=lambda value: int(value, 0), required=True)
    parser.add_argument("--memmove", type=lambda value: int(value, 0), required=True)
    args = parser.parse_args()

    # The CC2538 ROM table begins at 0x48. Entries 6..9 are the memory helpers.
    image = bytearray(0x100)
    for index, address in enumerate(
        (args.memset, args.memcpy, args.memcmp, args.memmove), start=6
    ):
        struct.pack_into("<I", image, 0x48 + index * 4, thumb(address))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(image)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
