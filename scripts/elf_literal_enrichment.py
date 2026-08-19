#!/usr/bin/env python3
"""Attach initialized ELF literals to Ghidra ProgramFacts.

Ghidra can represent a value loaded from a global pointer slot with the
slot's storage address.  Reading the immutable ELF initializer recovers the
actual pointer value without guessing from a symbol or decompiled expression.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def _parse_int(value: Any) -> int | None:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def enrich_program_facts_with_elf_literals(
    program_facts: dict[str, Any], elf_path: Path
) -> int:
    """Attach initialized, non-writable ELF literal values to P-code nodes."""

    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return 0

    ranges: list[tuple[int, int, bytes, bool]] = []
    with elf_path.open("rb") as stream:
        elf = ELFFile(stream)
        little_endian = bool(elf.little_endian)
        pointer_size = int(elf.elfclass // 8)
        for section in elf.iter_sections():
            flags = int(section["sh_flags"])
            alloc = bool(flags & 0x2)  # SHF_ALLOC
            writable = bool(flags & 0x1)  # SHF_WRITE
            if (
                not alloc
                or str(section["sh_type"]) == "SHT_NOBITS"
                or int(section["sh_size"]) <= 0
            ):
                continue
            start = int(section["sh_addr"])
            data = bytes(section.data())
            ranges.append((start, start + len(data), data, writable))

    def readonly_value(address: int, size: int) -> int | None:
        for start, end, data, writable in ranges:
            if writable or address < start or address + size > end:
                continue
            raw = data[address - start : address - start + size]
            return int.from_bytes(raw, "little" if little_endian else "big")
        return None

    enriched = 0
    pointer_seeds: set[int] = set()
    seen: set[tuple[str, str]] = set()
    for function in list(program_facts.get("functions", []) or []):
        for op in list(function.get("pcode_ops", []) or []):
            nodes = list(op.get("inputs", []) or [])
            if op.get("output"):
                nodes.append(op["output"])
            for node in nodes:
                if not bool(node.get("is_address")):
                    continue
                if str(node.get("space", "")).lower() not in {
                    "ram", "mem", "memory"
                }:
                    continue
                address = _parse_int(node.get("offset"))
                size = int(node.get("size", 0) or 0)
                if address is None or size not in {1, 2, 4, 8}:
                    continue
                value = readonly_value(address, size)
                if value is None:
                    continue
                node["initial_memory_value"] = f"0x{value:x}"
                node["initial_memory_address"] = f"0x{address:x}"
                node["initial_memory_source"] = (
                    "elf_initialized_nonwritable_segment"
                )
                if size == pointer_size:
                    pointer_seeds.add(value & ~1)
                key = (str(node.get("object_id", "")), str(node.get("value_id", "")))
                if key not in seen:
                    enriched += 1
                    seen.add(key)

    # Preserve a bounded pointer chain for immutable dispatch/descriptor tables.
    pointer_words: dict[str, str] = {}
    frontier = set(pointer_seeds)
    for _ in range(4):
        next_frontier: set[int] = set()
        for address in sorted(frontier):
            value = readonly_value(address, pointer_size)
            if value is None:
                continue
            pointer_words[f"0x{address:x}"] = f"0x{value:x}"
            next_frontier.add(value & ~1)
        frontier = next_frontier - {
            int(address, 0) for address in pointer_words
        }
        if not frontier:
            break
    if pointer_words:
        program_facts["elf_readonly_pointer_words"] = pointer_words
    enrichment = program_facts.setdefault("analysis_enrichment", {})
    enrichment["elf_literal_varnodes"] = enriched
    enrichment["elf_readonly_pointer_words"] = len(pointer_words)
    return enriched
