#!/usr/bin/env python3
"""Attach bounded static-corridor and runtime-frontier context to an Alert."""

from __future__ import annotations

import argparse
import copy
import re
from pathlib import Path
from typing import Any

from elftools.elf.elffile import ELFFile

from fuzzware_trace import parse_bb_trace
from validation_common import load_json, parse_address, write_json


SITE_FUNCTION_RE = re.compile(r"^site:([0-9a-fA-F]+):")


def function_intervals(binary: Path) -> list[tuple[int, int, str, str]]:
    rows: list[tuple[int, int, str, str]] = []
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            if section["sh_type"] not in {"SHT_SYMTAB", "SHT_DYNSYM"}:
                continue
            for symbol in section.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                start = int(symbol["st_value"]) & ~1
                size = int(symbol["st_size"])
                name = str(symbol.name or "")
                if start and size and name:
                    rows.append((start, start + size, name, f"fn:{start:08x}"))
    rows.sort(key=lambda row: (row[0], row[1], row[2]))
    return rows


def function_for_address(
    address: int, intervals: list[tuple[int, int, str, str]]
) -> tuple[str, str] | None:
    address &= ~1
    for start, end, name, function_id in intervals:
        if start <= address < end:
            return name, function_id
    return None


def load_functions(path: Path) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            row = load_json_line(line)
            function_id = str(row.get("function_id", ""))
            if function_id:
                rows[function_id] = row
    return rows


def load_json_line(line: str) -> dict[str, Any]:
    import json

    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("functions JSONL contains a non-object row")
    return value


def site_function_ids(alert: dict[str, Any]) -> list[str]:
    ordered: list[str] = []

    def add_site(site_id: Any) -> None:
        match = SITE_FUNCTION_RE.match(str(site_id or ""))
        if match:
            function_id = f"fn:{int(match.group(1), 16):08x}"
            if function_id not in ordered:
                ordered.append(function_id)

    add_site(alert.get("sink_site_id"))
    for parameter in alert.get("parameter_results", []) or []:
        for path in parameter.get("paths", []) or []:
            for edge in path.get("path", []) or []:
                add_site(edge.get("site_id"))
    return ordered


def compressed_runtime_functions(
    *,
    bb_trace: Path,
    intervals: list[tuple[int, int, str, str]],
    start_address: int | None,
) -> tuple[list[dict[str, Any]], list[int]]:
    rows: list[dict[str, Any]] = []
    addresses: list[int] = []
    started = start_address is None
    for event in parse_bb_trace(bb_trace):
        address = event.bb_addr & ~1
        if not started and address == (start_address & ~1):
            started = True
        if not started:
            continue
        addresses.append(address)
        matched = function_for_address(address, intervals)
        if matched is None:
            continue
        name, function_id = matched
        if rows and rows[-1]["function_id"] == function_id:
            rows[-1]["last_bb"] = f"0x{address:x}"
            rows[-1]["bb_count"] += 1
            continue
        rows.append(
            {
                "function_id": function_id,
                "name": name,
                "first_bb": f"0x{address:x}",
                "last_bb": f"0x{address:x}",
                "bb_count": 1,
            }
        )
    return rows, addresses


def build_context(
    *,
    evidence: dict[str, Any],
    binary: Path,
    functions_jsonl: Path,
    bb_trace: Path,
    start_address: int | None,
    max_functions: int = 12,
    max_runtime_steps: int = 64,
) -> dict[str, Any]:
    result = copy.deepcopy(evidence)
    alert = result.get("unchanged_alert", {}) or {}
    intervals = function_intervals(binary)
    functions = load_functions(functions_jsonl)
    static_ids = site_function_ids(alert)
    runtime_rows, runtime_addresses = compressed_runtime_functions(
        bb_trace=bb_trace,
        intervals=intervals,
        start_address=start_address,
    )
    observed_ids = {str(row["function_id"]) for row in runtime_rows}

    priority_ids: list[str] = []
    for function_id in static_ids + [
        str(row["function_id"]) for row in runtime_rows[-max_runtime_steps:]
    ]:
        if function_id in functions and function_id not in priority_ids:
            priority_ids.append(function_id)
    priority_ids = priority_ids[:max_functions]

    existing = {
        str(row.get("function_id", "")): row
        for row in result.get("decompiled_functions", []) or []
    }
    for function_id in priority_ids:
        existing.setdefault(function_id, functions[function_id])
    result["decompiled_functions"] = list(existing.values())

    sink_address = parse_address(
        (result.get("sink_definition", {}) or {}).get("instruction_address")
    )
    missing_static = [
        function_id for function_id in static_ids if function_id not in observed_ids
    ]
    result["execution_context"] = {
        "schema_version": "ct-mini-execution-context-v1",
        "bb_trace": str(bb_trace),
        "analysis_start_address": (
            f"0x{start_address:x}" if start_address is not None else None
        ),
        "runtime_function_sequence": runtime_rows[-max_runtime_steps:],
        "runtime_frontier": {
            "last_basic_block": (
                f"0x{runtime_addresses[-1]:x}" if runtime_addresses else None
            ),
            "last_function": runtime_rows[-1] if runtime_rows else None,
            "sink_observed": bool(
                sink_address is not None
                and (sink_address & ~1) in set(runtime_addresses)
            ),
        },
        "static_corridor_function_ids": static_ids,
        "static_corridor_functions_not_observed": missing_static,
        "included_function_ids": priority_ids,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--functions-jsonl", required=True, type=Path)
    parser.add_argument("--bb-trace", required=True, type=Path)
    parser.add_argument("--start-address")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    start_address = parse_address(args.start_address)
    result = build_context(
        evidence=load_json(args.evidence),
        binary=args.binary,
        functions_jsonl=args.functions_jsonl,
        bb_trace=args.bb_trace,
        start_address=start_address,
    )
    write_json(args.output, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
