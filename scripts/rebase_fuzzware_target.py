#!/usr/bin/env python3
"""Rebase a frozen Fuzzware/readiness setup onto a sibling firmware ELF."""

from __future__ import annotations

import argparse
import copy
import hashlib
import re
from pathlib import Path
from typing import Any

import yaml
from elftools.elf.elffile import ELFFile

from validation_common import load_json, write_json


SITE_RE = re.compile(r"^site:([0-9a-fA-F]+):([0-9a-fA-F]+):(.*)$")
ADDRESS_KEYS = {
    "addr",
    "callee_entry",
    "checkpoint",
    "return_address",
    "target_checkpoint",
}


def function_symbols(binary: Path) -> list[tuple[int, int, str]]:
    rows: list[tuple[int, int, str]] = []
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
                    rows.append((start, start + size, name))
    return sorted(set(rows))


def symbol_maps(
    source_binary: Path, target_binary: Path
) -> tuple[list[tuple[int, int, str]], dict[str, tuple[int, int]]]:
    source = function_symbols(source_binary)
    target: dict[str, tuple[int, int]] = {}
    ambiguous: set[str] = set()
    for start, end, name in function_symbols(target_binary):
        if name in target and target[name] != (start, end):
            ambiguous.add(name)
        else:
            target[name] = (start, end)
    for name in ambiguous:
        target.pop(name, None)
    return source, target


def rebase_address(
    address: int,
    source_intervals: list[tuple[int, int, str]],
    target_by_name: dict[str, tuple[int, int]],
) -> int:
    address &= ~1
    matches = [
        (start, end, name)
        for start, end, name in source_intervals
        if start <= address < end and name in target_by_name
    ]
    if len(matches) != 1:
        raise ValueError(f"address 0x{address:x} has no unique shared function")
    source_start, _, name = matches[0]
    target_start, target_end = target_by_name[name]
    rebased = target_start + (address - source_start)
    if rebased >= target_end:
        raise ValueError(
            f"function-relative address 0x{address:x} exceeds target {name}"
        )
    return rebased


def rebase_hex(
    value: Any,
    source_intervals: list[tuple[int, int, str]],
    target_by_name: dict[str, tuple[int, int]],
) -> str:
    address = int(str(value), 0)
    return f"0x{rebase_address(address, source_intervals, target_by_name):x}"


def rebase_site_id(
    site_id: str,
    source_intervals: list[tuple[int, int, str]],
    target_by_name: dict[str, tuple[int, int]],
) -> str:
    match = SITE_RE.match(site_id)
    if not match:
        return site_id
    function_address = rebase_address(
        int(match.group(1), 16), source_intervals, target_by_name
    )
    instruction_address = rebase_address(
        int(match.group(2), 16), source_intervals, target_by_name
    )
    return (
        f"site:{function_address:08x}:{instruction_address:08x}:"
        f"{match.group(3)}"
    )


def rebase_contract_value(
    value: Any,
    *,
    source_intervals: list[tuple[int, int, str]],
    target_by_name: dict[str, tuple[int, int]],
    key: str = "",
) -> Any:
    if isinstance(value, dict):
        return {
            child_key: rebase_contract_value(
                child,
                source_intervals=source_intervals,
                target_by_name=target_by_name,
                key=child_key,
            )
            for child_key, child in value.items()
        }
    if isinstance(value, list):
        return [
            rebase_contract_value(
                child,
                source_intervals=source_intervals,
                target_by_name=target_by_name,
                key=key,
            )
            for child in value
        ]
    if key == "call_site_id" and isinstance(value, str):
        return rebase_site_id(value, source_intervals, target_by_name)
    if key in ADDRESS_KEYS and isinstance(value, str) and value.startswith("0x"):
        return rebase_hex(value, source_intervals, target_by_name)
    return value


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rebase_config(
    *,
    source_config: dict[str, Any],
    target_base_config: dict[str, Any],
    target_firmware_path: str,
    source_intervals: list[tuple[int, int, str]],
    target_by_name: dict[str, tuple[int, int]],
) -> dict[str, Any]:
    result = copy.deepcopy(target_base_config)
    triggers = copy.deepcopy(source_config.get("interrupt_triggers", {}) or {})
    for trigger in triggers.values():
        if isinstance(trigger, dict) and isinstance(trigger.get("addr"), int):
            trigger["addr"] = rebase_address(
                int(trigger["addr"]), source_intervals, target_by_name
            )
    result["interrupt_triggers"] = triggers

    models: dict[str, Any] = {}
    for family, family_models in (source_config.get("mmio_models", {}) or {}).items():
        models[family] = {}
        for name, model in (family_models or {}).items():
            row = copy.deepcopy(model)
            if isinstance(row, dict) and isinstance(row.get("pc"), int):
                old_pc = int(row["pc"])
                new_pc = rebase_address(old_pc, source_intervals, target_by_name)
                row["pc"] = new_pc
                name = name.replace(f"{old_pc:08x}", f"{new_pc:08x}")
            models[family][name] = row
    result["mmio_models"] = models
    result["memory_map"]["text"]["file"] = target_firmware_path
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-elf", required=True, type=Path)
    parser.add_argument("--target-elf", required=True, type=Path)
    parser.add_argument("--source-config", required=True, type=Path)
    parser.add_argument("--target-base-config", required=True, type=Path)
    parser.add_argument("--target-firmware-path", required=True)
    parser.add_argument("--source-contract", required=True, type=Path)
    parser.add_argument("--output-config", required=True, type=Path)
    parser.add_argument("--output-contract", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()

    source_intervals, target_by_name = symbol_maps(
        args.source_elf, args.target_elf
    )
    contract = rebase_contract_value(
        load_json(args.source_contract),
        source_intervals=source_intervals,
        target_by_name=target_by_name,
    )
    write_json(args.output_contract, contract)

    source_config = yaml.safe_load(args.source_config.read_text(encoding="utf-8"))
    target_base = yaml.safe_load(
        args.target_base_config.read_text(encoding="utf-8")
    )
    config = rebase_config(
        source_config=source_config,
        target_base_config=target_base,
        target_firmware_path=args.target_firmware_path,
        source_intervals=source_intervals,
        target_by_name=target_by_name,
    )
    args.output_config.parent.mkdir(parents=True, exist_ok=True)
    args.output_config.write_text(
        yaml.safe_dump(config, sort_keys=True), encoding="utf-8"
    )
    write_json(
        args.manifest,
        {
            "schema_version": "ct-mini-fuzzware-target-rebase-v1",
            "source_elf_sha256": file_sha256(args.source_elf),
            "target_elf_sha256": file_sha256(args.target_elf),
            "source_config_sha256": file_sha256(args.source_config),
            "output_config_sha256": file_sha256(args.output_config),
            "source_contract_sha256": file_sha256(args.source_contract),
            "output_contract_sha256": file_sha256(args.output_contract),
            "address_rule": "same_function_symbol_plus_relative_offset",
            "known_vulnerability_input_used": False,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
