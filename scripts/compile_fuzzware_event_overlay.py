#!/usr/bin/env python3
"""Compile a symbol-relative Execution Plan IRQ schedule into Fuzzware config."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any

import yaml
from elftools.elf.elffile import ELFFile

from validation_common import load_json, sha256_file, write_json


def elf_function_symbols(binary: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            if section["sh_type"] not in {"SHT_SYMTAB", "SHT_DYNSYM"}:
                continue
            for symbol in section.iter_symbols():
                if (
                    symbol.name
                    and symbol["st_shndx"] != "SHN_UNDEF"
                    and symbol["st_info"]["type"] == "STT_FUNC"
                ):
                    symbols.setdefault(symbol.name, int(symbol["st_value"]) & ~1)
    return symbols


def compile_event_overlay(
    base: dict[str, Any],
    plan: dict[str, Any],
    symbols: dict[str, int],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result = copy.deepcopy(base)
    triggers = result.setdefault("interrupt_triggers", {})
    policy = plan.get("interrupt_schedule_policy", {}) or {}
    removed: list[dict[str, Any]] = []
    for name in policy.get("replace_trigger_names", []) or []:
        if name in triggers:
            removed.append({"name": name, "model": copy.deepcopy(triggers[name])})
            del triggers[name]

    installed: list[dict[str, Any]] = []
    schedule = sorted(
        plan.get("interrupt_schedule", []) or [],
        key=lambda row: (int(row.get("order", 0)), str(row.get("event_id", ""))),
    )
    if not schedule:
        raise ValueError("Execution Plan has no interrupt_schedule")
    if len(schedule) > 16:
        raise ValueError("interrupt schedule exceeds the bounded 16-event limit")

    seen_addresses: set[int] = set()
    for index, row in enumerate(schedule):
        symbol_name = str(row.get("trigger_symbol", ""))
        if symbol_name not in symbols:
            raise ValueError(f"IRQ trigger symbol not found: {symbol_name}")
        offset = int(row.get("trigger_offset", 0))
        address = symbols[symbol_name] + offset
        if address in seen_addresses:
            raise ValueError("two IRQ events resolve to the same one-shot address")
        seen_addresses.add(address)
        name = f"ct_plan_irq_{index:02d}"
        model = {"addr": address, "irq": int(row["irq"])}
        triggers[name] = model
        installed.append(
            {
                "name": name,
                "event_id": str(row["event_id"]),
                "order": int(row.get("order", index)),
                "model": copy.deepcopy(model),
                "derivation": {
                    "trigger_symbol": symbol_name,
                    "trigger_offset": offset,
                    "encoding": "ELF_symbol_plus_offset",
                    "evidence_ref": row.get("evidence_ref"),
                },
            }
        )
    periodic_changes: list[dict[str, Any]] = []
    for row in plan.get("periodic_irq_overrides", []) or []:
        name = str(row.get("trigger_name", ""))
        if name not in triggers:
            raise ValueError(f"periodic IRQ trigger not found: {name}")
        model = triggers[name]
        if "every_nth_tick" not in model:
            raise ValueError(f"IRQ trigger is not periodic: {name}")
        expected_irq = int(row["irq"])
        if int(model.get("irq", -1)) != expected_irq:
            raise ValueError(f"periodic IRQ number mismatch for {name}")
        every_nth_tick = int(row["every_nth_tick"])
        if not 1 <= every_nth_tick <= 1_000_000:
            raise ValueError("periodic IRQ interval is outside 1..1000000")
        previous = copy.deepcopy(model)
        model["every_nth_tick"] = every_nth_tick
        periodic_changes.append(
            {
                "name": name,
                "previous_model": previous,
                "model": copy.deepcopy(model),
                "evidence_ref": row["evidence_ref"],
            }
        )
    return result, [
        {
            "removed_triggers": removed,
            "installed_triggers": installed,
            "periodic_trigger_changes": periodic_changes,
        }
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-config", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--output-config", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()

    with args.base_config.open("r", encoding="utf-8") as handle:
        base = yaml.safe_load(handle) or {}
    plan = load_json(args.plan)
    effective, changes = compile_event_overlay(
        base, plan, elf_function_symbols(args.binary)
    )
    args.output_config.parent.mkdir(parents=True, exist_ok=True)
    with args.output_config.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(effective, handle, sort_keys=False)
    write_json(
        args.manifest,
        {
            "schema_version": "ct-mini-fuzzware-event-overlay-v1",
            "base_config": str(args.base_config),
            "base_config_sha256": sha256_file(args.base_config),
            "binary": str(args.binary),
            "binary_sha256": sha256_file(args.binary),
            "plan": str(args.plan),
            "plan_sha256": sha256_file(args.plan),
            "output_config": str(args.output_config),
            "changes": changes,
            "policy": {
                "source_boundary_only": True,
                "program_counter_forcing": False,
                "branch_patching": False,
            },
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
