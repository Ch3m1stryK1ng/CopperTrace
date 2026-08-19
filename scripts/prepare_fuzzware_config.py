#!/usr/bin/env python3
"""Freeze a Fuzzware base config and expose only reported Source MMIO reads."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any

import yaml
from elftools.elf.elffile import ELFFile

from validation_common import load_json, parse_address, sha256_file, write_json


def _source_contexts(evidence: dict[str, Any]) -> list[tuple[int, int]]:
    contexts: set[tuple[int, int]] = set()
    allowed = {
        address
        for value in evidence.get("allowed_register_addresses", []) or []
        for address in [parse_address(value)]
        if address is not None
    }
    sources = [
        *(evidence.get("upstream_hardware_sources", []) or []),
        *(evidence.get("runtime_hardware_sources", []) or []),
    ]
    for source in sources:
        proof = source.get("proof", {}) or {}
        address = parse_address(proof.get("register_address"))
        site = str(source.get("site_id", "")).split(":")
        pc = parse_address("0x" + site[2]) if len(site) >= 3 else None
        if address is None or pc is None or (allowed and address not in allowed):
            continue
        contexts.add((pc & ~1, address))
    return sorted(contexts)


def _manifest_contexts(manifest: dict[str, Any] | None) -> list[tuple[int, int]]:
    if not manifest:
        return []
    rows: set[tuple[int, int]] = set()
    for row in manifest.get("active_source_contexts", []) or []:
        pc = parse_address(row.get("pc"))
        address = parse_address(row.get("register_address"))
        if pc is not None and address is not None:
            rows.add((pc & ~1, address))
    return sorted(rows)


def _same_context(model: dict[str, Any], pc: int, address: int) -> bool:
    return parse_address(model.get("pc")) == pc and parse_address(model.get("addr")) == address


def _elf_symbols(binary: Path) -> dict[str, tuple[int, int, Any]]:
    symbols: dict[str, tuple[int, int, Any]] = {}
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        for table in elf.iter_sections():
            if table["sh_type"] not in {"SHT_SYMTAB", "SHT_DYNSYM"}:
                continue
            for symbol in table.iter_symbols():
                if not symbol.name or symbol["st_shndx"] == "SHN_UNDEF":
                    continue
                symbols.setdefault(
                    symbol.name,
                    (
                        int(symbol["st_value"]),
                        int(symbol["st_size"]),
                        symbol["st_shndx"],
                    ),
                )
    return symbols


def _read_elf_symbol_field(
    binary: Path,
    *,
    symbol_name: str,
    field_offset: int,
    field_size: int,
) -> int:
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        symbol = next(
            (
                symbol
                for table in elf.iter_sections()
                if table["sh_type"] in {"SHT_SYMTAB", "SHT_DYNSYM"}
                for symbol in table.iter_symbols()
                if symbol.name == symbol_name
                and symbol["st_shndx"] != "SHN_UNDEF"
            ),
            None,
        )
        if symbol is None:
            raise ValueError(f"hardware event object symbol not found: {symbol_name}")
        symbol_size = int(symbol["st_size"])
        if field_offset < 0 or field_size not in {1, 2, 4, 8}:
            raise ValueError("invalid hardware event object field")
        if symbol_size and field_offset + field_size > symbol_size:
            raise ValueError(
                f"hardware event field exceeds {symbol_name} size {symbol_size}"
            )
        section = elf.get_section(symbol["st_shndx"])
        section_offset = int(symbol["st_value"]) - int(section["sh_addr"])
        data = section.data()[
            section_offset + field_offset : section_offset + field_offset + field_size
        ]
        if len(data) != field_size:
            raise ValueError(f"hardware event field unavailable: {symbol_name}")
        return int.from_bytes(data, "little")


def materialize_hardware_event_models(
    binary: Path,
    profile: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Derive relocatable runtime events from non-vulnerability metadata."""
    if not profile:
        return []
    if profile.get("schema_version") != "ct-mini-hardware-events-v1":
        raise ValueError("unsupported hardware event profile schema")
    symbols = _elf_symbols(binary)
    rows: list[dict[str, Any]] = []
    for spec in profile.get("models", []) or []:
        kind = str(spec.get("kind", ""))
        if kind not in {
            "gpio_irq_status",
            "discarded_mmio_read",
            "interrupt_trigger",
        }:
            raise ValueError(f"unsupported hardware event kind: {spec.get('kind')}")
        function_name = str(spec.get("function_symbol", ""))
        function = symbols.get(function_name)
        if function is None:
            raise ValueError(f"hardware event function not found: {function_name}")
        function_offset = parse_address(spec.get("function_offset"))
        if function_offset is None:
            raise ValueError("hardware event profile has no function offset")
        pc = (function[0] & ~1) + function_offset
        if kind == "interrupt_trigger":
            irq = parse_address(spec.get("irq"))
            if irq is None:
                raise ValueError("interrupt trigger has no IRQ")
            rows.append(
                {
                    "name": str(spec.get("name") or f"irq_after_{function_name}"),
                    "kind": "interrupt_trigger",
                    "trigger_name": str(
                        spec.get("trigger_name")
                        or spec.get("name")
                        or f"irq_after_{function_name}"
                    ),
                    "model": {"addr": pc, "irq": irq},
                    "derivation": {
                        "function_symbol": function_name,
                        "function_offset": function_offset,
                        "encoding": "ELF_symbol_plus_offset",
                        "metadata_reference": spec.get("metadata_reference"),
                    },
                }
            )
            continue
        register_address = parse_address(spec.get("register_address"))
        if register_address is None:
            raise ValueError("MMIO hardware event has no register address")
        if kind == "gpio_irq_status":
            field_offset = parse_address(spec.get("pin_field_offset"))
            field_size = parse_address(spec.get("pin_field_size"))
            if None in {field_offset, field_size}:
                raise ValueError("GPIO event profile has incomplete field metadata")
            pin = _read_elf_symbol_field(
                binary,
                symbol_name=str(spec.get("config_symbol", "")),
                field_offset=field_offset,
                field_size=field_size,
            )
            if not 0 <= pin < 32:
                raise ValueError(f"GPIO IRQ pin is outside a 32-bit port: {pin}")
            value = 1 << pin
            derivation = {
                "function_symbol": function_name,
                "function_offset": function_offset,
                "config_symbol": str(spec.get("config_symbol", "")),
                "pin_field_offset": field_offset,
                "pin": pin,
                "encoding": "BIT(pin)",
                "metadata_reference": spec.get("metadata_reference"),
            }
        else:
            value = parse_address(spec.get("value"))
            if value is None:
                raise ValueError("discarded MMIO read model has no value")
            derivation = {
                "function_symbol": function_name,
                "function_offset": function_offset,
                "encoding": "constant_for_discarded_read",
                "metadata_reference": spec.get("metadata_reference"),
            }
        rows.append(
            {
                "name": str(spec.get("name") or f"gpio_irq_{function_name}"),
                "kind": "constant",
                "model": {
                    "pc": pc,
                    "addr": register_address,
                    "access_size": 4,
                    "val": value,
                },
                "derivation": derivation,
            }
        )
    return rows


def apply_hardware_event_models(
    config: dict[str, Any],
    event_models: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    models = config.setdefault("mmio_models", {})
    changes: list[dict[str, Any]] = []
    for event in event_models:
        model = event["model"]
        if event["kind"] == "interrupt_trigger":
            trigger_name = str(event["trigger_name"])
            triggers = config.setdefault("interrupt_triggers", {})
            previous = copy.deepcopy(triggers.get(trigger_name))
            triggers[trigger_name] = copy.deepcopy(model)
            changes.append(
                {
                    "name": str(event["name"]),
                    "event_kind": "interrupt_trigger",
                    "trigger_name": trigger_name,
                    "installed_model": copy.deepcopy(model),
                    "derivation": copy.deepcopy(event["derivation"]),
                    "replaced_trigger": previous,
                }
            )
            continue
        pc = int(model["pc"])
        address = int(model["addr"])
        removed: list[dict[str, Any]] = []
        for family, entries in models.items():
            if not isinstance(entries, dict):
                continue
            for name, existing in list(entries.items()):
                if isinstance(existing, dict) and _same_context(existing, pc, address):
                    removed.append(
                        {"kind": family, "name": name, "model": copy.deepcopy(existing)}
                    )
                    del entries[name]
        name = str(event["name"])
        models.setdefault(str(event["kind"]), {})[name] = copy.deepcopy(model)
        changes.append(
            {
                "name": name,
                "event_kind": "mmio_model",
                "installed_model": copy.deepcopy(model),
                "derivation": copy.deepcopy(event["derivation"]),
                "removed_models": removed,
            }
        )
    return changes


def merge_generated_models(
    base: dict[str, Any], generated: dict[str, Any] | None
) -> dict[str, Any]:
    """Merge the official pipeline's MMIO model output into its base config."""
    result = copy.deepcopy(base)
    if not generated:
        return result
    target_models = result.setdefault("mmio_models", {})
    for kind, entries in (generated.get("mmio_models", {}) or {}).items():
        if not isinstance(entries, dict):
            continue
        target_models.setdefault(kind, {}).update(copy.deepcopy(entries))
    return result


def cortex_m_external_irq_to_exception(external_irq: int) -> int:
    if external_irq < 0:
        raise ValueError("external IRQ index must be nonnegative")
    return 16 + external_irq


def zephyr_sw_isr_candidates(binary: Path, evidence: dict[str, Any]) -> list[int]:
    """Recover Fuzzware exception numbers for Source-bound Zephyr IRQ entries."""
    handler_starts = {
        int(parts[1], 16) & ~1
        for row in evidence.get("upstream_hardware_sources", []) or []
        for parts in [str(row.get("site_id", "")).split(":")]
        if len(parts) >= 3
    }
    if not handler_starts:
        return []
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        symbol = next(
            (
                sym
                for table in elf.iter_sections()
                if table["sh_type"] in {"SHT_SYMTAB", "SHT_DYNSYM"}
                for sym in table.iter_symbols()
                if sym.name == "_sw_isr_table"
            ),
            None,
        )
        if symbol is None:
            return []
        section = elf.get_section(symbol["st_shndx"])
        offset = int(symbol["st_value"]) - int(section["sh_addr"])
        data = section.data()[offset : offset + int(symbol["st_size"])]
    candidates: list[int] = []
    for external_irq, entry_offset in enumerate(range(0, len(data) - 7, 8)):
        handler = int.from_bytes(data[entry_offset + 4 : entry_offset + 8], "little")
        if handler & ~1 in handler_starts:
            # Fuzzware's NVIC API consumes Cortex-M exception numbers.
            # External interrupt N is exception 16 + N.
            candidates.append(cortex_m_external_irq_to_exception(external_irq))
    return candidates


def prepare_config(
    base: dict[str, Any], evidence: dict[str, Any], *, irq: int | None = None,
    irq_interval: int = 1000,
    readiness_manifest: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    result = copy.deepcopy(base)
    models = result.setdefault("mmio_models", {})
    evidence_contexts = set(_source_contexts(evidence))
    active_contexts = set(_manifest_contexts(readiness_manifest))
    if active_contexts and not active_contexts.issubset(evidence_contexts):
        raise ValueError("readiness manifest contains a non-evidence Source context")
    contexts = sorted(active_contexts or evidence_contexts)
    removed: list[dict[str, Any]] = []
    for model_kind, entries in list(models.items()):
        if not isinstance(entries, dict) or model_kind == "unmodeled":
            continue
        for name, model in list(entries.items()):
            if not isinstance(model, dict):
                continue
            if any(_same_context(model, pc, address) for pc, address in contexts):
                removed.append({"kind": model_kind, "name": name, "model": model})
                del entries[name]

    unmodeled = models.setdefault("unmodeled", {})
    for pc, address in contexts:
        name = f"ct_source_pc_{pc:08x}_mmio_{address:08x}"
        unmodeled[name] = {"pc": pc, "addr": address}

    manifest = [
        {
            "pc": f"0x{pc:x}",
            "register_address": f"0x{address:x}",
            "model": "unmodeled",
        }
        for pc, address in contexts
    ]
    if not manifest:
        raise ValueError("no exact Source MMIO contexts found in evidence")
    if irq is not None:
        result.setdefault("interrupt_triggers", {})["ct_source_irq"] = {
            "every_nth_tick": irq_interval,
            "irq": irq,
        }
    return result, [{"source_contexts": manifest, "removed_models": removed}]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-config", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--model-config", type=Path)
    parser.add_argument("--output-config", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--hardware-event-profile", type=Path)
    parser.add_argument("--irq", type=int)
    parser.add_argument("--irq-interval", type=int, default=1000)
    parser.add_argument("--readiness-manifest", type=Path)
    args = parser.parse_args()

    with args.base_config.open("r", encoding="utf-8") as handle:
        base = yaml.safe_load(handle) or {}
    generated = None
    if args.model_config:
        with args.model_config.open("r", encoding="utf-8") as handle:
            generated = yaml.safe_load(handle) or {}
    base = merge_generated_models(base, generated)
    evidence = load_json(args.evidence)
    readiness_manifest = (
        load_json(args.readiness_manifest) if args.readiness_manifest else None
    )
    hardware_event_profile = (
        load_json(args.hardware_event_profile)
        if args.hardware_event_profile
        else None
    )
    if hardware_event_profile and not args.binary:
        raise ValueError("--hardware-event-profile requires --binary")
    irq_candidates = (
        zephyr_sw_isr_candidates(args.binary, evidence) if args.binary else []
    )
    if args.irq is not None and irq_candidates and args.irq not in irq_candidates:
        raise ValueError("requested IRQ is not bound to a reported Source handler")
    effective, changes = prepare_config(
        base,
        evidence,
        irq=args.irq,
        irq_interval=args.irq_interval,
        readiness_manifest=readiness_manifest,
    )
    hardware_event_changes: list[dict[str, Any]] = []
    if args.binary and hardware_event_profile:
        hardware_event_changes = apply_hardware_event_models(
            effective,
            materialize_hardware_event_models(args.binary, hardware_event_profile),
        )
    args.output_config.parent.mkdir(parents=True, exist_ok=True)
    with args.output_config.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(effective, handle, sort_keys=False)
    write_json(
        args.manifest,
        {
            "schema_version": "ct-mini-fuzzware-config-v1",
            "base_config": str(args.base_config),
            "base_config_sha256": sha256_file(args.base_config),
            "model_config": str(args.model_config) if args.model_config else None,
            "model_config_sha256": (
                sha256_file(args.model_config) if args.model_config else None
            ),
            "effective_config": str(args.output_config),
            "changes": changes,
            "irq_candidates": irq_candidates,
            "selected_irq": args.irq,
            "readiness_manifest": (
                str(args.readiness_manifest) if args.readiness_manifest else None
            ),
            "hardware_event_profile": (
                str(args.hardware_event_profile)
                if args.hardware_event_profile
                else None
            ),
            "hardware_event_profile_sha256": (
                sha256_file(args.hardware_event_profile)
                if args.hardware_event_profile
                else None
            ),
            "hardware_event_changes": hardware_event_changes,
            "policy": {
                "source_boundary_only": True,
                "program_counter_forcing": False,
                "branch_patching": False,
                "source_buffer_writes": False,
            },
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
