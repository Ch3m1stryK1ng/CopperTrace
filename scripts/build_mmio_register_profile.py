#!/usr/bin/env python3
"""Build deterministic MMIO register profiles from CMSIS facts and role data.

CMSIS headers establish register layouts and peripheral instance addresses.  A
separate, trusted overlay establishes register roles.  This module deliberately
does not infer a role from a register, binary, or code symbol name.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = "ct-mini-hardware-metadata-v2"
METADATA_SOURCES = {"svd", "typed_register_map", "trusted_platform_summary"}
REGISTER_ROLES = {
    "RX_DATA",
    "EXTERNAL_INPUT_DATA",
    "TX_DATA",
    "STATUS",
    "CONTROL",
    "DMA_RX_BUFFER_POINTER",
    "DMA_BUFFER_POINTER",
    "DMA_PERIPHERAL_SOURCE",
    "DMA_MEMORY_DESTINATION",
    "DMA_TRANSFER_COUNT",
    "DMA_DIRECTION",
    "DMA_START",
    "RX_START",
    "TX_START",
    "UNKNOWN",
}
LEGACY_ROLES = {
    "DATA": "EXTERNAL_INPUT_DATA",
    "STATUS": "STATUS",
    "CONTROL": "CONTROL",
}


def _address(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative integer or address string")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            result = int(text, 0)
        except ValueError as exc:
            raise ValueError(f"invalid {field}: {value!r}") from exc
    else:
        raise ValueError(f"invalid {field}: {value!r}")
    if result < 0:
        raise ValueError(f"{field} must be non-negative")
    return result


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _text(value: Any, field: str) -> str:
    result = str(value or "").strip()
    if not result:
        raise ValueError(f"{field} must be a non-empty string")
    return result


def _role(value: Any) -> str:
    role = _text(value, "role").upper()
    role = LEGACY_ROLES.get(role, role)
    if role not in REGISTER_ROLES:
        raise ValueError(f"unsupported register role: {value!r}")
    return role


def _find_sourceagent_root(explicit_root: str | Path | None) -> Path | None:
    candidates: list[Path] = []
    if explicit_root:
        candidates.append(Path(explicit_root))
    if os.environ.get("COPPERTRACE_SOURCEAGENT_ROOT"):
        candidates.append(Path(os.environ["COPPERTRACE_SOURCEAGENT_ROOT"]))
    candidates.append(Path(__file__).resolve().parents[2] / "sourceagent")
    for candidate in candidates:
        root = candidate.resolve()
        if (root / "sourceagent" / "pipeline" / "cmsis_parser.py").is_file():
            return root
    return None


def _cmsis_parsers(
    sourceagent_root: str | Path | None = None,
) -> tuple[Callable[[str], dict[str, dict[str, int]]], Callable[[str], dict[str, tuple[str, int]]]]:
    try:
        from sourceagent.pipeline.cmsis_parser import parse_base_addresses, parse_cmsis_header

        return parse_cmsis_header, parse_base_addresses
    except ModuleNotFoundError as first_error:
        root = _find_sourceagent_root(sourceagent_root)
        if root is None:
            raise ModuleNotFoundError(
                "cannot import sourceagent.pipeline.cmsis_parser; set "
                "COPPERTRACE_SOURCEAGENT_ROOT"
            ) from first_error
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from sourceagent.pipeline.cmsis_parser import parse_base_addresses, parse_cmsis_header

        return parse_cmsis_header, parse_base_addresses


def _header_facts(
    header_paths: Sequence[str | Path],
    *,
    sourceagent_root: str | Path | None,
) -> tuple[
    dict[str, dict[str, int]],
    dict[str, tuple[str, int]],
    dict[tuple[str, str], set[str]],
    dict[str, set[str]],
]:
    parse_cmsis_header, parse_base_addresses = _cmsis_parsers(sourceagent_root)
    structs: dict[str, dict[str, int]] = {}
    instances: dict[str, tuple[str, int]] = {}
    field_sources: dict[tuple[str, str], set[str]] = {}
    instance_sources: dict[str, set[str]] = {}

    paths = sorted({Path(path).resolve() for path in header_paths}, key=lambda item: item.as_posix())
    if not paths:
        raise ValueError("at least one CMSIS header is required")
    for path in paths:
        if not path.is_file():
            raise ValueError(f"CMSIS header does not exist: {path}")
        reference = path.name
        for peripheral_type, fields in parse_cmsis_header(str(path)).items():
            target = structs.setdefault(peripheral_type, {})
            for register, raw_offset in fields.items():
                offset = _address(raw_offset, f"offset for {peripheral_type}.{register}")
                previous = target.get(register)
                if previous is not None and previous != offset:
                    raise ValueError(
                        f"conflicting CMSIS offsets for {peripheral_type}.{register}: "
                        f"{_hex(previous)} and {_hex(offset)}"
                    )
                target[register] = offset
                field_sources.setdefault((peripheral_type, register), set()).add(reference)

        for peripheral_instance, raw_instance in parse_base_addresses(str(path)).items():
            peripheral_type, raw_base = raw_instance
            base = _address(raw_base, f"base for {peripheral_instance}")
            parsed = (str(peripheral_type), base)
            previous = instances.get(peripheral_instance)
            if previous is not None and previous != parsed:
                raise ValueError(
                    f"conflicting CMSIS bases for {peripheral_instance}: "
                    f"{previous!r} and {parsed!r}"
                )
            instances[peripheral_instance] = parsed
            instance_sources.setdefault(peripheral_instance, set()).add(reference)
    return structs, instances, field_sources, instance_sources


def _overlay_rows(role_overlay: Mapping[str, Any] | Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if isinstance(role_overlay, Mapping):
        rows: list[dict[str, Any]] = []
        for key in ("registers", "register_roles", "roles", "register_metadata"):
            value = role_overlay.get(key)
            if value is None:
                continue
            if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
                raise ValueError(f"{key} must be an array")
            rows.extend(dict(item) for item in value)
        return rows
    if isinstance(role_overlay, Sequence) and not isinstance(role_overlay, (str, bytes)):
        return [dict(item) for item in role_overlay]
    raise ValueError("role overlay must be an object or array")


def _normalize_overlay(
    row: Mapping[str, Any],
    *,
    structs: Mapping[str, Mapping[str, int]],
    instances: Mapping[str, tuple[str, int]],
    default_evidence_source: str,
    default_evidence_reference: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "role": _role(row.get("role")),
        "evidence_source": _text(
            row.get("evidence_source", default_evidence_source), "evidence_source"
        ),
        "evidence_reference": _text(
            row.get("evidence_reference", default_evidence_reference), "evidence_reference"
        ),
    }

    address_value = row.get("address", row.get("absolute_address"))
    if address_value is not None:
        result["address"] = _address(address_value, "register address")

    peripheral_type = str(row.get("peripheral_type", "") or "").strip()
    peripheral_instance = str(
        row.get("peripheral_instance", row.get("instance_name", "")) or ""
    ).strip()
    legacy_peripheral = str(row.get("peripheral", "") or "").strip()
    if not peripheral_instance and legacy_peripheral in instances:
        peripheral_instance = legacy_peripheral
    if peripheral_instance and peripheral_instance in instances:
        instance_type, instance_base = instances[peripheral_instance]
        if peripheral_type and peripheral_type != instance_type:
            raise ValueError(
                f"overlay type {peripheral_type} conflicts with {peripheral_instance} type "
                f"{instance_type}"
            )
        peripheral_type = peripheral_type or instance_type
        result["instance_base"] = instance_base

    raw_instance_base = row.get("instance_base", row.get("base_address"))
    if raw_instance_base is not None:
        supplied_base = _address(raw_instance_base, "instance_base")
        previous_base = result.get("instance_base")
        if previous_base is not None and previous_base != supplied_base:
            raise ValueError(f"conflicting instance base for {peripheral_instance}")
        result["instance_base"] = supplied_base

    if peripheral_type:
        result["peripheral_type"] = peripheral_type
    if peripheral_instance:
        result["peripheral_instance"] = peripheral_instance

    register = str(
        row.get("register", row.get("field_name", row.get("field", ""))) or ""
    ).strip()
    raw_offset = row.get("field_offset", row.get("offset"))
    if raw_offset is not None:
        result["field_offset"] = _address(raw_offset, "field_offset")
    elif peripheral_type and register:
        try:
            result["field_offset"] = structs[peripheral_type][register]
        except KeyError as exc:
            raise ValueError(f"unknown CMSIS field {peripheral_type}.{register}") from exc
    if register:
        result["register"] = register

    if "address" not in result and "instance_base" in result and "field_offset" in result:
        result["address"] = result["instance_base"] + result["field_offset"]
    if "address" not in result and not {
        "peripheral_type",
        "field_offset",
    }.issubset(result):
        raise ValueError(
            "each role overlay row needs address or peripheral_type plus field_offset"
        )
    return result


def _fact_matches_overlay(fact: Mapping[str, Any], overlay: Mapping[str, Any]) -> bool:
    selectors = (
        "address",
        "peripheral_type",
        "field_offset",
        "peripheral_instance",
        "instance_base",
        "register",
    )
    return all(key not in overlay or fact.get(key) == overlay[key] for key in selectors)


def _evidence_reference(references: set[str]) -> str:
    return ",".join(sorted(references)) or "cmsis_header"


def _register_sort_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("address", 1 << 128),
        str(row.get("peripheral_type", "")),
        row.get("field_offset", 1 << 128),
        str(row.get("peripheral_instance", "")),
        str(row.get("register", "")),
        str(row.get("role", "")),
        str(row.get("evidence_source", "")),
        str(row.get("evidence_reference", "")),
    )


def _json_register(row: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(row)
    for key in ("address", "field_offset", "instance_base"):
        if key in result:
            result[key] = _hex(int(result[key]))
    return result


def _normalize_ranges(
    role_overlay: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    default_evidence_source: str,
    default_evidence_reference: str,
) -> list[dict[str, Any]]:
    if not isinstance(role_overlay, Mapping):
        return []
    raw_ranges = role_overlay.get("mmio_ranges", []) or []
    if not isinstance(raw_ranges, Sequence) or isinstance(raw_ranges, (str, bytes)):
        raise ValueError("mmio_ranges must be an array")
    ranges: list[dict[str, Any]] = []
    for raw in raw_ranges:
        row = dict(raw)
        start = _address(row.get("start"), "mmio range start")
        end = _address(row.get("end"), "mmio range end")
        if end < start:
            raise ValueError(f"MMIO range end {_hex(end)} precedes start {_hex(start)}")
        normalized = {
            "start": start,
            "end": end,
            "evidence_source": _text(
                row.get("evidence_source", default_evidence_source), "evidence_source"
            ),
            "evidence_reference": _text(
                row.get("evidence_reference", default_evidence_reference),
                "evidence_reference",
            ),
        }
        if row.get("name"):
            normalized["name"] = _text(row["name"], "range name")
        ranges.append(normalized)
    return ranges


def build_mmio_register_profile(
    cmsis_headers: Sequence[str | Path],
    role_overlay: Mapping[str, Any] | Sequence[Mapping[str, Any]],
    *,
    platform_id: str | None = None,
    binary_sha256: str | None = None,
    scope: str | None = None,
    overlay_reference: str = "role_overlay",
    sourceagent_root: str | Path | None = None,
) -> dict[str, Any]:
    """Return a stable v2 profile without consulting firmware code semantics."""

    structs, instances, field_sources, instance_sources = _header_facts(
        cmsis_headers, sourceagent_root=sourceagent_root
    )
    overlay_mapping = role_overlay if isinstance(role_overlay, Mapping) else {}
    platform = _text(platform_id or overlay_mapping.get("platform_id"), "platform_id")
    metadata_source = str(overlay_mapping.get("metadata_source", "typed_register_map"))
    if metadata_source not in METADATA_SOURCES:
        raise ValueError(f"unsupported metadata_source: {metadata_source!r}")

    profile_scope = str(scope or overlay_mapping.get("scope", "platform")).strip().lower()
    if profile_scope not in {"platform", "binary"}:
        raise ValueError("scope must be 'platform' or 'binary'")
    digest = str(binary_sha256 or overlay_mapping.get("binary_sha256", "")).strip().lower()
    if digest and not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("binary_sha256 must contain 64 lowercase hexadecimal characters")
    if profile_scope == "binary" and not digest:
        raise ValueError("binary scope requires binary_sha256")

    default_evidence_source = _text(
        overlay_mapping.get("evidence_source", "role_overlay"), "evidence_source"
    )
    default_evidence_reference = _text(
        overlay_mapping.get("evidence_reference", overlay_reference), "evidence_reference"
    )
    overlays = [
        _normalize_overlay(
            row,
            structs=structs,
            instances=instances,
            default_evidence_source=default_evidence_source,
            default_evidence_reference=default_evidence_reference,
        )
        for row in _overlay_rows(role_overlay)
    ]

    relevant_types = {peripheral_type for peripheral_type, _ in instances.values()}
    relevant_types.update(
        str(row["peripheral_type"]) for row in overlays if row.get("peripheral_type")
    )
    facts: list[dict[str, Any]] = []
    for peripheral_type in sorted(relevant_types):
        fields = structs.get(peripheral_type, {})
        typed_instances = sorted(
            (
                (name, base)
                for name, (instance_type, base) in instances.items()
                if instance_type == peripheral_type
            ),
            key=lambda item: (item[1], item[0]),
        )
        for register, offset in sorted(fields.items(), key=lambda item: (item[1], item[0])):
            references = set(field_sources.get((peripheral_type, register), set()))
            if typed_instances:
                for peripheral_instance, instance_base in typed_instances:
                    fact = {
                        "address": instance_base + offset,
                        "peripheral_type": peripheral_type,
                        "field_offset": offset,
                        "peripheral_instance": peripheral_instance,
                        "instance_base": instance_base,
                        "register": register,
                        "evidence_source": "cmsis_header",
                        "evidence_reference": _evidence_reference(
                            references | instance_sources.get(peripheral_instance, set())
                        ),
                    }
                    facts.append(fact)
            else:
                facts.append(
                    {
                        "peripheral_type": peripheral_type,
                        "field_offset": offset,
                        "register": register,
                        "evidence_source": "cmsis_header",
                        "evidence_reference": _evidence_reference(references),
                    }
                )

    matched_overlays: set[int] = set()
    registers: list[dict[str, Any]] = []
    for fact in facts:
        matches = [
            (index, overlay)
            for index, overlay in enumerate(overlays)
            if _fact_matches_overlay(fact, overlay)
        ]
        if not matches:
            registers.append({**fact, "role": "UNKNOWN"})
            continue
        for index, overlay in matches:
            matched_overlays.add(index)
            registers.append(
                {
                    **fact,
                    "role": overlay["role"],
                    "evidence_source": overlay["evidence_source"],
                    "evidence_reference": overlay["evidence_reference"],
                }
            )

    for index, overlay in enumerate(overlays):
        if index not in matched_overlays:
            registers.append(dict(overlay))

    deduplicated: dict[str, dict[str, Any]] = {}
    for register in registers:
        key = json.dumps(_json_register(register), sort_keys=True, separators=(",", ":"))
        deduplicated[key] = register
    ordered_registers = sorted(deduplicated.values(), key=_register_sort_key)

    peripheral_instances = []
    for name, (peripheral_type, base) in sorted(
        instances.items(), key=lambda item: (item[1][1], item[1][0], item[0])
    ):
        peripheral_instances.append(
            {
                "peripheral_instance": name,
                "peripheral_type": peripheral_type,
                "instance_base": _hex(base),
                "evidence_source": "cmsis_header",
                "evidence_reference": _evidence_reference(instance_sources.get(name, set())),
            }
        )

    ranges = _normalize_ranges(
        role_overlay,
        default_evidence_source=default_evidence_source,
        default_evidence_reference=default_evidence_reference,
    )
    if not ranges:
        for name, (peripheral_type, base) in sorted(
            instances.items(), key=lambda item: (item[1][1], item[0])
        ):
            offsets = list(structs.get(peripheral_type, {}).values())
            if not offsets:
                continue
            ranges.append(
                {
                    "start": base,
                    "end": base + max(offsets) + 3,
                    "name": name,
                    "evidence_source": "cmsis_header",
                    "evidence_reference": _evidence_reference(
                        instance_sources.get(name, set())
                    ),
                }
            )
    ranges.sort(key=lambda row: (row["start"], row["end"], str(row.get("name", ""))))

    header_references = sorted(
        {reference for references in field_sources.values() for reference in references}
        | {reference for references in instance_sources.values() for reference in references}
    )
    profile: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "scope": profile_scope,
        "metadata_source": metadata_source,
        "platform_id": platform,
        "evidence_source": "cmsis_header+role_overlay",
        "evidence_reference": ",".join(header_references + [default_evidence_reference]),
        "mmio_ranges": [
            {
                **row,
                "start": _hex(int(row["start"])),
                "end": _hex(int(row["end"])),
            }
            for row in ranges
        ],
        "peripheral_instances": peripheral_instances,
        "registers": [_json_register(row) for row in ordered_registers],
    }
    if digest:
        profile["binary_sha256"] = digest
    return profile


def write_profile(profile: Mapping[str, Any], output_path: str | Path) -> None:
    Path(output_path).write_text(
        json.dumps(profile, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cmsis-header",
        "--header",
        action="append",
        dest="cmsis_headers",
        required=True,
        help="CMSIS header; repeat for each input header",
    )
    parser.add_argument("--role-overlay", required=True, type=Path)
    parser.add_argument("--platform-id")
    parser.add_argument("--binary-sha256")
    parser.add_argument("--scope", choices=("platform", "binary"))
    parser.add_argument("--sourceagent-root", type=Path)
    parser.add_argument("--out", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    overlay = json.loads(args.role_overlay.read_text(encoding="utf-8"))
    profile = build_mmio_register_profile(
        args.cmsis_headers,
        overlay,
        platform_id=args.platform_id,
        binary_sha256=args.binary_sha256,
        scope=args.scope,
        overlay_reference=args.role_overlay.name,
        sourceagent_root=args.sourceagent_root,
    )
    write_profile(profile, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
