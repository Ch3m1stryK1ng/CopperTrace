"""Deterministic MMIO register role resolution for hardware profiles.

The resolver consumes trusted metadata only.  It never classifies a register
from code, symbol, peripheral, or register names.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any


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
LEGACY_ROLE_MAP = {
    "DATA": "EXTERNAL_INPUT_DATA",
    "STATUS": "STATUS",
    "CONTROL": "CONTROL",
}


def _address(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative integer or address string")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = int(value.strip(), 0)
        except ValueError as exc:
            raise ValueError(f"invalid {field}: {value!r}") from exc
    else:
        raise ValueError(f"invalid {field}: {value!r}")
    if parsed < 0:
        raise ValueError(f"{field} must be non-negative")
    return parsed


def _optional_address(value: Any, field: str) -> int | None:
    return None if value is None or value == "" else _address(value, field)


def _hex(value: int | None) -> str:
    return "" if value is None else f"0x{value:x}"


def _type_name(value: Any) -> str:
    return re.sub(r"_conflict\d*$", "", str(value or "").strip())


def _normalized_role(value: Any) -> tuple[str, str]:
    original = str(value or "").strip().upper()
    normalized = LEGACY_ROLE_MAP.get(original, original)
    if normalized not in REGISTER_ROLES:
        raise ValueError(f"unsupported register role: {value!r}")
    return normalized, original


def _coalesce_address(field: str, *values: Any) -> int | None:
    parsed = [_address(value, field) for value in values if value is not None and value != ""]
    if not parsed:
        return None
    if len(set(parsed)) != 1:
        raise ValueError(f"conflicting {field} values")
    return parsed[0]


def _candidate_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        row.get("address", 1 << 128),
        str(row.get("peripheral_type", "")),
        row.get("field_offset", 1 << 128),
        row.get("instance_base", 1 << 128),
        str(row.get("peripheral_instance", "")),
        str(row.get("register", "")),
        str(row.get("role", "")),
        str(row.get("evidence_source", "")),
        str(row.get("evidence_reference", "")),
    )


def _public_candidate(row: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in (
        "address",
        "peripheral_type",
        "field_offset",
        "peripheral_instance",
        "instance_base",
        "register",
        "role",
        "evidence_source",
        "evidence_reference",
    ):
        if key not in row:
            continue
        value = row[key]
        result[key] = _hex(value) if key in {"address", "field_offset", "instance_base"} else value
    if row.get("legacy_role"):
        result["legacy_role"] = row["legacy_role"]
    return result


class MMIORegisterResolver:
    """Resolve MMIO access facts against one immutable metadata profile."""

    def __init__(
        self,
        profile: Mapping[str, Any],
        *,
        platform_id: str | None = None,
        binary_sha256: str | None = None,
    ) -> None:
        self.profile = dict(profile)
        self.schema_version = str(profile.get("schema_version", ""))
        self.platform_id = str(profile.get("platform_id", ""))
        self.binary_sha256 = str(profile.get("binary_sha256", "")).lower()
        self._scope_error = self._scope_mismatch(platform_id, binary_sha256)
        self._registers = tuple(self._normalize_registers(profile))
        self._instances = tuple(self._normalize_instances(profile))
        self._ranges = tuple(self._normalize_ranges(profile))

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        platform_id: str | None = None,
        binary_sha256: str | None = None,
    ) -> "MMIORegisterResolver":
        profile = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(profile, platform_id=platform_id, binary_sha256=binary_sha256)

    def _scope_mismatch(
        self, expected_platform: str | None, expected_binary: str | None
    ) -> str:
        if expected_platform and self.platform_id and expected_platform != self.platform_id:
            return "platform_id_mismatch"
        if expected_binary:
            expected = str(expected_binary).strip().lower()
            if not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("binary_sha256 must contain 64 hexadecimal characters")
            if self.binary_sha256 and expected != self.binary_sha256:
                return "binary_sha256_mismatch"
        return ""

    def _normalize_registers(self, profile: Mapping[str, Any]) -> list[dict[str, Any]]:
        raw_rows: list[Any] = []
        raw_rows.extend(list(profile.get("registers", []) or []))
        raw_rows.extend(list(profile.get("register_metadata", []) or []))
        default_source = str(profile.get("metadata_source", "hardware_metadata"))
        default_reference = str(
            profile.get("evidence_reference", self.schema_version or "hardware_metadata")
        )
        result: list[dict[str, Any]] = []
        for raw in raw_rows:
            row = dict(raw)
            role, original_role = _normalized_role(row.get("role"))
            normalized: dict[str, Any] = {
                "role": role,
                "evidence_source": str(row.get("evidence_source", default_source)),
                "evidence_reference": str(row.get("evidence_reference", default_reference)),
            }
            if original_role != role:
                normalized["legacy_role"] = original_role

            address = row.get("address", row.get("absolute_address"))
            if address is not None:
                normalized["address"] = _address(address, "register address")
            peripheral_type = _type_name(row.get("peripheral_type"))
            if peripheral_type:
                normalized["peripheral_type"] = peripheral_type
            field_offset = row.get("field_offset", row.get("offset"))
            if field_offset is not None:
                normalized["field_offset"] = _address(field_offset, "field_offset")
            peripheral_instance = str(
                row.get(
                    "peripheral_instance",
                    row.get("instance_name", row.get("peripheral", "")),
                )
                or ""
            ).strip()
            if peripheral_instance:
                normalized["peripheral_instance"] = peripheral_instance
            instance_base = row.get("instance_base", row.get("base_address"))
            if instance_base is not None:
                normalized["instance_base"] = _address(instance_base, "instance_base")
            register = str(row.get("register", row.get("field_name", "")) or "").strip()
            if register:
                normalized["register"] = register

            if "address" not in normalized and not {
                "peripheral_type",
                "field_offset",
            }.issubset(normalized):
                raise ValueError(
                    "register metadata needs address or peripheral_type plus field_offset"
                )
            result.append(normalized)
        return sorted(result, key=_candidate_key)

    def _normalize_instances(self, profile: Mapping[str, Any]) -> list[dict[str, Any]]:
        instances: list[dict[str, Any]] = []
        for raw in list(profile.get("peripheral_instances", []) or []):
            row = dict(raw)
            instances.append(
                {
                    "peripheral_instance": str(
                        row.get("peripheral_instance", row.get("instance_name", ""))
                    ).strip(),
                    "peripheral_type": _type_name(row.get("peripheral_type")),
                    "instance_base": _address(
                        row.get("instance_base", row.get("base_address")), "instance_base"
                    ),
                }
            )
        for register in self._registers:
            if "instance_base" not in register or "peripheral_type" not in register:
                continue
            instances.append(
                {
                    "peripheral_instance": str(register.get("peripheral_instance", "")),
                    "peripheral_type": register["peripheral_type"],
                    "instance_base": register["instance_base"],
                }
            )
        unique = {
            (
                row["peripheral_instance"],
                row["peripheral_type"],
                row["instance_base"],
            ): row
            for row in instances
        }
        return sorted(
            unique.values(),
            key=lambda row: (
                row["instance_base"],
                row["peripheral_type"],
                row["peripheral_instance"],
            ),
        )

    def _normalize_ranges(self, profile: Mapping[str, Any]) -> list[tuple[int, int]]:
        result: list[tuple[int, int]] = []
        for raw in list(profile.get("mmio_ranges", []) or []):
            row = dict(raw)
            start = _address(row.get("start"), "mmio range start")
            end = _address(row.get("end"), "mmio range end")
            if end < start:
                raise ValueError("MMIO range end precedes its start")
            result.append((start, end))
        return sorted(set(result))

    def _absolute_candidates(self, address: int | None) -> list[dict[str, Any]]:
        if address is None:
            return []
        return [row for row in self._registers if row.get("address") == address]

    def _typed_candidates(
        self,
        peripheral_type: str,
        typed_base: int | None,
        offset: int | None,
    ) -> list[dict[str, Any]]:
        if not peripheral_type or offset is None:
            return []
        computed_address = typed_base + offset if typed_base is not None else None
        result = []
        for row in self._registers:
            if row.get("peripheral_type") != peripheral_type:
                continue
            if row.get("field_offset") != offset:
                continue
            if typed_base is not None:
                if "instance_base" in row and row["instance_base"] != typed_base:
                    continue
                if "address" in row and row["address"] != computed_address:
                    continue
            result.append(row)
        if computed_address is not None:
            result.extend(self._absolute_candidates(computed_address))
        return result

    def _instance_candidates(self, instance_base: int | None, offset: int | None) -> list[dict[str, Any]]:
        if instance_base is None or offset is None:
            return []
        address = instance_base + offset
        types = {
            row["peripheral_type"]
            for row in self._instances
            if row["instance_base"] == instance_base and row.get("peripheral_type")
        }
        result = self._absolute_candidates(address)
        for row in self._registers:
            direct_instance_match = (
                row.get("instance_base") == instance_base
                and row.get("field_offset") == offset
            )
            typed_instance_match = (
                row.get("peripheral_type") in types
                and row.get("field_offset") == offset
                and row.get("instance_base", instance_base) == instance_base
                and row.get("address", address) == address
            )
            if direct_instance_match or typed_instance_match:
                result.append(row)
        return result

    @staticmethod
    def _deduplicate(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        unique: dict[str, dict[str, Any]] = {}
        for row in rows:
            key = json.dumps(_public_candidate(row), sort_keys=True, separators=(",", ":"))
            unique[key] = row
        return sorted(unique.values(), key=_candidate_key)

    def _outside_ranges(self, address: int | None) -> bool:
        if address is None or not self._ranges:
            return False
        return not any(start <= address <= end for start, end in self._ranges)

    def resolve(
        self,
        absolute_address: Any = None,
        *,
        address: Any = None,
        peripheral_type: str | None = None,
        typed_base: Any = None,
        constant_offset: Any = None,
        instance_base: Any = None,
        offset: Any = None,
        field_offset: Any = None,
        base_address: Any = None,
    ) -> dict[str, Any]:
        """Resolve one access using absolute, typed, then instance facts.

        ``base_address`` is an alias for ``typed_base`` when a peripheral type
        is supplied, and for ``instance_base`` otherwise.  ``offset`` and
        ``field_offset`` are aliases for ``constant_offset``.
        """

        direct_address = _coalesce_address("absolute_address", absolute_address, address)
        access_offset = _coalesce_address(
            "constant_offset", constant_offset, offset, field_offset
        )
        normalized_type = _type_name(peripheral_type)
        if normalized_type:
            resolved_typed_base = _coalesce_address("typed_base", typed_base, base_address)
            resolved_instance_base = _optional_address(instance_base, "instance_base")
        else:
            resolved_typed_base = _optional_address(typed_base, "typed_base")
            resolved_instance_base = _coalesce_address(
                "instance_base", instance_base, base_address
            )

        typed_address = (
            resolved_typed_base + access_offset
            if resolved_typed_base is not None and access_offset is not None
            else None
        )
        instance_address = (
            resolved_instance_base + access_offset
            if resolved_instance_base is not None and access_offset is not None
            else None
        )
        result_address = direct_address
        if result_address is None:
            result_address = typed_address if typed_address is not None else instance_address

        query = {
            "absolute_address": _hex(direct_address),
            "peripheral_type": normalized_type,
            "typed_base": _hex(resolved_typed_base),
            "instance_base": _hex(resolved_instance_base),
            "constant_offset": _hex(access_offset),
        }
        if self._scope_error:
            return self._unresolved(self._scope_error, query, result_address, "", [])

        tiers = [
            ("absolute_address", self._absolute_candidates(direct_address)),
            (
                "typed_base_offset",
                self._typed_candidates(normalized_type, resolved_typed_base, access_offset),
            ),
            (
                "instance_base_offset",
                self._instance_candidates(resolved_instance_base, access_offset),
            ),
        ]
        selected_kind = ""
        all_candidates: list[dict[str, Any]] = []
        for match_kind, candidates in tiers:
            if candidates and not selected_kind:
                selected_kind = match_kind
            all_candidates.extend(candidates)
        candidates = self._deduplicate(all_candidates)
        if not candidates:
            sufficient = direct_address is not None or (
                access_offset is not None
                and (normalized_type or resolved_instance_base is not None)
            )
            reason = "no_matching_register" if sufficient else "insufficient_address_facts"
            if sufficient and self._outside_ranges(result_address):
                reason = "address_outside_mmio_ranges"
            return self._unresolved(reason, query, result_address, "", [])

        roles = sorted({str(row["role"]) for row in candidates})
        if len(roles) != 1:
            return self._unresolved(
                "conflicting_register_roles",
                query,
                result_address,
                selected_kind,
                candidates,
            )

        primary = candidates[0]
        evidence = sorted(
            {
                (str(row.get("evidence_source", "")), str(row.get("evidence_reference", "")))
                for row in candidates
            }
        )
        result: dict[str, Any] = {
            "status": "resolved",
            "resolved": True,
            "role": roles[0],
            "reason": "",
            "match_kind": selected_kind,
            "address": _hex(result_address if result_address is not None else primary.get("address")),
            "query": query,
            "evidence_source": primary.get("evidence_source", ""),
            "evidence_reference": primary.get("evidence_reference", ""),
            "evidence": [
                {"evidence_source": source, "evidence_reference": reference}
                for source, reference in evidence
            ],
            "candidates": [_public_candidate(row) for row in candidates],
        }
        for key in ("peripheral_type", "peripheral_instance", "register"):
            if primary.get(key):
                result[key] = primary[key]
        if "field_offset" in primary:
            result["field_offset"] = _hex(primary["field_offset"])
        return result

    @staticmethod
    def _unresolved(
        reason: str,
        query: Mapping[str, Any],
        address: int | None,
        match_kind: str,
        candidates: list[dict[str, Any]],
    ) -> dict[str, Any]:
        return {
            "status": "unresolved",
            "resolved": False,
            "role": "UNKNOWN",
            "reason": reason,
            "match_kind": match_kind,
            "address": _hex(address),
            "query": dict(query),
            "evidence_source": "",
            "evidence_reference": "",
            "evidence": [],
            "candidates": [_public_candidate(row) for row in candidates],
        }


MmioRegisterResolver = MMIORegisterResolver


def resolve_mmio_register(
    profile: Mapping[str, Any],
    absolute_address: Any = None,
    **access_facts: Any,
) -> dict[str, Any]:
    """Pure convenience wrapper around :class:`MMIORegisterResolver`."""

    return MMIORegisterResolver(profile).resolve(absolute_address, **access_facts)


def is_external_input_role(role: str) -> bool:
    return str(role).upper() in {"RX_DATA", "EXTERNAL_INPUT_DATA"}
