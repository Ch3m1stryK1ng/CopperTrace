"""Select hardware register profiles from evidence contained in an ELF.

The canonical path never accepts a sample-to-profile mapping.  Profiles are
selected by exact non-file ELF identity symbols when available.  Without an
identity, selection requires an observed MMIO register cluster.  Selection
only enables a register profile; Source confirmation still requires an exact
register access and data-flow proof.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


DMA_REGISTER_ROLES = {
    "DMA_RX_BUFFER_POINTER",
    "DMA_BUFFER_POINTER",
    "DMA_PERIPHERAL_SOURCE",
    "DMA_MEMORY_DESTINATION",
    "DMA_TRANSFER_COUNT",
    "DMA_DIRECTION",
    "DMA_START",
    "RX_START",
    "TX_START",
}

READ_ROLES = {"RX_DATA", "EXTERNAL_INPUT_DATA", "STATUS"}
WRITE_ROLES = {"TX_DATA", "CONTROL"} | DMA_REGISTER_ROLES


def _integer(value: Any) -> int | None:
    if isinstance(value, bool) or value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except ValueError:
        return None


def _hex(value: int | None) -> str:
    return "" if value is None else f"0x{value:x}"


def load_profile_registry(path: str | Path) -> list[dict[str, Any]]:
    """Load generic hardware profiles without using target metadata."""

    root = Path(path)
    paths = [root] if root.is_file() else sorted(root.glob("*.profile.json"))
    profiles: list[dict[str, Any]] = []
    for profile_path in paths:
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        if str(profile.get("scope", "platform")) == "binary":
            continue
        profile["_registry_path"] = str(profile_path)
        profiles.append(profile)
    return profiles


def extract_elf_identity_symbols(path: str | Path) -> dict[str, list[int]]:
    """Read usable identity symbols, excluding file/source-name metadata."""

    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError as exc:  # pragma: no cover - environment failure
        raise RuntimeError("pyelftools is required for ELF identity extraction") from exc

    symbols: dict[str, set[int]] = defaultdict(set)
    with Path(path).open("rb") as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                name = str(symbol.name or "").strip()
                symbol_type = str(symbol["st_info"]["type"])
                if not name or symbol_type == "STT_FILE":
                    continue
                lowered = name.lower()
                if lowered.endswith((".c", ".cc", ".cpp", ".s", ".o")):
                    continue
                symbols[name].add(int(symbol["st_value"]))
    return {name: sorted(values) for name, values in sorted(symbols.items())}


def _required_identity_rows(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    identity = dict(profile.get("binary_identity", {}) or {})
    return [
        {"name": row} if isinstance(row, str) else dict(row or {})
        for row in list(identity.get("required_symbols", []) or [])
    ]


def match_identity(
    profile: Mapping[str, Any], symbols: Mapping[str, list[int]]
) -> dict[str, Any]:
    required = _required_identity_rows(profile)
    if not required:
        return {"status": "not_declared", "matched_symbols": [], "missing_symbols": []}

    matched: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    for row in required:
        name = str(row.get("name", "")).strip()
        expected = _integer(row.get("value"))
        values = list(symbols.get(name, []) or [])
        if not name or not values or (expected is not None and expected not in values):
            missing.append(
                {
                    "name": name,
                    "expected_value": _hex(expected),
                    "observed_values": [_hex(value) for value in values],
                }
            )
            continue
        matched.append(
            {
                "name": name,
                "expected_value": _hex(expected),
                "observed_values": [_hex(value) for value in values],
            }
        )
    return {
        "status": "matched" if not missing else "not_matched",
        "matched_symbols": matched,
        "missing_symbols": missing,
    }


def _profile_id(profile: Mapping[str, Any]) -> str:
    return str(profile.get("profile_id", profile.get("platform_id", ""))).strip()


def _register_rows(profile: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        dict(row or {})
        for row in list(
            profile.get("registers", profile.get("register_metadata", [])) or []
        )
    ]


def _register_address(row: Mapping[str, Any]) -> int | None:
    direct = _integer(row.get("address", row.get("absolute_address")))
    if direct is not None:
        return direct
    base = _integer(row.get("instance_base", row.get("base_address")))
    offset = _integer(row.get("field_offset", row.get("offset")))
    return base + offset if base is not None and offset is not None else None


def _cluster_key(row: Mapping[str, Any]) -> str:
    instance = str(
        row.get("peripheral_instance", row.get("instance_name", ""))
    ).strip()
    if instance:
        return f"instance:{instance}"
    base = _integer(row.get("instance_base", row.get("base_address")))
    if base is not None:
        return f"base:{base:x}"
    address = _register_address(row)
    return f"page:{address & ~0xfff:x}" if address is not None else ""


def _access_compatible(
    role: str,
    observed: set[str],
    observed_behaviors: set[str],
    row: Mapping[str, Any],
) -> bool:
    declared = str(row.get("access", "")).strip().lower()
    if declared:
        allowed = {
            "read-only": {"READ"},
            "write-only": {"WRITE"},
            "read-write": {"READ", "WRITE"},
            "readwrite": {"READ", "WRITE"},
        }.get(declared, {"READ", "WRITE"})
        access_match = bool(observed.intersection(allowed))
    else:
        normalized = str(role).upper()
        if normalized in READ_ROLES:
            access_match = "READ" in observed
        elif normalized in WRITE_ROLES:
            access_match = "WRITE" in observed
        else:
            access_match = bool(observed)
    expected_behaviors = {
        str(value).upper()
        for value in list(row.get("expected_behaviors", []) or [])
        if str(value)
    }
    if expected_behaviors and not expected_behaviors.intersection(observed_behaviors):
        return False
    return access_match


def match_register_clusters(
    profile: Mapping[str, Any],
    accesses: Iterable[Mapping[str, Any]],
    *,
    minimum_registers: int = 2,
) -> list[dict[str, Any]]:
    """Return profile clusters supported by at least two observed registers."""

    observed: dict[int, set[str]] = defaultdict(set)
    behaviors: dict[int, set[str]] = defaultdict(set)
    for access in accesses:
        address = _integer(access.get("address"))
        kind = str(access.get("access", "")).upper()
        if address is not None and kind in {"READ", "WRITE"}:
            observed[address].add(kind)
            behaviors[address].update(
                str(value).upper()
                for value in list(access.get("behaviors", []) or [])
                if str(value)
            )

    clusters: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in _register_rows(profile):
        key = _cluster_key(row)
        if key:
            clusters[key].append(row)

    matches: list[dict[str, Any]] = []
    for key, rows in sorted(clusters.items()):
        matched_rows: list[dict[str, Any]] = []
        for row in rows:
            address = _register_address(row)
            role = str(row.get("role", "")).upper()
            if (
                address is not None
                and address in observed
                and _access_compatible(
                    role,
                    observed[address],
                    behaviors[address],
                    row,
                )
            ):
                matched_rows.append(
                    {
                        "address": _hex(address),
                        "role": role,
                        "observed_accesses": sorted(observed[address]),
                        "observed_behaviors": sorted(behaviors[address]),
                        "register": str(row.get("register", "")),
                    }
                )
        if len({row["address"] for row in matched_rows}) >= minimum_registers:
            matches.append(
                {
                    "cluster_id": key,
                    "matched_registers": matched_rows,
                    "matched_register_count": len(
                        {row["address"] for row in matched_rows}
                    ),
                }
            )
    return matches


def _consensus_profile(profiles: list[dict[str, Any]]) -> dict[str, Any]:
    """Keep only register roles on which every candidate profile agrees."""

    if len(profiles) == 1:
        return {
            key: value
            for key, value in profiles[0].items()
            if not str(key).startswith("_")
        }

    rows_by_profile: list[dict[int, dict[str, Any]]] = []
    for profile in profiles:
        indexed: dict[int, dict[str, Any]] = {}
        for row in _register_rows(profile):
            address = _register_address(row)
            if address is not None:
                indexed[address] = row
        rows_by_profile.append(indexed)

    common_addresses = set(rows_by_profile[0])
    for indexed in rows_by_profile[1:]:
        common_addresses.intersection_update(indexed)

    registers: list[dict[str, Any]] = []
    for address in sorted(common_addresses):
        rows = [indexed[address] for indexed in rows_by_profile]
        roles = {str(row.get("role", "")).upper() for row in rows}
        if len(roles) != 1:
            continue
        primary = dict(rows[0])
        primary["address"] = _hex(address)
        primary["evidence_source"] = "register_first_profile_consensus"
        primary["evidence_reference"] = ",".join(
            sorted(_profile_id(profile) for profile in profiles)
        )
        registers.append(primary)

    return {
        "schema_version": "ct-mini-hardware-profile-consensus-v1",
        "scope": "platform",
        "metadata_source": "trusted_platform_summary",
        "platform_id": "register-first-consensus",
        "registers": registers,
    }


def select_hardware_profile(
    profiles: Iterable[Mapping[str, Any]],
    *,
    elf_symbols: Mapping[str, list[int]],
    observed_accesses: Iterable[Mapping[str, Any]],
    minimum_registers: int = 2,
) -> dict[str, Any]:
    """Select a validated profile or consensus profile without target hints."""

    normalized_profiles = [dict(profile) for profile in profiles]
    accesses = [dict(row) for row in observed_accesses]
    identity_results = {
        _profile_id(profile): match_identity(profile, elf_symbols)
        for profile in normalized_profiles
    }
    cluster_results = {
        _profile_id(profile): match_register_clusters(
            profile, accesses, minimum_registers=minimum_registers
        )
        for profile in normalized_profiles
    }

    identity_matches = [
        profile
        for profile in normalized_profiles
        if identity_results[_profile_id(profile)]["status"] == "matched"
    ]
    if identity_matches:
        candidates = identity_matches
        mode = (
            "elf_identity_plus_register_cluster"
            if all(cluster_results[_profile_id(profile)] for profile in candidates)
            else "elf_identity"
        )
    else:
        candidates = [
            profile
            for profile in normalized_profiles
            if cluster_results[_profile_id(profile)]
        ]
        mode = "register_cluster_only"

    if not candidates:
        return {
            "status": "unresolved",
            "mode": "unresolved",
            "reason": "no_elf_identity_or_register_cluster_match",
            "selected_profile_ids": [],
            "identity_results": identity_results,
            "cluster_results": cluster_results,
            "profile": {},
        }

    selected_ids = sorted(_profile_id(profile) for profile in candidates)
    profile = _consensus_profile(candidates)
    if not list(profile.get("registers", []) or []):
        return {
            "status": "unresolved",
            "mode": mode,
            "reason": "candidate_profiles_have_no_consensus_register_roles",
            "selected_profile_ids": selected_ids,
            "identity_results": identity_results,
            "cluster_results": cluster_results,
            "profile": {},
        }
    return {
        "status": "resolved",
        "mode": mode,
        "reason": "",
        "selected_profile_ids": selected_ids,
        "identity_results": identity_results,
        "cluster_results": cluster_results,
        "profile": profile,
    }
