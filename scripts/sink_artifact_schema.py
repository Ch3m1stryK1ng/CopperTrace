#!/usr/bin/env python3
"""Sink Miner v2 registry and artifact compatibility helpers.

The v2 registry keeps Sink semantics separate from recognition method.  This
module also accepts the legacy deterministic v1 registry so callers can migrate
without maintaining two analysis engines.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


SINK_ARTIFACT_SCHEMA_VERSION = "ct-mini-sinks-v2"
SINK_REGISTRY_SCHEMA_VERSION = "ct-mini-sink-patterns-v2"

RECOGNITION_DETERMINISTIC = "deterministic"
RECOGNITION_HEURISTIC = "heuristic"

_ROLE_DEFAULT_TRACKING = {
    "dst": "memory_object",
    "src": "memory_content",
    "len": "scalar",
    "value": "scalar",
    "fmt": "memory_content",
    "amount": "scalar",
    "buffer": "memory_object",
    "offset": "scalar",
    "index": "scalar",
    "cursor": "scalar",
    "width": "scalar",
    "available_length": "scalar",
}


def _enabled_entries(entries: Any) -> list[dict[str, Any]]:
    if isinstance(entries, dict):
        rows = []
        for name, value in entries.items():
            row = dict(value or {})
            row.setdefault("name", str(name))
            rows.append(row)
        entries = rows
    return [
        dict(entry)
        for entry in list(entries or [])
        if isinstance(entry, dict) and entry.get("enabled", True) is not False
    ]


def _entries_by_name(entries: Any) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for entry in _enabled_entries(entries):
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        out[name] = {
            key: value
            for key, value in entry.items()
            if key not in {"name", "enabled"}
        }
    return out


def semantic_roles(spec: dict[str, Any]) -> tuple[str, ...]:
    """Return every argument/effect role declared by one primitive summary."""

    roles: list[str] = []
    declared = list(spec.get("semantic_roles", []) or [])
    for role in declared:
        role = str(role)
        if role and role not in roles:
            roles.append(role)
    for role in ("dst", "src", "len", "value", "fmt"):
        if isinstance(spec.get(f"{role}_arg"), int) and role not in roles:
            roles.append(role)
    if str(spec.get("value_expr", "")).strip() and "value" not in roles:
        roles.append("value")
    return tuple(roles)


def role_tracking(spec: dict[str, Any], role: str) -> str:
    declared = dict(spec.get("role_tracking", {}) or {})
    return str(declared.get(role, _ROLE_DEFAULT_TRACKING.get(role, "scalar")))


def _normalize_primitive(spec: dict[str, Any]) -> dict[str, Any]:
    row = dict(spec)
    roles = semantic_roles(row)
    row["semantic_roles"] = list(roles)
    row["vulnerable_parameter_roles"] = [
        str(role) for role in list(row.get("vulnerable_parameter_roles", []) or [])
    ]
    unknown = set(row["vulnerable_parameter_roles"]) - set(roles)
    if unknown:
        raise ValueError(
            "vulnerable roles are not semantic roles: "
            + ", ".join(sorted(unknown))
        )
    tracking = dict(row.get("role_tracking", {}) or {})
    row["role_tracking"] = {
        role: str(tracking.get(role, _ROLE_DEFAULT_TRACKING.get(role, "scalar")))
        for role in roles
    }
    # Kept only for consumers of the v1 schema.  Sink Miner v2 performs
    # parameter-level pruning and does not use one admission role to withdraw
    # an otherwise useful callsite.
    row["admission_roles"] = [
        str(role) for role in list(
            row.get("admission_roles", row["vulnerable_parameter_roles"]) or []
        )
    ]
    row["recognition"] = RECOGNITION_DETERMINISTIC
    return row


def normalize_sink_registry(
    raw: dict[str, Any], *, path: str | Path = ""
) -> dict[str, Any]:
    """Normalize either the v1 or v2 JSON registry to one engine contract."""

    primitive = {
        name: _normalize_primitive(spec)
        for name, spec in _entries_by_name(raw.get("primitive_sinks", [])).items()
    }
    if not primitive:
        raise ValueError(f"registry has no enabled primitive_sinks: {path}")

    heuristic_rules = _enabled_entries(raw.get("heuristic_sink_rules", []))
    # v1 called these structural rules and treated one of them as
    # deterministic.  v2 preserves the rule definition but explicitly
    # reclassifies it; the deterministic engine never consumes this list.
    heuristic_rules.extend(_enabled_entries(raw.get("structural_sink_rules", [])))
    normalized_heuristics: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for rule in heuristic_rules:
        rule_id = str(rule.get("id", "")).strip()
        if not rule_id or rule_id in seen_ids:
            continue
        seen_ids.add(rule_id)
        item = dict(rule)
        item["recognition"] = RECOGNITION_HEURISTIC
        normalized_heuristics.append(item)

    return {
        "schema_version": str(raw.get("schema_version", "")),
        "normalized_schema_version": SINK_REGISTRY_SCHEMA_VERSION,
        "name": str(raw.get("name", "")),
        "path": str(path),
        "policy": dict(raw.get("policy", {}) or {}),
        "sink_labels": _enabled_entries(raw.get("sink_labels", [])),
        "primitive_sinks": primitive,
        "framework_sinks": _entries_by_name(raw.get("framework_sinks", [])),
        "pattern_sinks": _enabled_entries(raw.get("pattern_sinks", [])),
        "heuristic_sink_rules": normalized_heuristics,
        # Legacy key retained for loaders/reporters.  Its entries are
        # heuristic definitions and must not enter deterministic results.
        "structural_sink_rules": normalized_heuristics,
        "dispatch_patterns": _enabled_entries(raw.get("dispatch_patterns", [])),
    }


def load_sink_registry(path: str | Path) -> dict[str, Any]:
    registry_path = Path(path)
    raw = json.loads(registry_path.read_text())
    return normalize_sink_registry(raw, path=registry_path)


def deterministic_compatibility_fields() -> dict[str, Any]:
    """Fields retained while existing Mini consumers migrate to v2."""

    return {
        "recognition": RECOGNITION_DETERMINISTIC,
        "decision": "ACCEPT_DETERMINISTIC",
    }


def dedupe_rows(
    rows: Iterable[dict[str, Any]], *keys: str
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, ...]] = set()
    for row in rows:
        key = tuple(str(row.get(name, "")) for name in keys)
        if key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out
