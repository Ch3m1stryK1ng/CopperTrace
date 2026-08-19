#!/usr/bin/env python3
"""Shared helpers for CopperTrace Mini execution validation."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable


SUPPORTED_SINK_LABELS = frozenset(
    {
        "COPY_SINK",
        "MEMSET_SINK",
        "STORE_SINK",
        "LOOP_WRITE_SINK",
        "BUFFER_STATE_SINK",
    }
)
SOURCE_REACHED_STATUSES = frozenset(
    {"SOURCE_REACHED_DETERMINISTIC", "SOURCE_REACHED_HEURISTIC"}
)


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def reviewed_validation_entries(
    reviewed: dict[str, Any],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Resolve post-review queue entries to their unchanged TruPoC Alerts."""

    trupocs: dict[str, dict[str, Any]] = {}
    for row in list(reviewed.get("trupocs", []) or []):
        alert = dict(row.get("alert", {}) or {})
        alert_id = str(alert.get("alert_id", "") or "")
        if not alert_id:
            raise ValueError("reviewed TruPoC is missing alert.alert_id")
        if alert_id in trupocs:
            raise ValueError(f"duplicate reviewed TruPoC alert_id: {alert_id}")
        trupocs[alert_id] = alert

    result: list[tuple[dict[str, Any], dict[str, Any]]] = []
    seen: set[str] = set()
    for queue_row in list(reviewed.get("validation_queue", []) or []):
        alert_id = str(queue_row.get("alert_id", "") or "")
        if not alert_id or alert_id in seen:
            raise ValueError(f"invalid validation queue alert_id: {alert_id!r}")
        alert = trupocs.get(alert_id)
        if alert is None:
            raise ValueError(
                f"validation queue references non-TruPoC alert: {alert_id}"
            )
        seen.add(alert_id)
        result.append((deepcopy(queue_row), deepcopy(alert)))
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_address(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    text = str(value or "").strip().lower()
    if not text:
        return None
    try:
        return int(text, 16 if text.startswith("0x") else 10)
    except ValueError:
        return None


def canonical_address(value: Any) -> str:
    address = parse_address(value)
    return f"0x{address:x}" if address is not None else ""


def find_by_id(rows: Iterable[dict[str, Any]], row_id: str) -> dict[str, Any] | None:
    for row in rows:
        if str(row.get("id", "")) == row_id:
            return row
    return None


def reached_source_ids(chain: dict[str, Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for parameter in chain.get("parameter_results", []) or []:
        if str(parameter.get("status", "")) not in SOURCE_REACHED_STATUSES:
            continue
        for path in parameter.get("paths", []) or []:
            source_id = str(path.get("source_id", ""))
            if source_id and source_id not in seen:
                seen.add(source_id)
                result.append(source_id)
    return result


def source_backed_callsite_ids(chain: dict[str, Any]) -> list[str]:
    """Return exact CALL sites occurring on Source-backed parameter paths."""
    per_parameter: list[set[str]] = []
    union: set[str] = set()
    for parameter in chain.get("parameter_results", []) or []:
        if str(parameter.get("status", "")) not in SOURCE_REACHED_STATUSES:
            continue
        sites: set[str] = set()
        for path in parameter.get("paths", []) or []:
            for edge in path.get("path", []) or []:
                if str(edge.get("kind", "")) != "ACTUAL_FORMAL":
                    continue
                site_id = str(edge.get("site_id", ""))
                if site_id.startswith("site:"):
                    sites.add(site_id)
                    union.add(site_id)
        if sites:
            per_parameter.append(sites)
    if per_parameter:
        common = set.intersection(*per_parameter)
        if common:
            return sorted(common)
    return sorted(union)


def trace_contains_address(trace: str, addresses: Iterable[int]) -> bool:
    normalized = {address & ~1 for address in addresses}
    if not normalized:
        return False
    for token in re.findall(r"(?i)(?:0x)?[0-9a-f]{6,16}", trace):
        try:
            observed = int(token, 16) & ~1
        except ValueError:
            continue
        if observed in normalized:
            return True
    return False
