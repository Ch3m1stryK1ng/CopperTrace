#!/usr/bin/env python3
"""Mechanically reject evaluation leakage from generalized analysis modules."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Iterable


CVE_RE = re.compile(r"\bCVE[-_]\d{4}[-_]\d{4,7}\b", re.IGNORECASE)
PUBLIC_PROFILE_MARKERS = (
    "public_expected_sources",
    "public_expected_sinks",
    "public_chain_matches",
)
STANDARD_BOUNDARIES = {
    "memcpy",
    "memmove",
    "memset",
    "strcpy",
    "strncpy",
    "sprintf",
    "snprintf",
    "recv",
    "recvfrom",
    "read",
}


def _json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _walk(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def evaluation_tokens(
    manifest: Path,
    source_profiles: Path,
    sink_profile_dir: Path,
) -> tuple[set[str], set[str]]:
    sample_ids = {
        str(row.get("sample_id", ""))
        for row in list(_json(manifest).get("samples", []) or [])
        if str(row.get("sample_id", ""))
    }
    function_names: set[str] = set()
    profile_paths = [source_profiles, *sorted(sink_profile_dir.glob("*.json"))]
    for profile_path in profile_paths:
        for row in _walk(_json(profile_path)):
            for key in ("function", "function_name"):
                name = str(row.get(key, ""))
                if (
                    len(name) >= 8
                    and name not in STANDARD_BOUNDARIES
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name)
                ):
                    function_names.add(name)
    return sample_ids, function_names


def audit_file(
    path: Path,
    *,
    sample_ids: set[str],
    vulnerable_functions: set[str],
) -> list[dict[str, Any]]:
    text = path.read_text()
    findings: list[dict[str, Any]] = []
    for match in CVE_RE.finditer(text):
        findings.append({"kind": "CVE_IDENTIFIER", "token": match.group(0)})
    for marker in PUBLIC_PROFILE_MARKERS:
        if marker in text:
            findings.append({"kind": "PUBLIC_PROFILE_READ", "token": marker})
    for sample_id in sorted(sample_ids):
        if sample_id and sample_id in text:
            findings.append({"kind": "SAMPLE_ID", "token": sample_id})
    for name in sorted(vulnerable_functions):
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text):
            findings.append({"kind": "VULNERABLE_FUNCTION_NAME", "token": name})
    return [{"path": str(path), **row} for row in findings]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--source-profiles", required=True, type=Path)
    parser.add_argument("--sink-profile-dir", required=True, type=Path)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    sample_ids, function_names = evaluation_tokens(
        args.manifest,
        args.source_profiles,
        args.sink_profile_dir,
    )
    findings = [
        row
        for path in args.paths
        for row in audit_file(
            path,
            sample_ids=sample_ids,
            vulnerable_functions=function_names,
        )
    ]
    result = {
        "files": len(args.paths),
        "sample_tokens": len(sample_ids),
        "vulnerable_function_tokens": len(function_names),
        "findings": findings,
        "passed": not findings,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
