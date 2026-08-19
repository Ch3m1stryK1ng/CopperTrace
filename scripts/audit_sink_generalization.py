#!/usr/bin/env python3
"""Fail when the strict Sink Miner contains sample/CVE-specific shortcuts."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "registries/sink_patterns.v2.json"
DEFAULT_MANIFEST = ROOT / "datasets/source_mining_direct_taint_no_microbench.json"
CORE_FILES = (
    ROOT / "scripts/deterministic_sink_engine.py",
    ROOT / "scripts/body_sink_heuristics.py",
    ROOT / "scripts/high_pcode_loop_analysis.py",
    ROOT / "scripts/build_sink_artifacts.py",
)
GENERIC_PROFILE_NAMES = {"input", "output", "read", "write", "main", "process"}
ALLOWED_STANDARD_SEEDS = {
    "memcpy", "memmove", "bcopy", "memset", "bzero",
    "strcpy", "strcat", "strncpy", "strlcpy", "strncat",
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8",
    "__aeabi_memmove", "__aeabi_memmove4", "__aeabi_memmove8",
    "__aeabi_memset", "__aeabi_memclr", "__rt_memcpy", "__rt_memmove",
    "__memcpy_r4", "__memcpy_r7",
}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(errors="replace"))


def public_profile_tokens(manifest_path: Path) -> tuple[set[str], set[str]]:
    manifest = read_json(manifest_path)
    exact_functions: set[str] = set()
    cve_tokens: set[str] = set()
    for sample in list(manifest.get("samples", []) or []):
        cve = str(sample.get("cve", "")).strip()
        if cve:
            cve_tokens.add(cve)
            cve_tokens.add(cve.replace("-", "_"))
        profile_path = Path(str(sample.get("expected_profile_path", "")))
        if not profile_path.exists():
            continue
        for sink in list(read_json(profile_path).get("sinks", []) or []):
            for key in ("function_name", "callee"):
                name = str(sink.get(key, "")).strip()
                if name and name.lower() not in GENERIC_PROFILE_NAMES:
                    exact_functions.add(name)
    return exact_functions, cve_tokens


def audit(registry_path: Path, manifest_path: Path) -> list[str]:
    registry = read_json(registry_path)
    rows = [row for row in list(registry.get("primitive_sinks", []) or []) if row.get("enabled", True)]
    seed_names = {str(row.get("name", "")) for row in rows if str(row.get("name", ""))}
    public_names, cve_tokens = public_profile_tokens(manifest_path)
    failures: list[str] = []

    if list(registry.get("framework_sinks", []) or []):
        failures.append("strict registry must not contain framework_sinks")
    if list(registry.get("pattern_sinks", []) or []):
        failures.append("strict registry must not contain pattern_sinks")
    if list(registry.get("dispatch_patterns", []) or []):
        failures.append("strict registry must not contain dispatch_patterns")

    forbidden_seeds = sorted(seed_names - ALLOWED_STANDARD_SEEDS)
    if forbidden_seeds:
        failures.append(
            "non-standard/project functions appear as primitive seeds: "
            + ", ".join(forbidden_seeds)
        )

    core_text = "\n".join(path.read_text(errors="replace") for path in CORE_FILES)
    distinctive_names = {
        name for name in public_names
        if len(name) >= 8 and name not in seed_names
    }
    leaked_names = sorted(
        name for name in distinctive_names
        if re.search(rf"\b{re.escape(name)}\b", core_text)
    )
    if leaked_names:
        failures.append(
            "public-profile custom names appear in strict implementation: "
            + ", ".join(leaked_names)
        )
    leaked_cves = sorted(token for token in cve_tokens if token and token in core_text)
    if leaked_cves:
        failures.append("CVE identifiers appear in strict implementation: " + ", ".join(leaked_cves))
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    failures = audit(args.registry, args.manifest)
    report = {
        "registry": str(args.registry),
        "manifest": str(args.manifest),
        "status": "FAIL" if failures else "PASS",
        "failures": failures,
    }
    print(json.dumps(report, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
