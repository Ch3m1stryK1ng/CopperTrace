#!/usr/bin/env python3
"""Select a hash-disjoint ARM ELF corpus without consulting analysis output."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FROZEN_A2_FILES = (
    ROOT / "scripts/filter_static_alerts_v2.py",
    ROOT / "scripts/check_binding.py",
    ROOT / "scripts/run_coppertrace_filter_corpus.py",
    ROOT / "scripts/filter_static_alerts.py",
    ROOT / "scripts/run_mango_filter_corpus.py",
)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def development_hashes(summary: dict[str, Any]) -> set[str]:
    hashes: set[str] = set()
    for row in list(summary.get("samples", []) or []):
        value = str(dict(row.get("provenance", {}) or {}).get("binary_sha256", ""))
        if re.fullmatch(r"[0-9a-f]{64}", value):
            hashes.add(value)
    return hashes


def parse_elf32_arm(path: Path) -> tuple[dict[str, Any] | None, str]:
    """Validate the ELF properties needed by the frozen Ghidra frontend."""

    try:
        data = path.read_bytes()
    except OSError as exc:
        return None, f"read_error:{exc.__class__.__name__}"
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return None, "not_elf"
    if data[4] != 1:
        return None, "not_elf32"
    if data[5] != 1:
        return None, "not_little_endian"

    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if e_type != 2:
        return None, f"not_et_exec:{e_type}"
    if e_machine != 40:
        return None, f"not_arm:{e_machine}"

    e_entry = struct.unpack_from("<I", data, 24)[0]
    e_phoff = struct.unpack_from("<I", data, 28)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
    if e_entry == 0:
        return None, "zero_entry"
    if e_phentsize < 32 or e_phoff + e_phentsize * e_phnum > len(data):
        return None, "invalid_program_headers"

    has_interp = False
    executable_loads = 0
    load_segments = 0
    for index in range(e_phnum):
        offset = e_phoff + index * e_phentsize
        p_type = struct.unpack_from("<I", data, offset)[0]
        p_flags = struct.unpack_from("<I", data, offset + 24)[0]
        if p_type == 3:
            has_interp = True
        if p_type == 1:
            load_segments += 1
            if p_flags & 1:
                executable_loads += 1
    if has_interp:
        return None, "has_pt_interp"
    if executable_loads == 0:
        return None, "no_executable_load"

    return {
        "elf_class": "ELF32",
        "endianness": "little",
        "elf_type": "ET_EXEC",
        "machine": "ARM",
        "entry": f"0x{e_entry:08x}",
        "load_segments": load_segments,
        "executable_load_segments": executable_loads,
        "file_size": len(data),
    }, "eligible"


def variant_key(path: Path) -> str:
    """Group stripped/unstripped siblings without inspecting program semantics."""

    value = str(path.resolve())
    value = re.sub(r"_stripped(?=\.elf$)", "", value, flags=re.IGNORECASE)
    if "/build/" in value and "/p2im-real_firmware/" in value:
        prefix, suffix = value.split("/p2im-real_firmware/", 1)
        product = suffix.split("/", 1)[0]
        value = f"{prefix}/p2im-real_firmware/{product}"
    return value


def candidate_preference(row: dict[str, Any]) -> tuple[int, int, str]:
    path = str(row["binary_path"])
    return (
        int("stripped" in Path(path).name.lower()),
        int("/build/" in path),
        path,
    )


def discover(
    candidate_roots: list[Path],
    dev_hashes: set[str],
    exclude_path_regexes: list[str] | None = None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    excluded = [re.compile(pattern) for pattern in (exclude_path_regexes or [])]
    for candidate_root in candidate_roots:
        if not candidate_root.exists():
            continue
        for path in sorted(candidate_root.rglob("*")):
            if not path.is_file() or path in seen_paths:
                continue
            seen_paths.add(path)
            resolved = str(path.resolve())
            if any(pattern.search(resolved) for pattern in excluded):
                rows.append(
                    {
                        "binary_path": resolved,
                        "candidate_root": str(candidate_root.resolve()),
                        "eligibility": "excluded_path_policy",
                    }
                )
                continue
            elf, reason = parse_elf32_arm(path)
            row: dict[str, Any] = {
                "binary_path": resolved,
                "candidate_root": str(candidate_root.resolve()),
                "eligibility": reason,
            }
            if elf is None:
                rows.append(row)
                continue
            binary_hash = sha256_path(path)
            row.update(elf)
            row["binary_sha256"] = binary_hash
            row["variant_key"] = variant_key(path)
            if binary_hash in dev_hashes:
                row["eligibility"] = "excluded_development_hash"
            rows.append(row)
    return rows


def select(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    eligible = [row for row in rows if row.get("eligibility") == "eligible"]

    by_hash: dict[str, dict[str, Any]] = {}
    for row in eligible:
        binary_hash = str(row["binary_sha256"])
        current = by_hash.get(binary_hash)
        if current is None or candidate_preference(row) < candidate_preference(current):
            by_hash[binary_hash] = row

    by_variant: dict[str, dict[str, Any]] = {}
    for row in by_hash.values():
        key = str(row["variant_key"])
        current = by_variant.get(key)
        if current is None or candidate_preference(row) < candidate_preference(current):
            by_variant[key] = row

    selected = sorted(by_variant.values(), key=lambda row: str(row["binary_sha256"]))[:limit]
    return [
        {
            "sample_id": f"independent_{str(row['binary_sha256'])[:16]}",
            "binary_path": row["binary_path"],
            "binary_sha256": row["binary_sha256"],
            "elf": {
                key: row[key]
                for key in (
                    "elf_class",
                    "endianness",
                    "elf_type",
                    "machine",
                    "entry",
                    "load_segments",
                    "executable_load_segments",
                    "file_size",
                )
            },
            "selection_basis": "sha256_order_after_elf_hash_and_variant_dedup",
        }
        for row in selected
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", action="append", required=True, type=Path)
    parser.add_argument(
        "--exclude-path-regex",
        action="append",
        default=[],
        help="Predeclared corpus exclusion applied before ELF/content analysis.",
    )
    parser.add_argument("--development-summary", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--inventory-out", required=True, type=Path)
    args = parser.parse_args()

    dev_summary = read_json(args.development_summary)
    dev_hashes = development_hashes(dev_summary)
    inventory = discover(args.candidate_root, dev_hashes, args.exclude_path_regex)
    selected = select(inventory, args.limit)
    if len(selected) < args.limit:
        raise SystemExit(
            f"only {len(selected)} eligible hash/variant-disjoint ELFs for limit {args.limit}"
        )

    frozen_files = {
        str(path.relative_to(ROOT)): sha256_path(path)
        for path in FROZEN_A2_FILES
    }
    manifest = {
        "schema_version": "ct-mini-independent-elf-selection-v1",
        "description": (
            "Independent ARM ELF corpus selected before analysis output is generated; "
            "selection uses ELF structure, development-set hash exclusion, exact hash "
            "deduplication, stripped/unstripped sibling deduplication, and SHA-256 order."
        ),
        "selection_policy": {
            "target": "ELF32 little-endian ARM ET_EXEC without PT_INTERP",
            "candidate_roots": [str(path.resolve()) for path in args.candidate_root],
            "exclude_path_regexes": list(args.exclude_path_regex),
            "development_summary": str(args.development_summary.resolve()),
            "development_summary_sha256": sha256_path(args.development_summary),
            "development_hashes_excluded": len(dev_hashes),
            "analysis_output_consulted": False,
            "stable_order": "binary_sha256 ascending",
            "limit": args.limit,
        },
        "frozen_filter_files": frozen_files,
        "samples": selected,
    }
    write_json(args.out, manifest)
    write_json(
        args.inventory_out,
        {
            "schema_version": "ct-mini-independent-elf-inventory-v1",
            "counts": {
                "files_examined": len(inventory),
                "elf_eligible_before_dedup": sum(
                    row.get("eligibility") == "eligible" for row in inventory
                ),
                "development_hash_exclusions": sum(
                    row.get("eligibility") == "excluded_development_hash"
                    for row in inventory
                ),
                "selected": len(selected),
            },
            "rows": inventory,
        },
    )
    print(json.dumps({"selected": len(selected), "manifest": str(args.out)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
