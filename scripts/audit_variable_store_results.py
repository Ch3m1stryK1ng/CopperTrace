#!/usr/bin/env python3
"""Summarize audit-only variable-address STORE findings by implementation."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from body_sink_heuristics import normalized_function_body_hash  # noqa: E402


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--corpus",
        action="append",
        required=True,
        help="NAME=ROOT where ROOT contains per_sample/<id>/public_match.json",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    corpus_roots: list[tuple[str, Path]] = []
    for raw in args.corpus:
        name, separator, value = str(raw).partition("=")
        if not separator or not name or not value:
            parser.error("--corpus must use NAME=ROOT")
        corpus_roots.append((name, Path(value)))

    seen_samples: set[str] = set()
    findings: list[dict[str, Any]] = []
    corpus_counts: Counter[str] = Counter()
    for corpus, root in corpus_roots:
        for public_path in sorted((root / "per_sample").glob("*/public_match.json")):
            public = read_json(public_path)
            sample_id = str(public.get("sample_id", ""))
            if not sample_id or sample_id in seen_samples:
                continue
            seen_samples.add(sample_id)
            sinks_path = public_path.with_name("sinks.json")
            facts_path = Path(str(public.get("program_facts", "")))
            if not sinks_path.exists() or not facts_path.exists():
                continue
            sinks = read_json(sinks_path)
            facts = read_json(facts_path)
            functions = {
                str(row.get("function_id", "")): dict(row)
                for row in list(facts.get("functions", []) or [])
            }
            binary_hash = str(public.get("provenance", {}).get("binary_sha256", ""))
            for raw_finding in list(sinks.get("heuristic_audit_candidates", []) or []):
                finding = dict(raw_finding)
                if str(finding.get("recognition_method", "")) != "variable_address_store":
                    continue
                function_id = str(finding.get("function_id", ""))
                function = functions.get(function_id, {})
                row = {
                    "corpus": corpus,
                    "sample_id": sample_id,
                    "binary_sha256": binary_hash,
                    "function": str(finding.get("function", "")),
                    "function_id": function_id,
                    "site_id": str(finding.get("site_id", "")),
                    "instruction_address": str(finding.get("instruction_address", "")),
                    "implementation_body_hash": normalized_function_body_hash(function),
                    "vulnerable_parameter_roles": list(
                        finding.get("vulnerable_parameter_roles", []) or []
                    ),
                    "vulnerable_parameters": list(
                        finding.get("vulnerable_parameters", []) or []
                    ),
                    "roles": dict(finding.get("roles", {}) or {}),
                    "proof": dict(finding.get("proof", {}) or {}),
                    "public_match_path": str(public_path),
                }
                findings.append(row)
                corpus_counts[corpus] += 1

    implementation_keys = {
        (row["binary_sha256"], row["function_id"]) for row in findings
    }
    family_counts = Counter(row["implementation_body_hash"] for row in findings)
    representative_by_family: dict[str, dict[str, Any]] = {}
    for row in findings:
        representative_by_family.setdefault(row["implementation_body_hash"], row)
    result = {
        "schema_version": "ct-mini-variable-store-audit-v1",
        "recognition_method": "variable_address_store",
        "eligible_for_bfs_rda": False,
        "corpus_callsites": dict(sorted(corpus_counts.items())),
        "audit_callsites": len(findings),
        "unique_binary_function_implementations": len(implementation_keys),
        "implementation_families": len(family_counts),
        "family_callsite_counts": dict(family_counts.most_common()),
        "family_representatives": list(representative_by_family.values()),
        "findings": findings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: result[key] for key in (
        "corpus_callsites",
        "audit_callsites",
        "unique_binary_function_implementations",
        "implementation_families",
    )}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
