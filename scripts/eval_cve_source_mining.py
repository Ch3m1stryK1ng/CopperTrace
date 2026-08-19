#!/usr/bin/env python3
"""Evaluate CopperTrace Mini source mining against public CVE source profiles.

This evaluates Source Miner only.  It does not evaluate sink reachability,
guard correctness, path feasibility, exploitability, or runtime validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import build_source_artifacts as source_builder


MINI_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = MINI_ROOT / "datasets/sink_mining_main.json"
DEFAULT_EXPECTED_SOURCES = MINI_ROOT / "datasets/public_expected_sources/source_profiles.json"
DEFAULT_OUTPUT = MINI_ROOT / "artifacts/eval_source_mining_public20"
BUILD_SCRIPT = MINI_ROOT / "scripts/build_source_artifacts.py"
ADJUDICATE_SCRIPT = MINI_ROOT / "scripts/adjudicate_source_llm.py"
GHIDRA_EXPORT_RUNNER = MINI_ROOT / "scripts/run_ghidra_high_pcode_export.sh"
GHIDRA_EXPORT_SCRIPT = MINI_ROOT / "scripts/ghidra_export_source_facts.py"
SOURCE_REGISTRY = MINI_ROOT / "registries/source_patterns.v0.json"
GHIDRA_FACT_SCHEMA = "ct-mini-ghidra-high-pcode-v5-static-objects"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(errors="replace"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evaluation_tool_hashes() -> dict[str, str]:
    paths = [
        BUILD_SCRIPT,
        ADJUDICATE_SCRIPT,
        MINI_ROOT / "scripts/resolve_source_llm.py",
        GHIDRA_EXPORT_SCRIPT,
        GHIDRA_EXPORT_RUNNER,
        SOURCE_REGISTRY,
        Path(__file__).resolve(),
    ]
    return {str(path.relative_to(MINI_ROOT)): sha256_path(path) for path in paths}


def ghidra_tool_fingerprint() -> str:
    ghidra_root = Path(
        os.environ.get("GHIDRA_INSTALL_DIR", "")
    )
    version_file = ghidra_root / "Ghidra/application.properties"
    values = [sha256_path(GHIDRA_EXPORT_SCRIPT), sha256_path(GHIDRA_EXPORT_RUNNER)]
    if version_file.exists():
        values.append(sha256_path(version_file))
    return hashlib.sha256("\n".join(values).encode()).hexdigest()


def prepare_program_facts(
    *,
    sample: dict[str, Any],
    decompiled: Path,
    cache_dir: Path,
    out_dir: Path,
) -> dict[str, Any]:
    """Export generalized source-relevant functions without expected-CVE input."""

    binary = Path(str(sample.get("binary_path", "")))
    if not binary.exists():
        return {"returncode": 2, "error": f"missing ELF: {binary}"}
    binary_hash = sha256_path(binary)
    prebuilt_path = optional_path(sample.get("program_facts_path"))
    if prebuilt_path and prebuilt_path.exists():
        prebuilt = read_json(prebuilt_path)
        if (
            str(prebuilt.get("binary_sha256", "")) == binary_hash
            and str(prebuilt.get("schema_version", "")) == GHIDRA_FACT_SCHEMA
        ):
            return {
                "returncode": 0,
                "program_facts": str(prebuilt_path),
                "selected_functions": int(
                    (prebuilt.get("counts", {}) or {}).get("selected_functions", 0)
                ),
                "cache_hit": True,
                "cache_kind": "manifest_full_program_facts",
            }
    registry = read_json(SOURCE_REGISTRY)
    lines = decompiled.read_text(errors="replace").splitlines(keepends=True)
    functions = source_builder.parse_functions(lines)
    selected = source_builder.select_source_fact_functions(functions, registry)
    selected = source_builder.expand_selected_source_callees(
        functions, selected, registry
    )
    selection_hash = hashlib.sha256("\n".join(selected).encode()).hexdigest()[:16]
    tool_fingerprint = ghidra_tool_fingerprint()
    facts_path = cache_dir / (
        f"{binary_hash[:20]}-{selection_hash}-{tool_fingerprint[:12]}.program_facts.json"
    )
    function_list = out_dir / "ghidra_source_fact_functions.txt"
    function_list.parent.mkdir(parents=True, exist_ok=True)
    function_list.write_text("\n".join(selected) + "\n")
    cache_dir.mkdir(parents=True, exist_ok=True)
    if facts_path.exists():
        try:
            cached = read_json(facts_path)
            if (
                str(cached.get("binary_sha256", "")) == binary_hash
                and str(cached.get("schema_version", "")) == GHIDRA_FACT_SCHEMA
            ):
                return {
                    "returncode": 0,
                    "program_facts": str(facts_path),
                    "selected_functions": len(selected),
                    "cache_hit": True,
                    "tool_fingerprint": tool_fingerprint,
                }
        except (OSError, json.JSONDecodeError):
            pass

    command = [
        str(GHIDRA_EXPORT_RUNNER),
        str(binary),
        str(facts_path),
        ",".join(selected),
    ]
    started = time.time()
    proc = subprocess.run(
        command,
        cwd=str(MINI_ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    elapsed = time.time() - started
    (out_dir / "run_ghidra_facts.log").write_text(
        "CMD: " + " ".join(command) + "\n\nSTDOUT:\n" + proc.stdout + "\nSTDERR:\n" + proc.stderr
    )
    return {
        "returncode": proc.returncode,
        "program_facts": str(facts_path),
        "selected_functions": len(selected),
        "cache_hit": False,
        "tool_fingerprint": tool_fingerprint,
        "runtime_seconds": elapsed,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def optional_path(raw: Any) -> Path | None:
    if raw is None:
        return None
    text = str(raw).strip()
    return Path(text) if text else None


def find_decompiled(sample: dict[str, Any]) -> Path | None:
    path = optional_path(sample.get("decompiled_c_path"))
    if path and path.exists():
        return path
    return None


def run_source_mini(
    sample: dict[str, Any],
    decompiled: Path,
    out_dir: Path,
    *,
    run_llm: bool,
    llm_limit: int,
    llm_request_timeout_sec: float,
    llm_batch_size: int,
    model: str | None,
    program_facts: Path | None,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    sources_json = out_dir / "sources.json"
    unconfirmed_json = out_dir / "source_unconfirmed.json"
    response = out_dir / "response_LLM.txt"
    source_dropped = out_dir / "source_dropped.json"
    adjudication_error = out_dir / "adjudication_error.json"
    build_log = out_dir / "run_build.log"
    llm_log = out_dir / "run_llm.log"
    build_cmd = [
        "python3",
        str(BUILD_SCRIPT),
        "--input",
        str(decompiled),
        "--sources-json",
        str(sources_json),
        "--source-unconfirmed-json",
        str(unconfirmed_json),
        "--elf",
        str(sample.get("binary_path", "")),
    ]
    if program_facts:
        build_cmd.extend(["--program-facts", str(program_facts)])
    hardware_metadata = optional_path(sample.get("hardware_metadata_path"))
    if hardware_metadata and not hardware_metadata.is_absolute():
        hardware_metadata = MINI_ROOT / hardware_metadata
    if hardware_metadata and hardware_metadata.exists():
        build_cmd.extend(["--hardware-metadata", str(hardware_metadata)])
    started = time.time()
    build_proc = subprocess.run(
        build_cmd,
        cwd=str(MINI_ROOT),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    build_elapsed = time.time() - started
    build_log.write_text(
        "CMD: " + " ".join(build_cmd) + "\n\nSTDOUT:\n" + build_proc.stdout + "\nSTDERR:\n" + build_proc.stderr
    )
    if build_proc.returncode != 0:
        return {
            "returncode": build_proc.returncode,
            "stage": "build",
            "runtime_seconds": build_elapsed,
            "sources_json": str(sources_json),
            "source_unconfirmed_json": str(unconfirmed_json),
            "response_LLM": "",
            "run_build_log": str(build_log),
            "run_llm_log": "",
            "stdout": build_proc.stdout,
            "stderr": build_proc.stderr,
        }

    llm_elapsed = 0.0
    llm_returncode = 0
    if run_llm:
        llm_cmd = [
            "python3",
            str(ADJUDICATE_SCRIPT),
            "--sources-json",
            str(sources_json),
            "--source-unconfirmed-json",
            str(unconfirmed_json),
            "--response",
            str(response),
            "--apply",
            "--source-dropped-json",
            str(source_dropped),
            "--adjudication-error-json",
            str(adjudication_error),
            "--batch-size",
            str(llm_batch_size),
        ]
        if llm_limit > 0:
            llm_cmd.extend(["--limit", str(llm_limit)])
        llm_cmd.extend(["--request-timeout-sec", str(llm_request_timeout_sec)])
        if model:
            llm_cmd.extend(["--model", model])
        llm_started = time.time()
        llm_proc = subprocess.run(
            llm_cmd,
            cwd=str(MINI_ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        llm_elapsed = time.time() - llm_started
        llm_returncode = llm_proc.returncode
        llm_log.write_text(
            "CMD: " + " ".join(llm_cmd) + "\n\nSTDOUT:\n" + llm_proc.stdout + "\nSTDERR:\n" + llm_proc.stderr
        )
        if llm_returncode != 0:
            return {
                "returncode": llm_returncode,
                "stage": "llm",
                "runtime_seconds": build_elapsed + llm_elapsed,
                "sources_json": str(sources_json),
                "source_unconfirmed_json": str(unconfirmed_json),
                "response_LLM": str(response),
                "source_dropped_json": str(source_dropped),
                "adjudication_error_json": str(adjudication_error),
                "run_build_log": str(build_log),
                "run_llm_log": str(llm_log),
                "stdout": llm_proc.stdout,
                "stderr": llm_proc.stderr,
            }

    return {
        "returncode": 0,
        "stage": "complete",
        "runtime_seconds": build_elapsed + llm_elapsed,
        "build_runtime_seconds": build_elapsed,
        "llm_runtime_seconds": llm_elapsed,
        "llm_returncode": llm_returncode,
        "sources_json": str(sources_json),
        "source_unconfirmed_json": str(unconfirmed_json),
        "response_LLM": str(response) if run_llm else "",
        "source_dropped_json": str(source_dropped) if run_llm else "",
        "adjudication_error_json": str(adjudication_error) if run_llm else "",
        "run_build_log": str(build_log),
        "run_llm_log": str(llm_log) if run_llm else "",
        "stdout": "",
        "stderr": "",
    }


def source_label_for_match(source: dict[str, Any]) -> str:
    return str(source.get("pipeline_label_hint") or source.get("label") or "")


def unique_expected_sources(profile: dict[str, Any]) -> list[dict[str, Any]]:
    by_id = {str(s.get("source_id", "")): s for s in list(profile.get("sources", []) or [])}
    chains = list(profile.get("chains", []) or [])
    if not chains:
        return list(by_id.values())
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for chain in chains:
        source_id = str(chain.get("source_id", ""))
        if not source_id or source_id in seen:
            continue
        source = dict(by_id.get(source_id, {"source_id": source_id}))
        source["chain_ids"] = [
            str(c.get("chain_id", ""))
            for c in chains
            if str(c.get("source_id", "")) == source_id and str(c.get("chain_id", ""))
        ]
        source["match_label"] = source_label_for_match(source)
        seen.add(source_id)
        out.append(source)
    return out


def row_matches_expected_site(expected: dict[str, Any], row: dict[str, Any]) -> bool:
    callee = str(expected.get("callee") or "").strip()
    if callee and str(row.get("callee") or "") != callee:
        return False

    source_buffer = str(expected.get("source_buffer") or "").strip()
    observed_source_buffer = str(row.get("source_buffer") or row.get("candidate_source_buffer") or "")
    if source_buffer and observed_source_buffer != source_buffer:
        if observed_source_buffer and (
            source_buffer in observed_source_buffer or observed_source_buffer in source_buffer
        ):
            pass
        else:
        # Keep site expressions as fallback because decompilers rename temps.
            expr = str(row.get("source_site") or "")
            if source_buffer not in expr:
                return False

    expr = str(row.get("source_site") or "")
    evidence = expr + json.dumps(row.get("proof", {}), sort_keys=True)
    all_terms = [str(v) for v in (expected.get("expr_contains_all") or []) if str(v)]
    if any(term not in evidence for term in all_terms):
        return False

    any_terms = [str(v) for v in (expected.get("expr_contains_any") or []) if str(v)]
    if any_terms and not any(term in evidence for term in any_terms):
        return False

    expr_regex = str(expected.get("expr_regex") or "").strip()
    if expr_regex:
        try:
            if re.search(expr_regex, expr) is None:
                return False
        except re.error:
            return False
    return True


def expected_has_site_filter(expected: dict[str, Any]) -> bool:
    return any(
        expected.get(key)
        for key in ("callee", "source_buffer", "expr_contains_all", "expr_contains_any", "expr_regex")
    )


def labels_compatible(expected: dict[str, Any], observed_label: str) -> bool:
    accepted = {
        str(label) for label in list(expected.get("accepted_labels", []) or []) if str(label)
    }
    expected_label = str(expected.get("match_label") or expected.get("label") or "")
    if expected_label:
        accepted.add(expected_label)
    if not accepted:
        return True
    return observed_label in accepted


def match_expected_source(
    expected: dict[str, Any],
    confirmed: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    expected_functions = {
        str(name)
        for name in (
            list(expected.get("function_names", []) or [])
            or [expected.get("function_name", "")]
        )
        if str(name)
    }
    has_site_filter = expected_has_site_filter(expected)

    same_function = [
        row
        for row in confirmed
        if not expected_functions or str(row.get("function", "")) in expected_functions
    ]
    site_scope = [row for row in same_function if row_matches_expected_site(expected, row)] if has_site_filter else same_function
    same_label = [
        row for row in site_scope
        if labels_compatible(expected, str(row.get("label", "")))
    ]
    if same_label:
        best = same_label[0]
        return {
            "status": "CONFIRMED_MATCH",
            "confirmed": True,
            "need_confirmation": False,
            "direct_confirmed": (
                str(best.get("decision", "")) == "ACCEPT_DETERMINISTIC"
                and str(best.get("confirmation_source", "")) != "llm_review"
            ),
            "llm_confirmed": str(best.get("confirmation_source", "")) == "llm_review",
            "matched_source": best,
            "notes": "function/site/label match in sources.json",
        }

    same_function_candidates = [
        row for row in candidates
        if (not expected_functions or str(row.get("function", "")) in expected_functions)
        and labels_compatible(expected, str(row.get("label_hint", "")))
    ]
    if has_site_filter:
        same_function_candidates = [
            row for row in same_function_candidates if row_matches_expected_site(expected, row)
        ]
    if same_function_candidates:
        return {
            "status": "NEED_CONFIRMATION",
            "confirmed": False,
            "need_confirmation": True,
            "direct_confirmed": False,
            "llm_confirmed": False,
            "matched_candidate": same_function_candidates[0],
            "notes": "expected source appears only in source_unconfirmed.json",
        }

    note = "no confirmed or need-confirmation MINI source in expected function/site"
    if same_function:
        note = "confirmed sources exist in expected function, but none match expected label/site"
    return {
        "status": "MISS",
        "confirmed": False,
        "need_confirmation": False,
        "direct_confirmed": False,
        "llm_confirmed": False,
        "notes": note,
    }


def evaluate_sources(
    expected_sources: list[dict[str, Any]],
    confirmed: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    rows = []
    for expected in expected_sources:
        rows.append({"expected_source": expected, "match": match_expected_source(expected, confirmed, candidates)})
    total = len(rows)
    confirmed_count = sum(1 for r in rows if r["match"].get("confirmed"))
    need_confirmation = sum(1 for r in rows if r["match"].get("need_confirmation"))
    direct = sum(1 for r in rows if r["match"].get("direct_confirmed"))
    llm = sum(1 for r in rows if r["match"].get("llm_confirmed"))
    miss = total - confirmed_count - need_confirmation
    return {
        "expected_source_count": total,
        "confirmed": confirmed_count,
        "direct_confirmed": direct,
        "llm_confirmed": llm,
        "need_confirmation": need_confirmation,
        "miss": miss,
        "confirmed_rate": confirmed_count / total if total else None,
        "candidate_inclusive_rate": (confirmed_count + need_confirmation) / total if total else None,
        "matches": rows,
    }


def pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value * 100:.1f}%"


def unresolved_candidates_after_resolution(sources: dict[str, Any], unconfirmed: dict[str, Any]) -> list[dict[str, Any]]:
    resolved = {
        str(row.get("source_candidate_id", ""))
        for row in list(sources.get("confirmed_sources", []) or [])
        if str(row.get("source_candidate_id", ""))
    }
    resolution = dict(sources.get("resolution", {}) or {})
    for key in ("confirmed_candidate_ids", "rejected_candidate_ids"):
        resolved.update(str(cid) for cid in list(resolution.get(key, []) or []) if str(cid))
    return [
        candidate for candidate in list(unconfirmed.get("candidates", []) or [])
        if str(candidate.get("id", "")) not in resolved
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST, type=Path)
    parser.add_argument("--expected-sources", default=DEFAULT_EXPECTED_SOURCES, type=Path)
    parser.add_argument("--out", default=DEFAULT_OUTPUT, type=Path)
    parser.add_argument("--run-llm", action="store_true")
    parser.add_argument("--llm-candidate-limit-per-sample", default=0, type=int)
    parser.add_argument("--llm-request-timeout-sec", default=30.0, type=float)
    parser.add_argument("--llm-batch-size", default=8, type=int)
    parser.add_argument("--model", default=None)
    parser.add_argument("--run-ghidra", action="store_true")
    parser.add_argument(
        "--reuse-existing-artifacts",
        action="store_true",
        help="Recompute public-profile matching from existing per-sample source artifacts without mining or LLM calls.",
    )
    parser.add_argument(
        "--facts-cache",
        default=MINI_ROOT / "artifacts/ghidra_source_facts_cache",
        type=Path,
    )
    args = parser.parse_args()
    initial_tool_hashes = evaluation_tool_hashes()

    manifest = read_json(args.manifest)
    samples = list(manifest.get("samples", []) or [])
    args.out.mkdir(parents=True, exist_ok=True)

    inventory = []
    expected_records = []
    per_sample_results = []

    for sample in samples:
        sample_id = str(sample.get("sample_id", ""))
        decompiled = find_decompiled(sample)

        sample_out = args.out / "per_sample" / sample_id
        entry = {
            "sample_id": sample_id,
            "cve": str(sample.get("cve") or sample_id),
            "provider": str(sample.get("provider") or ""),
            "binary_path": str(sample.get("binary_path", "")),
            "decompiled_c": str(decompiled) if decompiled else "",
            "expected_source_count": 0,
            "profile_status": "not_loaded_during_mining",
            "testable": bool(decompiled and Path(decompiled).exists()),
        }
        inventory.append(entry)
        if not entry["testable"]:
            result = {
                "sample_id": sample_id,
                "status": "UNTESTABLE",
                "inventory": entry,
                "reason": "missing decompiled C",
            }
            per_sample_results.append(result)
            continue

        existing_sources = sample_out / "sources.json"
        existing_unconfirmed = sample_out / "source_unconfirmed.json"
        if args.reuse_existing_artifacts and existing_sources.exists() and existing_unconfirmed.exists():
            run = {
                "returncode": 0,
                "stage": "reuse_existing_artifacts",
                "runtime_seconds": 0.0,
                "sources_json": str(existing_sources),
                "source_unconfirmed_json": str(existing_unconfirmed),
                "response_LLM": str(sample_out / "response_LLM.txt"),
                "source_dropped_json": str(sample_out / "source_dropped.json"),
                "adjudication_error_json": str(sample_out / "adjudication_error.json"),
            }
            facts_run = {"returncode": 0, "skipped": True, "reason": "reuse_existing_artifacts"}
        else:
            run = None

        program_facts: Path | None = None
        facts_run: dict[str, Any] = {"returncode": 0, "skipped": True}
        if run is None and args.run_ghidra:
            facts_run = prepare_program_facts(
                sample=sample,
                decompiled=Path(decompiled),
                cache_dir=args.facts_cache,
                out_dir=sample_out,
            )
            if facts_run["returncode"] != 0:
                result = {
                    "sample_id": sample_id,
                    "status": "GHIDRA_FACT_EXPORT_FAILED",
                    "inventory": entry,
                    "facts_run": {k: v for k, v in facts_run.items() if k not in {"stdout", "stderr"}},
                    "stderr": str(facts_run.get("stderr", ""))[-4000:],
                }
                per_sample_results.append(result)
                continue
            program_facts = Path(str(facts_run["program_facts"]))

        if run is None:
            run = run_source_mini(
                sample,
                Path(decompiled),
                sample_out,
                run_llm=args.run_llm,
                llm_limit=args.llm_candidate_limit_per_sample,
                llm_request_timeout_sec=args.llm_request_timeout_sec,
                llm_batch_size=args.llm_batch_size,
                model=args.model,
                program_facts=program_facts,
            )
        if run["returncode"] != 0:
            result = {
                "sample_id": sample_id,
                "status": "MINI_RUN_FAILED",
                "inventory": entry,
                "run": {k: v for k, v in run.items() if k not in {"stdout", "stderr"}},
                "stderr": str(run.get("stderr", ""))[-4000:],
            }
            per_sample_results.append(result)
            continue

        sources = read_json(Path(run["sources_json"]))
        unconfirmed = read_json(Path(run["source_unconfirmed_json"]))
        confirmed = list(sources.get("confirmed_sources", []) or [])
        candidates = unresolved_candidates_after_resolution(sources, unconfirmed)
        result = {
            "sample_id": sample_id,
            "status": "EVALUATED",
            "inventory": entry,
            "run": {k: v for k, v in run.items() if k not in {"stdout", "stderr"}},
            "facts_run": {k: v for k, v in facts_run.items() if k not in {"stdout", "stderr"}},
            "mini_counts": sources.get("counts", {}),
            "mini_resolution": sources.get("resolution", {}),
            "mini_next_stage_ready": sources.get("next_stage_ready"),
            "_confirmed_sources": confirmed,
            "_unresolved_candidates": candidates,
        }
        per_sample_results.append(result)

    # Public profiles are deliberately loaded only after every miner/LLM run
    # has completed. They are evaluation labels, never miner inputs.
    profile_bundle = read_json(args.expected_sources)
    profiles = dict(profile_bundle.get("profiles", {}) or {})
    for result in per_sample_results:
        sample_id = str(result.get("sample_id", ""))
        profile = dict(profiles.get(sample_id, {}) or {})
        expected_sources = unique_expected_sources(profile)
        result["inventory"]["expected_source_count"] = len(expected_sources)
        result["inventory"]["profile_status"] = str(profile.get("profile_status") or "")
        for source in expected_sources:
            expected_records.append({"sample_id": sample_id, **source})
        if result.get("status") == "EVALUATED":
            result["source_scope"] = evaluate_sources(
                expected_sources,
                list(result.pop("_confirmed_sources", []) or []),
                list(result.pop("_unresolved_candidates", []) or []),
            )
            result["notes"] = {
                "evaluation_scope": "Source Miner only; expected sources are public-grounded source surfaces.",
                "confirmed_meaning": "Expected function/site/label appears in sources.json after deterministic scan and optional LLM resolution.",
                "need_confirmation_meaning": "Expected source remains only in source_unconfirmed.json.",
            }
        elif expected_sources:
            # Infrastructure/miner failures count as misses; they must not
            # silently disappear from the recall denominator.
            result["source_scope"] = evaluate_sources(expected_sources, [], [])
        write_json(args.out / "per_sample" / sample_id / "match.json", result)

    evaluated = [r for r in per_sample_results if r.get("status") == "EVALUATED"]
    eval_with_expected = [
        r for r in per_sample_results
        if r.get("source_scope", {}).get("expected_source_count", 0) > 0
    ]
    total_expected = sum(r["source_scope"]["expected_source_count"] for r in eval_with_expected)
    total_confirmed = sum(r["source_scope"]["confirmed"] for r in eval_with_expected)
    total_direct = sum(r["source_scope"]["direct_confirmed"] for r in eval_with_expected)
    total_llm = sum(r["source_scope"]["llm_confirmed"] for r in eval_with_expected)
    total_need = sum(r["source_scope"]["need_confirmation"] for r in eval_with_expected)
    total_miss = sum(r["source_scope"]["miss"] for r in eval_with_expected)

    global_confirmed = sum(int(r.get("mini_counts", {}).get("confirmed_sources") or 0) for r in evaluated)
    global_direct = sum(int(r.get("mini_counts", {}).get("direct_confirmed_sources") or 0) for r in evaluated)
    global_llm = sum(int(r.get("mini_counts", {}).get("llm_confirmed_sources") or 0) for r in evaluated)
    global_unconfirmed_initial = sum(int(r.get("mini_counts", {}).get("unconfirmed_candidates") or 0) for r in evaluated)
    global_llm_confirmed = sum(int(r.get("mini_resolution", {}).get("llm_confirmed_total") or 0) for r in evaluated)
    global_llm_rejected = sum(int(r.get("mini_resolution", {}).get("rejected_total") or 0) for r in evaluated)
    global_remaining_need_confirmation = sum(int(r.get("mini_resolution", {}).get("unresolved_blockers") or 0) for r in evaluated)
    matched_output_keys: set[tuple[str, str]] = set()
    for result in eval_with_expected:
        for match_row in result.get("source_scope", {}).get("matches", []):
            matched = (match_row.get("match", {}) or {}).get("matched_source") or {}
            source_id = str(matched.get("id", ""))
            if source_id:
                matched_output_keys.add((str(result.get("sample_id", "")), source_id))
    public_trigger_precision_lower_bound = (
        len(matched_output_keys) / global_confirmed if global_confirmed else None
    )

    final_tool_hashes = evaluation_tool_hashes()
    if final_tool_hashes != initial_tool_hashes:
        raise SystemExit("evaluation tool files changed during execution; results are invalid")

    summary = {
        "schema_version": "ct-mini-cve-source-eval-v1",
        "manifest": str(args.manifest),
        "expected_sources": str(args.expected_sources),
        "run_llm": args.run_llm,
        "run_ghidra": args.run_ghidra,
        "sample_count": len(samples),
        "evaluated_count": len(evaluated),
        "untestable_count": sum(1 for r in per_sample_results if r.get("status") == "UNTESTABLE"),
        "failed_count": sum(
            1 for r in per_sample_results
            if r.get("status") in {"MINI_RUN_FAILED", "GHIDRA_FACT_EXPORT_FAILED"}
        ),
        "trigger_reference": {
            "sample_count_with_expected": len(eval_with_expected),
            "expected_source_count": total_expected,
            "confirmed": total_confirmed,
            "direct_confirmed": total_direct,
            "llm_confirmed": total_llm,
            "need_confirmation": total_need,
            "miss": total_miss,
            "confirmed_rate": total_confirmed / total_expected if total_expected else None,
            "candidate_inclusive_rate": (total_confirmed + total_need) / total_expected if total_expected else None,
        },
        "global_miner_counts": {
            "confirmed_sources": global_confirmed,
            "direct_confirmed_sources": global_direct,
            "llm_confirmed_sources": global_llm,
            "initial_source_unconfirmed_candidates": global_unconfirmed_initial,
            "llm_confirmed_candidates": global_llm_confirmed,
            "llm_rejected_candidates": global_llm_rejected,
            "remaining_need_confirmation_candidates": global_remaining_need_confirmation,
        },
        "blind_output_audit": {
            "expected_profiles_used_after_mining_only": not args.reuse_existing_artifacts,
            "fresh_blind_run": not args.reuse_existing_artifacts,
            "frozen_tool_hashes": initial_tool_hashes,
            "tool_hashes_unchanged_at_end": True,
            "public_profile_sha256": sha256_path(args.expected_sources),
            "public_trigger_matched_confirmed_outputs": len(matched_output_keys),
            "other_confirmed_outputs_requiring_independent_review": max(
                0, global_confirmed - len(matched_output_keys)
            ),
            "public_trigger_precision_lower_bound": public_trigger_precision_lower_bound,
            "interpretation": "A conservative lower bound, not full tool precision: additional confirmed Sources may be valid ingress sites unrelated to the selected CVE trigger.",
        },
        "per_sample": [
            {
                "sample_id": r["sample_id"],
                "status": r["status"],
                "expected_sources": r.get("source_scope", {}).get("expected_source_count"),
                "confirmed": r.get("source_scope", {}).get("confirmed"),
                "direct_confirmed": r.get("source_scope", {}).get("direct_confirmed"),
                "llm_confirmed": r.get("source_scope", {}).get("llm_confirmed"),
                "need_confirmation": r.get("source_scope", {}).get("need_confirmation"),
                "miss": r.get("source_scope", {}).get("miss"),
                "mini_confirmed_sources": r.get("mini_counts", {}).get("confirmed_sources"),
                "mini_initial_unconfirmed_candidates": r.get("mini_counts", {}).get("unconfirmed_candidates"),
                "mini_remaining_need_confirmation": r.get("mini_resolution", {}).get("unresolved_blockers"),
                "llm_rejected": r.get("mini_resolution", {}).get("rejected_total"),
                "remaining_need_confirmation": r.get("mini_resolution", {}).get("unresolved_blockers"),
                "runtime_seconds": r.get("run", {}).get("runtime_seconds"),
            }
            for r in per_sample_results
        ],
    }

    write_json(args.out / "cve_samples.json", inventory)
    write_json(args.out / "cve_expected_sources.json", expected_records)
    write_json(args.out / "summary.json", summary)

    lines = [
        "# CopperTrace Mini CVE Source Mining Evaluation",
        "",
        f"Manifest: `{args.manifest}`",
        f"Samples: {summary['sample_count']} total, {summary['evaluated_count']} evaluated, {summary['failed_count']} failed.",
        f"LLM resolution: {'on' if args.run_llm else 'off'}",
        "",
        "## Trigger Reference",
        "",
    ]
    tr = summary["trigger_reference"]
    total = tr["expected_source_count"]
    lines.extend(
        [
            f"- confirmed: {tr['confirmed']} / {total}",
            f"- direct confirmed: {tr['direct_confirmed']} / {total}",
            f"- LLM confirmed: {tr['llm_confirmed']} / {total}",
            f"- need confirmation: {tr['need_confirmation']} / {total}",
            f"- miss: {tr['miss']} / {total}",
            "",
            "## Global Miner Counts",
            "",
        ]
    )
    gm = summary["global_miner_counts"]
    lines.extend(
        [
            f"- total confirmed sources: {gm['confirmed_sources']}",
            f"- direct confirmed sources: {gm['direct_confirmed_sources']}",
            f"- LLM confirmed sources: {gm['llm_confirmed_sources']}",
            f"- initial source_unconfirmed candidates: {gm['initial_source_unconfirmed_candidates']}",
            f"- LLM confirmed/rejected/remaining need-confirmation candidates: {gm['llm_confirmed_candidates']}/{gm['llm_rejected_candidates']}/{gm['remaining_need_confirmation_candidates']}",
            "",
            "## Per Sample",
            "",
            "| Sample | Expected | Confirmed direct/LLM | Need confirmation | Miss | MINI confirmed | Initial candidates | Remaining blockers | Runtime (s) |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in summary["per_sample"]:
        rt = row.get("runtime_seconds")
        rt_s = f"{rt:.3f}" if isinstance(rt, (int, float)) else "n/a"
        lines.append(
            f"| {row['sample_id']} | {row.get('expected_sources', 'n/a')} | "
            f"{row.get('direct_confirmed', 'n/a')}/{row.get('llm_confirmed', 'n/a')} | "
            f"{row.get('need_confirmation', 'n/a')} | {row.get('miss', 'n/a')} | "
            f"{row.get('mini_confirmed_sources', 'n/a')} | "
            f"{row.get('mini_initial_unconfirmed_candidates', 'n/a')} | "
            f"{row.get('mini_remaining_need_confirmation', 'n/a')} | {rt_s} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation Notes",
            "",
            "- This evaluates Source Miner only, not complete vulnerability chains.",
            "- Confirmed means public expected function/site/label appears in `sources.json`.",
            "- Need confirmation means it remains in `source_unconfirmed.json` after the chosen resolution mode.",
            "- Zephyr CVE-2021-3329 is retained in inventory but has no public code-level expected source profile.",
        ]
    )
    (args.out / "summary.md").write_text("\n".join(lines) + "\n")
    print(json.dumps(summary["trigger_reference"], indent=2, sort_keys=True))
    print(json.dumps(summary["global_miner_counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
