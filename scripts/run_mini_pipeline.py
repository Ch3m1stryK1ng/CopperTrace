#!/usr/bin/env python3
"""Run the no-front-LLM CopperTrace Mini prototype over a dataset manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import eval_cve_source_mining as source_eval  # noqa: E402


DEFAULT_MANIFEST = ROOT / "datasets/source_mining_direct_taint_no_microbench.json"
DEFAULT_SOURCE_PROFILES = ROOT / "datasets/public_expected_sources/source_profiles.json"
DEFAULT_FACTS_CACHE = ROOT / "artifacts/ghidra_source_facts_cache"
DEFAULT_HARDWARE_PROFILE_REGISTRY = ROOT / "registries" / "hardware"
ABLATION_CAPABILITIES = (
    "mcu-source-recognition",
    "body-derived-sink-heuristics",
)


def source_builder_ablation_args(
    disabled_capabilities: tuple[str, ...],
) -> list[str]:
    if "mcu-source-recognition" in disabled_capabilities:
        return ["--disable-mcu-source-recognition"]
    return []


def sink_builder_ablation_args(
    disabled_capabilities: tuple[str, ...],
) -> list[str]:
    if "body-derived-sink-heuristics" in disabled_capabilities:
        return ["--disable-body-derived-sink-heuristics"]
    return []


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_tree(path: Path, pattern: str = "*.profile.json") -> str:
    digest = hashlib.sha256()
    for child in sorted(path.glob(pattern)):
        digest.update(str(child.relative_to(path)).encode())
        digest.update(b"\0")
        digest.update(bytes.fromhex(sha256_path(child)))
    return digest.hexdigest()


def prepare_full_program_facts(
    *, sample: dict[str, Any], cache_dir: Path, out_dir: Path
) -> dict[str, Any]:
    """Export whole-image High P-code facts; public CVE profiles are not inputs."""

    binary = Path(str(sample.get("binary_path", "")))
    if not binary.exists():
        return {"returncode": 2, "error": f"missing ELF: {binary}"}
    binary_hash = sha256_path(binary)
    prebuilt = source_eval.optional_path(sample.get("program_facts_path"))
    if prebuilt and prebuilt.exists():
        artifact = read_json(prebuilt)
        if (
            str(artifact.get("binary_sha256", "")) == binary_hash
            and str(artifact.get("schema_version", "")) == source_eval.GHIDRA_FACT_SCHEMA
        ):
            return {
                "returncode": 0,
                "program_facts": str(prebuilt),
                "cache_hit": True,
                "cache_kind": "manifest_full_program_facts",
            }
    fingerprint = source_eval.ghidra_tool_fingerprint()
    facts_path = cache_dir / f"{binary_hash[:20]}-full-{fingerprint[:12]}.program_facts.json"
    cache_dir.mkdir(parents=True, exist_ok=True)
    if facts_path.exists():
        cached = read_json(facts_path)
        if (
            str(cached.get("binary_sha256", "")) == binary_hash
            and str(cached.get("schema_version", "")) == source_eval.GHIDRA_FACT_SCHEMA
        ):
            return {
                "returncode": 0,
                "program_facts": str(facts_path),
                "cache_hit": True,
                "cache_kind": "whole_image_cache",
            }
    command = [
        str(source_eval.GHIDRA_EXPORT_RUNNER),
        str(binary),
        str(facts_path),
    ]
    proc = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    (out_dir / "run_ghidra_full_facts.log").write_text(
        "CMD: " + " ".join(command) + "\n\nSTDOUT:\n" + proc.stdout + "\nSTDERR:\n" + proc.stderr
    )
    return {
        "returncode": proc.returncode,
        "program_facts": str(facts_path),
        "cache_hit": False,
        "cache_kind": "whole_image_export",
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(errors="replace"))


def optional_file(value: Any) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    path = Path(text)
    return path if path.is_file() else None


def materialize_decompiled_c(
    *, program_facts: Path, out_dir: Path
) -> dict[str, Any]:
    """Materialize the C view carried by whole-image Ghidra ProgramFacts."""

    output = out_dir / "plain_decompiled.c"
    command = [
        sys.executable,
        str(ROOT / "scripts/program_facts_to_corpus.py"),
        "--program-facts",
        str(program_facts),
        "--out",
        str(output),
    ]
    proc = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    (out_dir / "materialize_decompiled_c.log").write_text(
        "CMD: "
        + " ".join(command)
        + "\n\nSTDOUT:\n"
        + proc.stdout
        + "\nSTDERR:\n"
        + proc.stderr
    )
    try:
        report = json.loads(proc.stdout.strip()) if proc.stdout.strip() else {}
    except json.JSONDecodeError:
        report = {}
    materialized = int(report.get("functions_materialized", 0) or 0)
    if proc.returncode != 0 or not output.is_file() or materialized <= 0:
        return {
            "returncode": proc.returncode or 2,
            "error": "failed_to_materialize_decompiled_c",
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "functions_materialized": materialized,
        }
    return {
        "returncode": 0,
        "decompiled_c": str(output),
        "functions_materialized": materialized,
    }


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n")


def run_command(command: list[str], *, log_path: Path) -> None:
    proc = subprocess.run(command, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log_path.write_text(
        "CMD: " + " ".join(command) + "\n\nSTDOUT:\n" + proc.stdout + "\nSTDERR:\n" + proc.stderr
    )
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(command)}")


def normalized(text: Any) -> str:
    return re.sub(r"\s+", "", str(text or "")).lower()


def match_sink(
    expected: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    primitive_effect_sites: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    pattern = str(expected.get("expr_regex", ""))
    site_pattern = str(expected.get("site_id_regex", ""))
    required_parts = [normalized(item) for item in list(expected.get("expr_contains_all", []) or [])]
    effects_by_site: dict[str, list[dict[str, Any]]] = {}
    for effect in list(primitive_effect_sites or []):
        site_id = str(effect.get("site_id") or effect.get("effect_site_id") or "")
        if site_id:
            effects_by_site.setdefault(site_id, []).append(dict(effect))

    matches: list[tuple[dict[str, Any], dict[str, Any], str, str, list[dict[str, Any]]]] = []
    for row in rows:
        expected_label = str(expected.get("pipeline_label_hint") or expected.get("label", ""))
        if expected_label and str(row.get("label", "")) != expected_label:
            continue
        views = [("sink_boundary", row)] + [
            ("body_derived_boundary", dict(boundary))
            for boundary in list(row.get("boundary_callsites", []) or [])
        ]
        effect_site_id = str(row.get("effect_site_id", ""))
        views.extend(
            ("body_derived_effect", effect)
            for effect in effects_by_site.get(effect_site_id, [])
        )
        for matched_via, view in views:
            if str(view.get("function", "")) != str(expected.get("function_name", "")):
                continue
            callee = str(expected.get("callee", ""))
            if callee and str(view.get("callee", "")) != callee:
                continue
            if site_pattern and re.search(site_pattern, str(view.get("site_id", ""))) is None:
                continue
            if pattern and not site_pattern and re.search(pattern, str(view.get("expr", ""))) is None:
                continue
            if required_parts and not all(part in normalized(view.get("expr", "")) for part in required_parts):
                continue
            site_id = str(view.get("site_id", ""))
            binding_status = str(view.get("binding_status", row.get("binding_status", "")))
            site_binding = (
                "HIGH_PCODE_SITE"
                if site_id.startswith("site:")
                and (
                    matched_via in {"sink_boundary", "body_derived_boundary"}
                    or binding_status.startswith("verified_high_pcode_")
                )
                else "TEXT_SITE"
                if site_id.startswith("textsite:")
                else "UNBOUND_SITE"
            )
            parameters = list(view.get("vulnerable_parameters", []) or [])
            matches.append((row, view, matched_via, site_binding, parameters))
    if matches:
        row, view, matched_via, site_binding, parameters = matches[0]
        sink_ids = list(dict.fromkeys(
            str(candidate.get("id", ""))
            for candidate, _view, _via, _binding, _parameters in matches
            if str(candidate.get("id", ""))
        ))
        return {
            "status": (
                "DETERMINISTIC_HIT"
                if str(row.get("recognition", "")) == "deterministic"
                or row.get("decision") == "ACCEPT_DETERMINISTIC"
                else "HEURISTIC_HIT"
            ),
            "expected_sink_id": str(expected.get("sink_id", "")),
            "sink_id": sink_ids[0] if sink_ids else "",
            "sink_ids": sink_ids,
            "effect_site_id": str(row.get("effect_site_id", row.get("site_id", ""))),
            "matched_via": matched_via,
            "site_id": str(view.get("site_id", "")),
            "decision": str(row.get("decision", "")),
            "recognition": str(row.get("recognition", "")),
            "site_binding": site_binding,
            "parameter_bindings": {
                "total": len(parameters),
                "bound": len([
                    parameter for parameter in parameters
                    if parameter.get("value_id") or parameter.get("object_id")
                ]),
            },
        }
    return {"status": "MISS", "expected_sink_id": str(expected.get("sink_id", ""))}


def match_source(expected: dict[str, Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    required_parts = [normalized(item) for item in list(expected.get("expr_contains_all", []) or [])]
    expected_functions = {
        str(name)
        for name in (
            list(expected.get("function_names", []) or [])
            or [expected.get("function_name", "")]
        )
        if str(name)
    }
    matches: list[dict[str, Any]] = []
    for row in rows:
        if expected_functions and str(row.get("function", "")) not in expected_functions:
            continue
        expected_label = str(expected.get("label", ""))
        if expected_label and str(row.get("label", "")) != expected_label:
            continue
        callee = str(expected.get("callee", ""))
        if callee and str(row.get("callee", "")) != callee:
            continue
        buffer_name = str(expected.get("source_buffer", ""))
        if buffer_name and normalized(buffer_name) not in normalized(row.get("source_buffer", "")):
            continue
        site_text = normalized(row.get("source_site", ""))
        evidence_text = site_text + normalized(
            json.dumps(row.get("proof", {}), sort_keys=True)
        )
        if required_parts and not all(part in evidence_text for part in required_parts):
            continue
        matches.append(row)
    if matches:
        row = matches[0]
        return {
            "status": "DETERMINISTIC_HIT" if all(
                match.get("decision") == "ACCEPT_DETERMINISTIC"
                for match in matches
            ) else "HEURISTIC_HIT",
            "expected_source_id": str(expected.get("source_id", "")),
            "source_id": str(row.get("id", "")),
            "source_ids": sorted(
                {str(match.get("id", "")) for match in matches if match.get("id")}
            ),
            "site_id": str(row.get("site_id", "")),
            "decision": str(row.get("decision", "")),
        }
    return {"status": "MISS", "expected_source_id": str(expected.get("source_id", ""))}


def evaluate_chains(
    expected_sink_matches: list[dict[str, Any]],
    expected_source_matches: list[dict[str, Any]],
    chains: dict[str, Any],
) -> list[dict[str, Any]]:
    by_sink = {str(chain.get("sink_id", "")): chain for chain in list(chains.get("chains", []) or [])}
    source_ids = {
        str(source_id)
        for match in expected_source_matches
        if str(match.get("status", "")) != "MISS"
        for source_id in (
            list(match.get("source_ids", []) or [])
            or [match.get("source_id", "")]
        )
        if str(source_id)
    }
    results = []
    for sink_match in expected_sink_matches:
        sink_ids = [
            str(sink_id)
            for sink_id in (
                list(sink_match.get("sink_ids", []) or [])
                or [sink_match.get("sink_id", "")]
            )
            if str(sink_id)
        ]
        if not sink_ids:
            results.append({"expected_sink_id": sink_match.get("expected_sink_id"), "status": "SINK_MISS"})
            continue
        candidate_chains = [by_sink[sink_id] for sink_id in sink_ids if sink_id in by_sink]
        if not candidate_chains:
            results.append({"expected_sink_id": sink_match.get("expected_sink_id"), "status": "CHAIN_NOT_EMITTED"})
            continue
        evaluated = []
        for chain in candidate_chains:
            reached = {
                str(source_id)
                for parameter in list(chain.get("parameter_results", []) or [])
                for path in list(parameter.get("paths", []) or [])
                for source_id in (
                    list(path.get("source_lineage_ids", []) or [])
                    or [path.get("source_id", "")]
                )
                if str(source_id)
            }
            status = str(chain.get("status", ""))
            evaluated.append((
                bool(reached & source_ids),
                status.startswith("SOURCE_REACHED_"),
                status,
                chain,
                reached,
            ))
        _matched, _source_reached, _status, chain, reached = max(
            evaluated,
            key=lambda item: (
                item[0],
                item[1],
                item[2] == "GRAPH_INCOMPLETE",
                item[2] != "PROVEN_INTERNAL_ONLY",
            ),
        )
        sink_id = str(chain.get("sink_id", ""))
        results.append(
            {
                "expected_sink_id": sink_match.get("expected_sink_id"),
                "sink_id": sink_id,
                "candidate_sink_ids": sink_ids,
                "status": str(chain.get("status", "")),
                "matched_public_source": bool(reached & source_ids),
                "reached_source_ids": sorted(reached),
            }
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST, type=Path)
    parser.add_argument("--source-profiles", default=DEFAULT_SOURCE_PROFILES, type=Path)
    parser.add_argument("--facts-cache", default=DEFAULT_FACTS_CACHE, type=Path)
    parser.add_argument(
        "--hardware-profile-registry",
        default=DEFAULT_HARDWARE_PROFILE_REGISTRY,
        type=Path,
    )
    parser.add_argument(
        "--allow-manifest-hardware-metadata-debug",
        action="store_true",
        help=(
            "Debug-only: allow a sample manifest to select hardware metadata. "
            "Canonical evaluation leaves this disabled."
        ),
    )
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument(
        "--facts-mode",
        choices=("full", "source-selected"),
        default="full",
        help="Use whole-image ProgramFacts by default; source-selected mode is diagnostic only.",
    )
    parser.add_argument(
        "--audit-sink-heuristics",
        action="store_true",
        help=(
            "Execute registry rules marked audit_enabled. Rules marked "
            "audit_only are reported but remain outside BFS/RDA startpoints."
        ),
    )
    parser.add_argument(
        "--sink-heuristic-method",
        action="append",
        default=[],
        help=(
            "Audit a named Sink heuristic in addition to rules enabled by "
            "default. May be repeated and requires --audit-sink-heuristics."
        ),
    )
    parser.add_argument(
        "--graph-mode",
        choices=("unified", "callgraph-only"),
        default="unified",
        help="Run the normal unified graph or the controlled Callgraph-only ablation.",
    )
    parser.add_argument(
        "--disable-capability",
        action="append",
        choices=ABLATION_CAPABILITIES,
        default=[],
        help=(
            "Disable one analysis capability for a controlled ablation. May "
            "be repeated to compose Source and Sink Miner ablations."
        ),
    )
    parser.add_argument(
        "--max-finite-callind-targets",
        type=int,
        default=32,
        help=(
            "Maximum complete immutable function-table target set retained "
            "as MAY CALLIND relations. Sets above the limit are not truncated."
        ),
    )
    parser.add_argument(
        "--max-trace-witnesses",
        type=int,
        default=64,
        help=(
            "Maximum representative reverse-BFS traces serialized per Sink. "
            "This does not restrict the graph admitted to RDA."
        ),
    )
    parser.add_argument(
        "--reuse-static-artifacts-from",
        type=Path,
        help=(
            "Reuse sources.json, sinks.json, and channel_graph.json from a "
            "completed compatible run and execute only BFS/RDA. Intended for "
            "controlled graph-mode ablations."
        ),
    )
    parser.add_argument(
        "--reuse-source-sink-artifacts-from",
        type=Path,
        help=(
            "Reuse hash-matched sources.json and sinks.json, then rebuild "
            "Channelgraph and BFS/RDA with the current graph budget."
        ),
    )
    args = parser.parse_args()
    disabled_capabilities = tuple(sorted(set(args.disable_capability)))
    if args.sink_heuristic_method and not args.audit_sink_heuristics:
        parser.error(
            "--sink-heuristic-method requires --audit-sink-heuristics"
        )
    if (
        args.reuse_static_artifacts_from is not None
        and args.reuse_source_sink_artifacts_from is not None
    ):
        parser.error(
            "--reuse-static-artifacts-from and "
            "--reuse-source-sink-artifacts-from are mutually exclusive"
        )
    if disabled_capabilities and (
        args.reuse_static_artifacts_from is not None
        or args.reuse_source_sink_artifacts_from is not None
    ):
        parser.error(
            "--disable-capability cannot be combined with reused Source/Sink "
            "artifacts"
        )

    manifest = read_json(args.manifest)
    profiles = read_json(args.source_profiles)
    raw_profiles = profiles.get("profiles", {}) or {}
    profile_rows = list(raw_profiles.values()) if isinstance(raw_profiles, dict) else list(raw_profiles)
    source_profiles = {
        str(profile.get("sample_id", "")): profile for profile in profile_rows
    }
    selected = set(args.sample)
    samples = [
        sample for sample in list(manifest.get("samples", []) or [])
        if not selected or str(sample.get("sample_id", "")) in selected
    ]
    args.out.mkdir(parents=True, exist_ok=True)

    sample_results = []
    aggregate = Counter()
    source_status = Counter()
    sink_status = Counter()
    chain_status = Counter()
    sink_binding_status = Counter()
    unique_binary_counts: dict[str, dict[str, dict[str, int]]] = {}

    for sample in samples:
        sample_id = str(sample.get("sample_id", ""))
        sample_out = args.out / "per_sample" / sample_id
        sample_out.mkdir(parents=True, exist_ok=True)
        decompiled = optional_file(sample.get("decompiled_c_path"))
        decompiled_generated_from_program_facts = False
        if args.facts_mode == "full":
            facts_run = prepare_full_program_facts(
                sample=sample,
                cache_dir=args.facts_cache,
                out_dir=sample_out,
            )
        else:
            if decompiled is None:
                sample_results.append(
                    {
                        "sample_id": sample_id,
                        "status": "INFRA_FAILURE",
                        "reason": "missing_decompiled_c",
                    }
                )
                continue
            facts_run = source_eval.prepare_program_facts(
                sample=sample,
                decompiled=decompiled,
                cache_dir=args.facts_cache,
                out_dir=sample_out,
            )
        if int(facts_run.get("returncode", 1)) != 0:
            sample_results.append({"sample_id": sample_id, "status": "INFRA_FAILURE", "facts": facts_run})
            continue
        program_facts = Path(str(facts_run["program_facts"]))
        if decompiled is None:
            corpus_run = materialize_decompiled_c(
                program_facts=program_facts,
                out_dir=sample_out,
            )
            if int(corpus_run.get("returncode", 1)) != 0:
                sample_results.append(
                    {
                        "sample_id": sample_id,
                        "status": "INFRA_FAILURE",
                        "reason": "decompiled_c_materialization_failed",
                        "materialization": corpus_run,
                    }
                )
                continue
            decompiled = Path(str(corpus_run["decompiled_c"]))
            decompiled_generated_from_program_facts = True
        sources_path = sample_out / "sources.json"
        source_compat = sample_out / "source_unconfirmed.json"
        sinks_path = sample_out / "sinks.json"
        sink_compat = sample_out / "sink_unconfirmed.json"
        graph_path = sample_out / "channel_graph.json"
        chains_path = sample_out / "chains.json"
        binary = str(sample.get("binary_path", ""))
        hardware_metadata: Path | None = None
        hardware_metadata_value = (
            str(sample.get("hardware_metadata_path", "")).strip()
            if args.allow_manifest_hardware_metadata_debug
            else ""
        )
        if hardware_metadata_value:
            hardware_metadata = Path(hardware_metadata_value)
            if not hardware_metadata.is_absolute():
                hardware_metadata = ROOT / hardware_metadata
            if not hardware_metadata.exists():
                sample_results.append(
                    {
                        "sample_id": sample_id,
                        "status": "INFRA_FAILURE",
                        "reason": f"missing_hardware_metadata: {hardware_metadata}",
                    }
                )
                continue

        source_command = [
            sys.executable, str(ROOT / "scripts/build_source_artifacts.py"),
            "--input", str(decompiled), "--elf", binary,
            "--program-facts", str(program_facts),
            "--sources-json", str(sources_path),
            "--source-unconfirmed-json", str(source_compat),
            "--hardware-profile-registry", str(args.hardware_profile_registry),
        ]
        if hardware_metadata:
            source_command.extend(["--hardware-metadata", str(hardware_metadata)])
        source_command.extend(source_builder_ablation_args(disabled_capabilities))

        sink_command = [
            sys.executable, str(ROOT / "scripts/build_sink_artifacts.py"),
            "--input", str(decompiled), "--elf", binary,
            "--program-facts", str(program_facts),
            "--sources-json", str(sources_path),
            "--channel-graph", str(graph_path),
            "--sinks-json", str(sinks_path),
            "--sink-unconfirmed-json", str(sink_compat),
        ] + (
            ["--hardware-metadata", str(hardware_metadata)]
            if hardware_metadata
            else []
        )
        if args.audit_sink_heuristics:
            sink_command.append("--audit-heuristics")
            for method in args.sink_heuristic_method:
                sink_command.extend(["--heuristic-method", method])
        sink_command.extend(sink_builder_ablation_args(disabled_capabilities))

        analysis_sources_path = sources_path
        analysis_sinks_path = sinks_path
        analysis_graph_path = graph_path
        reused_static_artifacts = False
        reused_source_sink_artifacts = False
        reuse_root = (
            args.reuse_static_artifacts_from
            or args.reuse_source_sink_artifacts_from
        )
        if reuse_root is not None:
            reuse_sample = (
                reuse_root / "per_sample" / sample_id
            )
            analysis_sources_path = reuse_sample / "sources.json"
            analysis_sinks_path = reuse_sample / "sinks.json"
            if args.reuse_static_artifacts_from is not None:
                analysis_graph_path = reuse_sample / "channel_graph.json"
            required = [
                analysis_sources_path,
                analysis_sinks_path,
                reuse_sample / "public_match.json",
            ]
            if args.reuse_static_artifacts_from is not None:
                required.append(analysis_graph_path)
            missing = [str(path) for path in required if not path.exists()]
            if missing:
                sample_results.append(
                    {
                        "sample_id": sample_id,
                        "status": "INFRA_FAILURE",
                        "reason": "missing_reused_static_artifacts",
                        "missing": missing,
                    }
                )
                continue
            prior_match = read_json(reuse_sample / "public_match.json")
            prior_provenance = dict(prior_match.get("provenance", {}) or {})
            if (
                str(prior_provenance.get("binary_sha256", ""))
                != sha256_path(Path(binary))
                or str(prior_provenance.get("program_facts_sha256", ""))
                != sha256_path(program_facts)
            ):
                sample_results.append(
                    {
                        "sample_id": sample_id,
                        "status": "INFRA_FAILURE",
                        "reason": "reused_static_artifact_identity_mismatch",
                    }
                )
                continue
            reused_static_artifacts = args.reuse_static_artifacts_from is not None
            reused_source_sink_artifacts = (
                args.reuse_source_sink_artifacts_from is not None
            )
            if reused_source_sink_artifacts:
                shutil.copy2(analysis_sources_path, sources_path)
                shutil.copy2(analysis_sinks_path, sinks_path)
                analysis_sources_path = sources_path
                analysis_sinks_path = sinks_path

        graph_command = [
            sys.executable, str(ROOT / "scripts/build_channel_graph_v2.py"),
            "--program-facts", str(program_facts),
            "--sources-json", str(analysis_sources_path),
            "--elf", binary,
            "--max-finite-callind-targets",
            str(max(0, int(args.max_finite_callind_targets))),
            "--output", str(graph_path),
        ]
        rda_command = [
            sys.executable, str(ROOT / "scripts/run_sink_backward_dfa.py"),
            "--program-facts", str(program_facts),
            "--sources-json", str(analysis_sources_path),
            "--sinks-json", str(analysis_sinks_path),
            "--channel-graph", str(analysis_graph_path),
            "--output", str(chains_path),
            "--strict",
            "--allow-may-channel",
            "--graph-mode", args.graph_mode,
            "--max-steps", "10000",
            "--max-function-depth", "8",
            "--max-summary-ops", "2000",
            "--max-summary-alternatives", "16",
            "--max-trace-witnesses",
            str(max(0, int(args.max_trace_witnesses))),
        ]
        if reused_static_artifacts:
            commands = [(4, rda_command)]
        elif reused_source_sink_artifacts:
            commands = [(2, graph_command), (4, rda_command)]
        else:
            commands = [
                (1, source_command),
                (2, graph_command),
                (3, sink_command),
                (4, rda_command),
            ]
        try:
            for stage, command in commands:
                run_command(command, log_path=sample_out / f"stage_{stage}.log")
        except Exception as exc:
            sample_results.append({"sample_id": sample_id, "status": "INFRA_FAILURE", "reason": str(exc)})
            continue

        sources = read_json(analysis_sources_path)
        sinks = read_json(analysis_sinks_path)
        graph = read_json(analysis_graph_path)
        chains = read_json(chains_path)
        sink_profile_path = optional_file(sample.get("expected_profile_path"))
        sink_profile = read_json(sink_profile_path) if sink_profile_path else {"sinks": []}
        source_profile = source_profiles.get(sample_id, {"sources": []})
        source_matches = [match_source(expected, list(sources.get("source_sites", []) or [])) for expected in list(source_profile.get("sources", []) or [])]
        sink_matches = [
            match_sink(
                expected,
                list(sinks.get("sink_startpoints", []) or []),
                primitive_effect_sites=list(sinks.get("primitive_effect_sites", []) or []),
            )
            for expected in list(sink_profile.get("sinks", []) or [])
        ]
        chain_matches = evaluate_chains(sink_matches, source_matches, chains)
        for match in source_matches:
            source_status[str(match.get("status", ""))] += 1
        for match in sink_matches:
            sink_status[str(match.get("status", ""))] += 1
            sink_binding_status[str(match.get("site_binding", "MISS"))] += 1
        for match in chain_matches:
            chain_status[str(match.get("status", ""))] += 1

        counts = {
            "sources": dict(sources.get("counts", {}) or {}),
            "sinks": dict(sinks.get("counts", {}) or {}),
            "graph": dict(graph.get("counts", {}) or {}),
            "chains": dict(chains.get("counts", {}) or {}),
        }
        aggregate["source_sites"] += int(counts["sources"].get("source_sites", 0))
        aggregate["sink_startpoints"] += int(counts["sinks"].get("sink_startpoints", 0))
        aggregate["object_nodes"] += int(counts["graph"].get("object_nodes", 0))
        aggregate["shared_objects"] += int(counts["graph"].get("shared_objects", 0))
        aggregate["channel_edges"] += int(counts["graph"].get("channel_edges", 0))
        aggregate["candidate_channel_edges"] += int(counts["graph"].get("candidate_channel_edges", 0))
        aggregate["source_write_candidates"] += int(counts["graph"].get("deterministic_source_write_candidates", 0))
        aggregate["channel_blockers"] += int(counts["graph"].get("channel_blockers", 0))
        aggregate["unified_nodes"] += int(counts["graph"].get("unified_nodes", 0))
        aggregate["unified_edges"] += int(counts["graph"].get("unified_edges", 0))
        aggregate["unified_shared_object_nodes"] += int(counts["graph"].get("unified_shared_object_nodes", 0))
        aggregate["resolved_indirect_call_edges"] += int(
            counts["graph"].get("resolved_indirect_call_edges", 0)
        )
        aggregate["chains"] += int(counts["chains"].get("chains", 0))
        for name in (
            "reverse_bfs_runs",
            "parameter_rda_runs",
            "candidate_traces",
            "mixed_candidate_traces",
            "channel_assisted_chains",
        ):
            aggregate[f"chain_{name}"] += int(counts["chains"].get(name, 0))
        for name in (
            "deterministic_sink_calls",
            "heuristic_sink_calls",
            "heuristic_sink_startpoints",
            "heuristic_audit_candidates",
            "primitive_calls_observed",
            "withdrawn_out_of_scope",
            "body_derived_summaries",
            "body_derived_boundary_callsites",
            "analysis_blockers",
        ):
            aggregate[f"sink_{name}"] += int(counts["sinks"].get(name, 0))
        binary_sha256 = sha256_path(Path(binary))
        unique_binary_counts.setdefault(binary_sha256, counts)
        result = {
            "sample_id": sample_id,
            "cve": str(sample.get("cve", "")),
            "status": "OK",
            "program_facts": str(program_facts),
            "decompiled_c_path": str(decompiled),
            "facts_cache_hit": bool(facts_run.get("cache_hit")),
            "facts_cache_kind": str(facts_run.get("cache_kind", "")),
            "provenance": {
                "binary_sha256": binary_sha256,
                "decompiled_c_sha256": sha256_path(decompiled),
                "decompiled_c_generated_from_program_facts": (
                    decompiled_generated_from_program_facts
                ),
                "program_facts_sha256": sha256_path(program_facts),
                "hardware_metadata_path": str(hardware_metadata or ""),
                "hardware_metadata_sha256": sha256_path(hardware_metadata)
                if hardware_metadata
                else "",
                "hardware_profile_registry": str(args.hardware_profile_registry),
                "hardware_profile_registry_sha256": sha256_tree(
                    args.hardware_profile_registry
                ),
                "manifest_hardware_metadata_ignored": bool(
                    sample.get("hardware_metadata_path")
                    and not args.allow_manifest_hardware_metadata_debug
                ),
                "reused_static_artifacts": reused_static_artifacts,
                "reused_source_sink_artifacts": reused_source_sink_artifacts,
                "disabled_capabilities": list(disabled_capabilities),
                "static_artifact_source": str(
                    reuse_root or args.out
                ),
                "sources_sha256": sha256_path(analysis_sources_path),
                "sinks_sha256": sha256_path(analysis_sinks_path),
                "channel_graph_sha256": sha256_path(analysis_graph_path),
                "public_sink_profile_sha256": sha256_path(sink_profile_path)
                if sink_profile_path
                else "",
            },
            "counts": counts,
            "public_source_matches": source_matches,
            "public_sink_matches": sink_matches,
            "public_chain_matches": chain_matches,
        }
        write_json(sample_out / "public_match.json", result)
        sample_results.append(result)

    unique_aggregate = Counter()
    for counts in unique_binary_counts.values():
        unique_aggregate["source_sites"] += int(counts["sources"].get("source_sites", 0))
        unique_aggregate["sink_startpoints"] += int(counts["sinks"].get("sink_startpoints", 0))
        unique_aggregate["object_nodes"] += int(counts["graph"].get("object_nodes", 0))
        unique_aggregate["shared_objects"] += int(counts["graph"].get("shared_objects", 0))
        unique_aggregate["channel_edges"] += int(counts["graph"].get("channel_edges", 0))
        unique_aggregate["candidate_channel_edges"] += int(counts["graph"].get("candidate_channel_edges", 0))
        unique_aggregate["source_write_candidates"] += int(counts["graph"].get("deterministic_source_write_candidates", 0))
        unique_aggregate["channel_blockers"] += int(counts["graph"].get("channel_blockers", 0))
        unique_aggregate["unified_nodes"] += int(counts["graph"].get("unified_nodes", 0))
        unique_aggregate["unified_edges"] += int(counts["graph"].get("unified_edges", 0))
        unique_aggregate["unified_shared_object_nodes"] += int(counts["graph"].get("unified_shared_object_nodes", 0))
        unique_aggregate["resolved_indirect_call_edges"] += int(
            counts["graph"].get("resolved_indirect_call_edges", 0)
        )
        unique_aggregate["chains"] += int(counts["chains"].get("chains", 0))
        for name in (
            "reverse_bfs_runs",
            "parameter_rda_runs",
            "candidate_traces",
            "mixed_candidate_traces",
            "channel_assisted_chains",
        ):
            unique_aggregate[f"chain_{name}"] += int(counts["chains"].get(name, 0))
        for name in (
            "deterministic_sink_calls",
            "heuristic_sink_calls",
            "heuristic_sink_startpoints",
            "heuristic_audit_candidates",
            "primitive_calls_observed",
            "withdrawn_out_of_scope",
            "body_derived_summaries",
            "body_derived_boundary_callsites",
            "analysis_blockers",
        ):
            unique_aggregate[f"sink_{name}"] += int(counts["sinks"].get(name, 0))

    summary = {
        "schema_version": "ct-mini-pipeline-eval-v2",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "manifest": str(args.manifest),
        "facts_mode": args.facts_mode,
        "sink_heuristic_mode": (
            "audit_enabled_rules"
            if args.audit_sink_heuristics
            else "strict_enabled_rules_only"
        ),
        "sink_heuristic_methods": sorted(
            set(args.sink_heuristic_method)
        ),
        "hardware_profile_mode": (
            "manifest_debug_override_enabled"
            if args.allow_manifest_hardware_metadata_debug
            else "elf_automatic_register_first"
        ),
        "ground_truth_policy": "public_CVE_profiles_only_no_local_CopperTrace_GT",
        "front_llm": False,
        "evaluation_mode": (
            "ablation" if disabled_capabilities or args.graph_mode != "unified" else "full"
        ),
        "disabled_capabilities": list(disabled_capabilities),
        "graph_mode": args.graph_mode,
        "static_artifact_reuse_from": str(
            args.reuse_static_artifacts_from or ""
        ),
        "source_sink_artifact_reuse_from": str(
            args.reuse_source_sink_artifacts_from or ""
        ),
        "analysis_budgets": {
            "max_finite_callind_targets": max(
                0, int(args.max_finite_callind_targets)
            ),
            "max_trace_witnesses": max(
                0, int(args.max_trace_witnesses)
            ),
        },
        "samples_requested": len(samples),
        "samples_ok": len([row for row in sample_results if row.get("status") == "OK"]),
        "samples_failed": len([row for row in sample_results if row.get("status") != "OK"]),
        "unique_binaries_ok": len(unique_binary_counts),
        "public_sources": dict(sorted(source_status.items())),
        "public_sinks": dict(sorted(sink_status.items())),
        "public_sink_site_binding": dict(sorted(sink_binding_status.items())),
        "public_chain_status": dict(sorted(chain_status.items())),
        "pipeline_totals": dict(sorted(aggregate.items())),
        "pipeline_totals_unique_binaries": dict(sorted(unique_aggregate.items())),
        "samples": sample_results,
        "provenance": {
            "manifest_sha256": sha256_path(args.manifest),
            "source_profiles_sha256": sha256_path(args.source_profiles),
            "hardware_profile_registry_sha256": sha256_tree(
                args.hardware_profile_registry
            ),
            "tool_sha256": {
                str(path.relative_to(ROOT)): sha256_path(path)
                for path in (
                    Path(__file__).resolve(),
                    ROOT / "scripts/eval_cve_source_mining.py",
                    ROOT / "scripts/ghidra_export_source_facts.py",
                    ROOT / "scripts/run_ghidra_high_pcode_export.sh",
                    ROOT / "scripts/build_source_artifacts.py",
                    ROOT / "scripts/build_mmio_register_profile.py",
                    ROOT / "scripts/hardware_profile_matcher.py",
                    ROOT / "scripts/mmio_register_resolver.py",
                    ROOT / "scripts/build_sink_artifacts.py",
                    ROOT / "scripts/deterministic_sink_engine.py",
                    ROOT / "scripts/body_sink_heuristics.py",
                    ROOT / "scripts/variable_store_heuristic.py",
                    ROOT / "scripts/high_pcode_loop_analysis.py",
                    ROOT / "scripts/sink_artifact_schema.py",
                    ROOT / "scripts/audit_sink_generalization.py",
                    ROOT / "scripts/build_channel_graph_v2.py",
                    ROOT / "scripts/run_sink_backward_dfa.py",
                    ROOT / "registries/source_patterns.v0.json",
                    ROOT / "registries/sink_patterns.v2.json",
                    ROOT / "schemas/hardware_metadata.schema.json",
                )
            },
            "ghidra_tool_fingerprint": source_eval.ghidra_tool_fingerprint(),
        },
    }
    write_json(args.out / "summary.json", summary)
    lines = [
        "# CopperTrace Mini Pipeline Evaluation",
        "",
        f"- Samples: {summary['samples_ok']} / {summary['samples_requested']} OK",
        f"- Public source matches: `{summary['public_sources']}`",
        f"- Public sink matches: `{summary['public_sinks']}`",
        f"- Public chain status: `{summary['public_chain_status']}`",
        f"- Pipeline totals: `{summary['pipeline_totals']}`",
        f"- Unique binaries: `{summary['unique_binaries_ok']}`",
        f"- Pipeline totals over unique binaries: `{summary['pipeline_totals_unique_binaries']}`",
        "",
        "Static source reachability is not vulnerability or exploitability confirmation.",
    ]
    (args.out / "summary.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({key: summary[key] for key in (
        "samples_ok", "samples_failed", "unique_binaries_ok", "public_sources",
        "public_sinks", "public_chain_status", "pipeline_totals",
        "pipeline_totals_unique_binaries",
    )}, indent=2))
    return 0 if summary["samples_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
