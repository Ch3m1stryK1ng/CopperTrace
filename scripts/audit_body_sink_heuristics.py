#!/usr/bin/env python3
"""Audit body-derived Sink heuristics on an independent firmware corpus.

The auditor deliberately does not infer review labels. Detector output without a
manual review is reported as ``pending_review`` and cannot enable a heuristic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "datasets/sink_heuristic_audit_manifest.json"
DEFAULT_LABELS = ROOT / "datasets/sink_heuristic_audit_labels.json"

DEFAULT_THRESHOLDS = {
    "min_audited_unique_bodies": 10,
    "min_semantic_precision": 0.80,
    "min_parameter_precision": 0.80,
    "min_correct_codebase_families": 2,
    "require_all_detected_bodies_reviewed": True,
    "require_all_manifest_outputs": True,
}

PATTERN_ALIASES = {
    "counted_range": "counted_range",
    "counted_range_copy": "counted_range",
    "counted_range_fill": "counted_range",
    "counted_range_operation": "counted_range",
    "body_counted_range": "counted_range",
    "sentinel_copy": "sentinel_copy",
    "sentinel_copy_operation": "sentinel_copy",
    "body_sentinel_copy": "sentinel_copy",
    "paired_buffer_state": "paired_buffer_state",
    "paired_buffer_state_effect": "paired_buffer_state",
    "paired_buffer_state_update": "paired_buffer_state",
    "body_proved_paired_buffer_state_update": "paired_buffer_state",
    "buffer_state_reserve": "buffer_state_reserve",
    "buffer_state_reservation_or_growth": "buffer_state_reserve",
    "stateful_loop_write": "stateful_loop_write",
    "in_place_swap": "in_place_swap",
    "in_place_swap_operation": "in_place_swap",
    "body_in_place_swap": "in_place_swap",
    "parser_oob_read": "parser_oob_read",
    "parser_out_of_bounds_read": "parser_oob_read",
    "body_parser_oob_read": "parser_oob_read",
}

REVIEW_STATUSES = {"pending_review", "reviewed"}
SEMANTIC_VERDICTS = {"correct", "incorrect", "uncertain"}
PARAMETER_VERDICTS = {"correct", "incorrect", "not_applicable", "uncertain"}
MANIFEST_SCHEMA = "ct-mini-sink-heuristic-audit-manifest-v1"
LABELS_SCHEMA = "ct-mini-sink-heuristic-audit-labels-v1"


@dataclass(frozen=True)
class Finding:
    sample_id: str
    codebase_family: str
    pattern: str
    implementation_key: str
    identity_strength: str
    callsite_key: str
    sink_id: str

    @property
    def review_key(self) -> str:
        return f"{self.pattern}|{self.implementation_key}"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(errors="replace"))


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n")


def resolve_repo_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_pattern(row: dict[str, Any]) -> str:
    raw = (
        row.get("recognition_method")
        or row.get("heuristic_pattern")
        or row.get("pattern")
        or row.get("detection_kind")
        or ""
    )
    key = str(raw).strip().lower()
    return PATTERN_ALIASES.get(key, key)


def is_explicit_heuristic(row: dict[str, Any], bucket: str) -> bool:
    recognition = str(row.get("recognition", "")).strip().lower()
    decision = str(row.get("decision", "")).strip().upper()
    return (
        bucket == "heuristic_sink_calls"
        or recognition == "heuristic"
        or decision == "ACCEPT_HEURISTIC"
    )


def sink_rows(document: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for bucket in ("heuristic_sink_calls", "sink_startpoints", "sinks"):
        for raw in list(document.get(bucket, []) or []):
            if not isinstance(raw, dict) or not is_explicit_heuristic(raw, bucket):
                continue
            row = dict(raw)
            pattern = normalized_pattern(row)
            identity = str(
                row.get("id")
                or row.get("sink_id")
                or "|".join(
                    [
                        str(row.get("function_id", "")),
                        str(row.get("site_id", row.get("effect_site_id", ""))),
                        pattern,
                    ]
                )
            )
            if identity in seen:
                continue
            seen.add(identity)
            rows.append(row)
    return rows


def nested_string(row: dict[str, Any], names: Iterable[str]) -> str:
    proof = row.get("proof") if isinstance(row.get("proof"), dict) else {}
    for name in names:
        value = row.get(name)
        if value:
            return str(value)
        value = proof.get(name)
        if value:
            return str(value)
    return ""


def implementation_identity(
    row: dict[str, Any], binary_sha256: str, pattern: str
) -> tuple[str, str]:
    body_hash = nested_string(
        row,
        (
            "implementation_body_hash",
            "function_body_hash",
            "normalized_body_hash",
            "body_hash",
        ),
    )
    if body_hash:
        return f"body:{body_hash.lower()}", "body_hash"

    implementation_id = nested_string(row, ("implementation_id", "body_id"))
    if implementation_id:
        return f"implementation:{implementation_id}", "analyzer_implementation_id"

    function_id = str(
        row.get("implementation_function_id")
        or row.get("function_id")
        or row.get("callee_function_id")
        or row.get("function")
        or ""
    )
    if function_id:
        return (
            f"location:{binary_sha256}:{function_id}:{pattern}",
            "binary_function_location",
        )

    site_id = str(
        row.get("effect_site_id")
        or row.get("site_id")
        or row.get("instruction_address")
        or row.get("plain_line")
        or "unknown"
    )
    return f"location:{binary_sha256}:{site_id}:{pattern}", "binary_site_location"


def row_callsite_keys(row: dict[str, Any], sample_id: str) -> list[str]:
    callsites: list[str] = []
    boundary_rows = row.get("boundary_callsites")
    if not isinstance(boundary_rows, list):
        boundary_rows = row.get("callsite_instances")
    if isinstance(boundary_rows, list) and boundary_rows:
        for index, boundary in enumerate(boundary_rows):
            if isinstance(boundary, dict):
                key = (
                    boundary.get("site_id")
                    or boundary.get("callsite_id")
                    or boundary.get("instruction_address")
                    or boundary.get("plain_line")
                )
            else:
                key = boundary
            callsites.append(f"{sample_id}:{key or index}")
    else:
        key = (
            row.get("site_id")
            or row.get("effect_site_id")
            or row.get("instruction_address")
            or row.get("plain_line")
            or row.get("id")
            or row.get("sink_id")
            or "unknown"
        )
        callsites.append(f"{sample_id}:{key}")
    return sorted(set(callsites))


def development_hashes(
    manifest: dict[str, Any], errors: list[str], warnings: list[str]
) -> set[str]:
    hashes: set[str] = set()
    for raw_path in list(manifest.get("development_manifests", []) or []):
        path = resolve_repo_path(str(raw_path))
        if not path.exists():
            errors.append(f"development manifest is missing: {path}")
            continue
        try:
            document = read_json(path)
        except (OSError, ValueError) as exc:
            errors.append(f"cannot read development manifest {path}: {exc}")
            continue
        for sample in list(document.get("samples", []) or []):
            binary_value = str(sample.get("binary_path", "")).strip()
            if not binary_value:
                continue
            binary_path = resolve_repo_path(binary_value)
            if not binary_path.exists():
                warnings.append(
                    f"development binary is unavailable for overlap check: {binary_path}"
                )
                continue
            hashes.add(sha256_file(binary_path))
    return hashes


def validate_manifest(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["audit manifest must be a JSON object"]
    if document.get("schema_version") != MANIFEST_SCHEMA:
        errors.append(
            f"manifest schema_version must be {MANIFEST_SCHEMA!r}"
        )
    if not isinstance(document.get("samples"), list):
        errors.append("manifest samples must be a JSON array")
    patterns = document.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        errors.append("manifest patterns must be a non-empty JSON array")
    elif len({str(value) for value in patterns}) != len(patterns):
        errors.append("manifest patterns must not contain duplicates")
    thresholds = document.get("thresholds")
    if not isinstance(thresholds, dict):
        errors.append("manifest thresholds must be a JSON object")
    else:
        integer_fields = (
            "min_audited_unique_bodies",
            "min_correct_codebase_families",
        )
        precision_fields = (
            "min_semantic_precision",
            "min_parameter_precision",
        )
        for field in integer_fields:
            value = thresholds.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                errors.append(f"threshold {field} must be a positive integer")
        for field in precision_fields:
            value = thresholds.get(field)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                errors.append(f"threshold {field} must be numeric")
            elif not 0.0 <= float(value) <= 1.0:
                errors.append(f"threshold {field} must be in [0, 1]")
    return errors


def collect_findings(
    manifest: dict[str, Any],
) -> tuple[list[Finding], dict[str, Any], list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    excluded_hashes = development_hashes(manifest, errors, warnings)
    findings: list[Finding] = []
    sample_rows: list[dict[str, Any]] = []
    seen_samples: set[str] = set()
    seen_hashes: dict[str, str] = {}

    for sample in list(manifest.get("samples", []) or []):
        sample_id = str(sample.get("sample_id", "")).strip()
        family = str(sample.get("codebase_family", "")).strip()
        binary_path = resolve_repo_path(str(sample.get("binary_path", "")))
        sinks_path = resolve_repo_path(str(sample.get("sinks_path", "")))
        sample_report: dict[str, Any] = {
            "sample_id": sample_id,
            "codebase_family": family,
            "binary_path": str(binary_path),
            "sinks_path": str(sinks_path),
            "status": "pending",
            "heuristic_callsites": 0,
            "heuristic_implementation_bodies": 0,
        }
        sample_rows.append(sample_report)

        if not sample_id or sample_id in seen_samples:
            errors.append(f"missing or duplicate sample_id: {sample_id!r}")
            sample_report["status"] = "invalid_manifest"
            continue
        seen_samples.add(sample_id)
        if not family or family.lower().startswith("unknown"):
            errors.append(f"{sample_id}: codebase_family must be explicit")
            sample_report["status"] = "invalid_manifest"
            continue
        if not binary_path.exists():
            errors.append(f"{sample_id}: binary is missing: {binary_path}")
            sample_report["status"] = "missing_binary"
            continue

        actual_hash = sha256_file(binary_path)
        sample_report["binary_sha256"] = actual_hash
        expected_hash = str(sample.get("binary_sha256", "")).strip().lower()
        if expected_hash and actual_hash != expected_hash:
            errors.append(
                f"{sample_id}: binary hash mismatch; expected {expected_hash}, got {actual_hash}"
            )
            sample_report["status"] = "binary_hash_mismatch"
            continue
        if actual_hash in excluded_hashes:
            errors.append(
                f"{sample_id}: binary hash overlaps a development/public-CVE sample"
            )
            sample_report["status"] = "development_overlap"
            continue
        if actual_hash in seen_hashes:
            errors.append(
                f"{sample_id}: duplicates corpus binary {seen_hashes[actual_hash]}"
            )
            sample_report["status"] = "duplicate_binary"
            continue
        seen_hashes[actual_hash] = sample_id

        if not sinks_path.exists():
            sample_report["status"] = "missing_sinks_output"
            continue
        try:
            document = read_json(sinks_path)
        except (OSError, ValueError) as exc:
            errors.append(f"{sample_id}: cannot read {sinks_path}: {exc}")
            sample_report["status"] = "invalid_sinks_output"
            continue

        rows = sink_rows(document)
        sample_report["status"] = "loaded"
        sample_impls: set[tuple[str, str]] = set()
        sample_callsites: set[str] = set()
        for row in rows:
            pattern = normalized_pattern(row)
            if pattern not in PATTERN_ALIASES.values():
                warnings.append(
                    f"{sample_id}: unsupported heuristic pattern {pattern!r} was ignored"
                )
                continue
            implementation_key, strength = implementation_identity(
                row, actual_hash, pattern
            )
            sink_id = str(row.get("id") or row.get("sink_id") or "")
            for callsite_key in row_callsite_keys(row, sample_id):
                findings.append(
                    Finding(
                        sample_id=sample_id,
                        codebase_family=family,
                        pattern=pattern,
                        implementation_key=implementation_key,
                        identity_strength=strength,
                        callsite_key=callsite_key,
                        sink_id=sink_id,
                    )
                )
                sample_callsites.add(callsite_key)
            sample_impls.add((pattern, implementation_key))
        sample_report["heuristic_callsites"] = len(sample_callsites)
        sample_report["heuristic_implementation_bodies"] = len(sample_impls)

    corpus = {
        "manifest_samples": len(list(manifest.get("samples", []) or [])),
        "loaded_samples": sum(row["status"] == "loaded" for row in sample_rows),
        "missing_sinks_outputs": [
            row["sample_id"]
            for row in sample_rows
            if row["status"] == "missing_sinks_output"
        ],
        "unique_binary_hashes": len(seen_hashes),
        "codebase_families": sorted(
            {
                row["codebase_family"]
                for row in sample_rows
                if row["status"] in {"loaded", "missing_sinks_output"}
            }
        ),
        "development_hashes_checked": len(excluded_hashes),
        "samples": sample_rows,
    }
    return findings, corpus, errors, warnings


def load_reviews(
    path: Path, errors: list[str]
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    try:
        document = read_json(path)
    except (OSError, ValueError) as exc:
        errors.append(f"cannot read labels {path}: {exc}")
        return {}, {}
    if not isinstance(document, dict):
        errors.append("labels document must be a JSON object")
        return {}, {}
    if document.get("schema_version") != LABELS_SCHEMA:
        errors.append(f"labels schema_version must be {LABELS_SCHEMA!r}")
    if not isinstance(document.get("reviews"), list):
        errors.append("labels reviews must be a JSON array")
        return {}, document
    reviews: dict[str, dict[str, Any]] = {}
    for row in list(document.get("reviews", []) or []):
        if not isinstance(row, dict):
            errors.append("label review rows must be JSON objects")
            continue
        key = str(row.get("review_key", "")).strip()
        if not key or key in reviews:
            errors.append(f"missing or duplicate review_key: {key!r}")
            continue
        status = str(row.get("review_status", "")).strip()
        if status not in REVIEW_STATUSES:
            errors.append(f"{key}: invalid review_status {status!r}")
            continue
        if status == "reviewed":
            semantic = str(row.get("semantic_verdict", "")).strip()
            parameter = str(row.get("parameter_verdict", "")).strip()
            if semantic not in SEMANTIC_VERDICTS:
                errors.append(f"{key}: invalid semantic_verdict {semantic!r}")
            if parameter not in PARAMETER_VERDICTS:
                errors.append(f"{key}: invalid parameter_verdict {parameter!r}")
            if semantic == "correct" and parameter == "not_applicable":
                errors.append(
                    f"{key}: a correct Sink semantic requires a parameter verdict"
                )
            if semantic == "incorrect" and parameter not in {
                "not_applicable",
                "uncertain",
            }:
                errors.append(
                    f"{key}: parameter verdict must be not_applicable/uncertain "
                    "when Sink semantics are incorrect"
                )
        reviews[key] = row
    return reviews, document


def precision(correct: int, incorrect: int) -> float | None:
    denominator = correct + incorrect
    return correct / denominator if denominator else None


def evaluate_patterns(
    findings: list[Finding],
    reviews: dict[str, dict[str, Any]],
    patterns: list[str],
    thresholds: dict[str, Any],
    corpus_complete: bool,
    global_errors: list[str],
) -> tuple[dict[str, Any], list[dict[str, Any]], list[str]]:
    by_pattern: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_pattern[finding.pattern].append(finding)

    reports: dict[str, Any] = {}
    pending_queue: list[dict[str, Any]] = []
    observed_review_keys: set[str] = set()

    for pattern in patterns:
        rows = by_pattern.get(pattern, [])
        by_impl: dict[str, list[Finding]] = defaultdict(list)
        for finding in rows:
            by_impl[finding.implementation_key].append(finding)

        semantic_correct = 0
        semantic_incorrect = 0
        parameter_correct = 0
        parameter_incorrect = 0
        audited_canonical: set[str] = set()
        inconclusive_canonical: set[str] = set()
        correct_families: set[str] = set()
        pending_impls: list[str] = []
        identity_strengths: dict[str, int] = defaultdict(int)
        canonical_verdicts: dict[str, tuple[str, str]] = {}

        for implementation_key, impl_rows in sorted(by_impl.items()):
            review_key = f"{pattern}|{implementation_key}"
            observed_review_keys.add(review_key)
            review = reviews.get(review_key)
            families = sorted({row.codebase_family for row in impl_rows})
            samples = sorted({row.sample_id for row in impl_rows})
            callsites = sorted({row.callsite_key for row in impl_rows})
            strength = impl_rows[0].identity_strength
            identity_strengths[strength] += 1

            if not review or review.get("review_status") != "reviewed":
                pending_impls.append(implementation_key)
                pending_queue.append(
                    {
                        "review_key": review_key,
                        "pattern": pattern,
                        "implementation_key": implementation_key,
                        "review_status": "pending_review",
                        "semantic_verdict": None,
                        "parameter_verdict": None,
                        "canonical_implementation_id": None,
                        "sample_ids": samples,
                        "codebase_families": families,
                        "callsite_count": len(callsites),
                        "identity_strength": strength,
                        "notes": "",
                    }
                )
                continue

            semantic = str(review.get("semantic_verdict"))
            parameter = str(review.get("parameter_verdict"))
            canonical = str(
                review.get("canonical_implementation_id") or implementation_key
            )
            previous = canonical_verdicts.get(canonical)
            if previous and previous != (semantic, parameter):
                global_errors.append(
                    f"{pattern}: conflicting labels for canonical implementation "
                    f"{canonical}"
                )
                continue
            if previous:
                continue
            canonical_verdicts[canonical] = (semantic, parameter)

            conclusive = semantic in {"correct", "incorrect"} and (
                (semantic == "correct" and parameter in {"correct", "incorrect"})
                or (semantic == "incorrect" and parameter == "not_applicable")
            )
            if not conclusive:
                inconclusive_canonical.add(canonical)
                continue
            audited_canonical.add(canonical)

            if semantic == "correct":
                semantic_correct += 1
                if parameter == "correct":
                    parameter_correct += 1
                    correct_families.update(families)
                elif parameter == "incorrect":
                    parameter_incorrect += 1
            else:
                semantic_incorrect += 1

        semantic_value = precision(semantic_correct, semantic_incorrect)
        parameter_value = precision(parameter_correct, parameter_incorrect)
        reasons: list[str] = []
        if not corpus_complete:
            reasons.append("independent_corpus_outputs_incomplete")
        if global_errors:
            reasons.append("audit_errors_present")
        if len(audited_canonical) < int(thresholds["min_audited_unique_bodies"]):
            reasons.append("insufficient_audited_unique_bodies")
        if (
            semantic_value is None
            or semantic_value < float(thresholds["min_semantic_precision"])
        ):
            reasons.append("semantic_precision_below_threshold")
        if (
            parameter_value is None
            or parameter_value < float(thresholds["min_parameter_precision"])
        ):
            reasons.append("parameter_precision_below_threshold")
        if len(correct_families) < int(
            thresholds["min_correct_codebase_families"]
        ):
            reasons.append("insufficient_correct_codebase_families")
        if thresholds.get("require_all_detected_bodies_reviewed", True) and (
            pending_impls or inconclusive_canonical
        ):
            reasons.append("review_queue_not_fully_resolved")

        reports[pattern] = {
            "detected_callsites": len({row.callsite_key for row in rows}),
            "detected_unique_implementation_bodies": len(by_impl),
            "implementation_identity_strengths": dict(sorted(identity_strengths.items())),
            "audited_unique_implementation_bodies": len(audited_canonical),
            "inconclusive_reviewed_bodies": len(inconclusive_canonical),
            "pending_review_bodies": len(pending_impls),
            "semantic_correct": semantic_correct,
            "semantic_incorrect": semantic_incorrect,
            "semantic_precision": semantic_value,
            "parameter_correct": parameter_correct,
            "parameter_incorrect": parameter_incorrect,
            "parameter_precision": parameter_value,
            "correct_codebase_families": sorted(correct_families),
            "correct_codebase_family_count": len(correct_families),
            "enablement_status": "enabled" if not reasons else "not_enabled",
            "enablement_blockers": reasons,
        }

    stale = sorted(set(reviews) - observed_review_keys)
    return reports, pending_queue, stale


def sync_pending_labels(
    labels_path: Path,
    labels_document: dict[str, Any],
    pending: list[dict[str, Any]],
) -> int:
    existing = list(labels_document.get("reviews", []) or [])
    existing_keys = {
        str(row.get("review_key", ""))
        for row in existing
        if isinstance(row, dict)
    }
    added = 0
    for row in pending:
        if row["review_key"] not in existing_keys:
            existing.append(row)
            existing_keys.add(row["review_key"])
            added += 1
    labels_document["reviews"] = existing
    write_json(labels_path, labels_document)
    return added


def run_audit(
    manifest_path: Path,
    labels_path: Path,
    sync_pending: bool = False,
) -> tuple[dict[str, Any], int]:
    errors: list[str] = []
    warnings: list[str] = []
    try:
        manifest = read_json(manifest_path)
    except (OSError, ValueError) as exc:
        return {"status": "ERROR", "errors": [str(exc)]}, 2
    errors.extend(validate_manifest(manifest))

    thresholds = dict(DEFAULT_THRESHOLDS)
    thresholds.update(dict(manifest.get("thresholds", {}) or {}))
    patterns = [
        PATTERN_ALIASES.get(str(value).lower(), str(value).lower())
        for value in list(
            manifest.get(
                "patterns",
                [
                    "counted_range",
                    "sentinel_copy",
                    "paired_buffer_state",
                    "in_place_swap",
                ],
            )
            or []
        )
    ]
    findings, corpus, collection_errors, collection_warnings = collect_findings(
        manifest
    )
    errors.extend(collection_errors)
    warnings.extend(collection_warnings)
    reviews, labels_document = load_reviews(labels_path, errors)

    require_outputs = thresholds.get("require_all_manifest_outputs", True)
    corpus_complete = (
        not errors
        and (
            not require_outputs
            or corpus["loaded_samples"] == corpus["manifest_samples"]
        )
    )
    reports, pending, stale = evaluate_patterns(
        findings,
        reviews,
        patterns,
        thresholds,
        corpus_complete,
        errors,
    )
    if stale:
        warnings.append(
            f"{len(stale)} stale manual review keys do not match current findings"
        )
    added = 0
    if sync_pending and labels_document:
        added = sync_pending_labels(labels_path, labels_document, pending)

    result = {
        "schema_version": "ct-mini-sink-heuristic-audit-report-v1",
        "status": "ERROR" if errors else "OK",
        "manifest": str(manifest_path),
        "labels": str(labels_path),
        "thresholds": thresholds,
        "corpus_complete": corpus_complete,
        "corpus": corpus,
        "patterns": reports,
        "pending_review": pending,
        "pending_reviews_added": added,
        "stale_review_keys": stale,
        "errors": errors,
        "warnings": warnings,
    }
    return result, 2 if errors else 0


def self_test() -> None:
    findings: list[Finding] = []
    reviews: dict[str, dict[str, Any]] = {}
    for index in range(10):
        family = "family_a" if index < 5 else "family_b"
        implementation = f"body:{index:02d}"
        for callsite in range(2):
            findings.append(
                Finding(
                    sample_id=f"sample_{index:02d}",
                    codebase_family=family,
                    pattern="counted_range",
                    implementation_key=implementation,
                    identity_strength="body_hash",
                    callsite_key=f"sample_{index:02d}:site_{callsite}",
                    sink_id=f"sink_{index}_{callsite}",
                )
            )
        semantic = "correct" if index < 8 else "incorrect"
        reviews[f"counted_range|{implementation}"] = {
            "review_key": f"counted_range|{implementation}",
            "review_status": "reviewed",
            "semantic_verdict": semantic,
            "parameter_verdict": "correct" if semantic == "correct" else "not_applicable",
        }

    errors: list[str] = []
    reports, pending, stale = evaluate_patterns(
        findings,
        reviews,
        ["counted_range"],
        dict(DEFAULT_THRESHOLDS),
        True,
        errors,
    )
    report = reports["counted_range"]
    assert not errors
    assert not pending
    assert not stale
    assert report["detected_callsites"] == 20
    assert report["detected_unique_implementation_bodies"] == 10
    assert report["audited_unique_implementation_bodies"] == 10
    assert report["semantic_precision"] == 0.8
    assert report["parameter_precision"] == 1.0
    assert report["correct_codebase_family_count"] == 2
    assert report["enablement_status"] == "enabled"

    reviews.pop("counted_range|body:09")
    errors = []
    reports, pending, _ = evaluate_patterns(
        findings,
        reviews,
        ["counted_range"],
        dict(DEFAULT_THRESHOLDS),
        True,
        errors,
    )
    assert len(pending) == 1
    assert reports["counted_range"]["enablement_status"] == "not_enabled"
    assert "review_queue_not_fully_resolved" in reports["counted_range"][
        "enablement_blockers"
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument(
        "--sync-pending",
        action="store_true",
        help="Append unlabeled findings as pending_review; never creates verdicts.",
    )
    parser.add_argument(
        "--require-enabled",
        action="store_true",
        help="Exit 1 unless every configured heuristic satisfies its threshold.",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print(json.dumps({"self_test": "PASS"}, indent=2))
        return 0

    result, code = run_audit(args.manifest, args.labels, args.sync_pending)
    print(json.dumps(result, indent=2))
    if code:
        return code
    if args.require_enabled and any(
        row["enablement_status"] != "enabled"
        for row in result["patterns"].values()
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
