#!/usr/bin/env python3
"""Run post-A2 Check collection and LLM review over one firmware corpus."""

from __future__ import annotations

import argparse
import asyncio
import copy
import gc
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from build_validation_queue import build_validation_queue
from check_candidate_collector import collect_canonical_alerts, read_json, write_json
from review_alerts_llm import (
    MAX_BATCH_SIZE,
    REVIEW_SCHEMA_VERSION,
    REVIEW_POLICY_VERSION,
    SourceAgentBatchRunner,
    StageInvocation,
    alert_namespaces,
    group_reviewed_alerts,
    review_enriched_batch,
)
from review_evidence_store import (
    ReviewEvidenceStore,
    prepare_sanitized_decompiled_c,
)
from run_mango_filter_corpus import _public_reproduction_ids, _represented_ids


ROOT = Path(__file__).resolve().parents[1]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _review_fingerprint(
    *,
    binary_sha256: str,
    decompiled_sha256: str,
    program_facts_sha256: str,
    enriched: list[dict[str, Any]],
    mode: str,
    model: str,
    review_settings: dict[str, Any] | None = None,
) -> str:
    payload = {
        "binary_sha256": binary_sha256,
        "decompiled_sha256": decompiled_sha256,
        "program_facts_sha256": program_facts_sha256,
        "review_policy_version": REVIEW_POLICY_VERSION,
        "mode": mode.upper(),
        "model": model if mode == "live" else "",
        "review_settings": dict(review_settings or {}),
        "enriched_alerts": enriched,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _clone_reused_review(
    reviewed: dict[str, Any], *, source_sample_id: str
) -> dict[str, Any]:
    cloned = copy.deepcopy(reviewed)
    for group in ("trupocs", "rejected_alerts", "unresolved_alerts"):
        for row in list(cloned.get(group, []) or []):
            provenance = dict(row.get("review_provenance", {}) or {})
            provenance["equivalent_review_reused"] = True
            provenance["reused_from_sample_id"] = source_sample_id
            provenance["llm_calls"] = 0
            provenance["reviewer_stage_invocations"] = 0
            row["review_provenance"] = provenance
    counts = dict(cloned.get("counts", {}) or {})
    counts["llm_calls"] = 0
    counts["reviewer_stage_invocations"] = 0
    cloned["counts"] = counts
    return cloned


def _program_facts_by_sample(input_summary: dict[str, Any]) -> dict[str, Path]:
    return {
        str(row.get("sample_id", "")): Path(str(row.get("program_facts", "")))
        for row in list(input_summary.get("samples", []) or [])
        if str(row.get("sample_id", "")) and str(row.get("program_facts", ""))
    }


def _summary_rows_by_sample(
    input_summary: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    return {
        str(row.get("sample_id", "")): dict(row)
        for row in list(input_summary.get("samples", []) or [])
        if str(row.get("sample_id", ""))
    }


def _resolve_decompiled_c_path(
    sample: dict[str, Any],
    summary_row: dict[str, Any],
    facts_path: Path | None,
) -> Path | None:
    """Resolve the corpus C artifact without relying on sample/CVE names."""

    for row in (sample, summary_row):
        for key in ("decompiled_c_path", "decompiled_c"):
            value = str(row.get(key, "") or "")
            if value:
                return Path(value)
    if facts_path is not None:
        return facts_path.parent / "plain_decompiled.c"
    return None


def _neutral_ids(manifest: dict[str, Any]) -> dict[str, str]:
    hash_to_id: dict[str, str] = {}
    result: dict[str, str] = {}
    for sample in list(manifest.get("samples", []) or []):
        sample_id = str(sample.get("sample_id", ""))
        binary_hash = str(sample.get("sha256", "") or sample_id)
        if binary_hash not in hash_to_id:
            hash_to_id[binary_hash] = f"FW{len(hash_to_id) + 1:04d}"
        if sample_id:
            result[sample_id] = hash_to_id[binary_hash]
    return result


async def _mock_batch(
    batch: list[dict[str, Any]],
    _store: ReviewEvidenceStore,
) -> StageInvocation:
    return StageInvocation(
        response={
            "schema_version": REVIEW_SCHEMA_VERSION,
            "decisions": [
                {
                    "alert_id": str(
                        dict(row.get("alert", {}) or {}).get("alert_id", "")
                    ),
                    "decision": "UNRESOLVED",
                    "dangerous_condition": "",
                    "blocking_relation": "",
                    "evidence_refs": [],
                    "missing_evidence": ["MOCK_SEMANTIC_REVIEW_NOT_PERFORMED"],
                    "reason": "mock transport validation; semantic review not performed",
                }
                for row in batch
            ],
        },
        provenance={
            "stage": "whole_alert",
            "mode": "MOCK_UNRESOLVED",
            "model_requests": 1,
        },
    )


def _validate_preflight(path: Path, expected_alias: str) -> dict[str, Any]:
    row = read_json(path)
    if str(row.get("status", "")) != "READY":
        raise RuntimeError("CLIProxy preflight is not READY")
    if str(row.get("expected_model_alias", "")) != expected_alias:
        raise RuntimeError("CLIProxy preflight does not match expected model alias")
    if not bool(row.get("exact_model_available", False)):
        raise RuntimeError("requested review model is unavailable; fallback is forbidden")
    if not bool(row.get("exact_model_callable", False)):
        raise RuntimeError("requested review model failed its exact-model completion probe")
    return row


async def _review_rows(
    enriched_rows: list[dict[str, Any]],
    *,
    base_store: ReviewEvidenceStore,
    reviewer,
    max_concurrency: int,
    max_batch_size: int,
) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(max(1, max_concurrency))
    batch_size = min(MAX_BATCH_SIZE, max(1, max_batch_size))
    batches = [
        enriched_rows[index : index + batch_size]
        for index in range(0, len(enriched_rows), batch_size)
    ]

    def execution_failed(batch_rows: list[dict[str, Any]]) -> bool:
        return bool(batch_rows) and all(
            str(row.get("review_status", "")) == "UNRESOLVED"
            and "REVIEW_EXECUTION_FAILED"
            in set(
                str(value)
                for value in list(
                    dict(row.get("whole_review", {}) or {}).get(
                        "missing_evidence", []
                    )
                    or []
                )
            )
            for row in batch_rows
        )

    async def run_batch(
        batch: list[dict[str, Any]], *, split_depth: int = 0
    ) -> list[dict[str, Any]]:
        batch_rows = await review_enriched_batch(
                batch,
                evidence_store=base_store.fork(
                    allowed_references_by_alert=alert_namespaces(batch)
                ),
                reviewer=reviewer,
            )
        if not execution_failed(batch_rows) or len(batch) == 1:
            for row in batch_rows:
                provenance = dict(row.get("review_provenance", {}) or {})
                provenance["adaptive_batch_split_depth"] = split_depth
                row["review_provenance"] = provenance
            return batch_rows

        failed_calls = sum(
            int(dict(row.get("review_provenance", {}) or {}).get("llm_calls", 0) or 0)
            for row in batch_rows
        )
        failed_stages = sum(
            int(
                dict(row.get("review_provenance", {}) or {}).get(
                    "reviewer_stage_invocations", 0
                )
                or 0
            )
            for row in batch_rows
        )
        midpoint = max(1, len(batch) // 2)
        split_rows = [
            *await run_batch(batch[:midpoint], split_depth=split_depth + 1),
            *await run_batch(batch[midpoint:], split_depth=split_depth + 1),
        ]
        if split_rows:
            provenance = dict(split_rows[0].get("review_provenance", {}) or {})
            provenance["llm_calls"] = int(provenance.get("llm_calls", 0) or 0) + failed_calls
            provenance["reviewer_stage_invocations"] = int(
                provenance.get("reviewer_stage_invocations", 0) or 0
            ) + failed_stages
            failures = list(provenance.get("adaptive_batch_failures", []) or [])
            failures.append(
                {
                    "split_depth": split_depth,
                    "alert_ids": [
                        str(dict(row.get("alert", {}) or {}).get("alert_id", ""))
                        for row in batch
                    ],
                    "llm_calls": failed_calls,
                    "reviewer_stage_invocations": failed_stages,
                }
            )
            provenance["adaptive_batch_failures"] = failures
            split_rows[0]["review_provenance"] = provenance
        return split_rows

    async def one(batch: list[dict[str, Any]]) -> list[dict[str, Any]]:
        async with semaphore:
            return await run_batch(batch)

    grouped = list(await asyncio.gather(*(one(batch) for batch in batches)))
    return [row for batch_rows in grouped for row in batch_rows]


def _reviewed_ids(rows: list[dict[str, Any]]) -> set[str]:
    return _represented_ids(
        [dict(row.get("alert", {}) or {}) for row in rows]
    )


def _assert_complete_review(
    enriched_rows: list[dict[str, Any]], reviewed: dict[str, Any]
) -> None:
    expected = [
        str(dict(row.get("alert", {}) or {}).get("alert_id", ""))
        for row in enriched_rows
    ]
    reviewed_rows = [
        *list(reviewed.get("trupocs", []) or []),
        *list(reviewed.get("rejected_alerts", []) or []),
        *list(reviewed.get("unresolved_alerts", []) or []),
    ]
    actual = [
        str(dict(row.get("alert", {}) or {}).get("alert_id", ""))
        for row in reviewed_rows
    ]
    if not all(expected) or len(expected) != len(set(expected)):
        raise RuntimeError("A2 canonical Alerts must have unique nonempty alert IDs")
    if not all(actual) or len(actual) != len(set(actual)):
        raise RuntimeError("review outcomes must have unique nonempty alert IDs")
    if set(expected) != set(actual):
        missing = sorted(set(expected) - set(actual))
        unexpected = sorted(set(actual) - set(expected))
        raise RuntimeError(
            "review partition is incomplete: "
            f"missing={missing[:8]} unexpected={unexpected[:8]}"
        )


def _is_review_execution_failure(row: dict[str, Any]) -> bool:
    return (
        str(row.get("review_status", "")) == "UNRESOLVED"
        and "REVIEW_EXECUTION_FAILED"
        in {
            str(value)
            for value in list(
                dict(row.get("whole_review", {}) or {}).get(
                    "missing_evidence", []
                )
                or []
            )
        }
    )


def _merge_execution_failure_retries(
    prior_rows: list[dict[str, Any]],
    retried_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Replace transport/protocol failures while retaining their audit cost."""

    failed = [row for row in prior_rows if _is_review_execution_failure(row)]
    failed_ids = {
        str(dict(row.get("alert", {}) or {}).get("alert_id", "")) for row in failed
    }
    retry_ids = {
        str(dict(row.get("alert", {}) or {}).get("alert_id", ""))
        for row in retried_rows
    }
    if failed_ids != retry_ids:
        raise RuntimeError("execution-failure retry IDs do not match prior failures")
    kept = [row for row in prior_rows if not _is_review_execution_failure(row)]
    if retried_rows and failed:
        prior_calls = sum(
            int(dict(row.get("review_provenance", {}) or {}).get("llm_calls", 0) or 0)
            for row in failed
        )
        prior_stages = sum(
            int(
                dict(row.get("review_provenance", {}) or {}).get(
                    "reviewer_stage_invocations", 0
                )
                or 0
            )
            for row in failed
        )
        provenance = dict(retried_rows[0].get("review_provenance", {}) or {})
        provenance["llm_calls"] = int(provenance.get("llm_calls", 0) or 0) + prior_calls
        provenance["reviewer_stage_invocations"] = int(
            provenance.get("reviewer_stage_invocations", 0) or 0
        ) + prior_stages
        provenance["execution_failure_repair"] = {
            "prior_failed_alerts": len(failed),
            "prior_llm_calls": prior_calls,
            "prior_reviewer_stage_invocations": prior_stages,
        }
        retried_rows[0]["review_provenance"] = provenance
    return [*kept, *retried_rows]


def _usage_totals(reviewed: dict[str, Any]) -> dict[str, int]:
    totals = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    for bucket in ("trupocs", "rejected_alerts", "unresolved_alerts"):
        for row in list(reviewed.get(bucket, []) or []):
            provenance = dict(row.get("review_provenance", {}) or {})
            if provenance.get("batch_cost_owner") is False:
                continue
            for stage in ("whole_alert",):
                stage_row = dict(provenance.get(stage, {}) or {})
                for attempt in list(stage_row.get("attempts", []) or []):
                    usage = dict(attempt.get("usage", {}) or {})
                    for key in totals:
                        totals[key] += int(usage.get(key, 0) or 0)
    return totals


async def run_corpus(
    *,
    manifest: dict[str, Any],
    input_summary: dict[str, Any],
    static_root: Path,
    a2_root: Path,
    output_root: Path,
    workspace_root: Path,
    mode: str,
    sourceagent_root: Path,
    model: str,
    expected_model_alias: str,
    preflight_record: Path | None,
    max_concurrency: int,
    max_context_ops: int,
    max_check_candidates: int,
    reasoning_effort: str = "high",
    max_helper_depth: int = 2,
    max_batch_size: int = 4,
    validation_queue_size: int = 20,
    resume: bool = False,
    retry_execution_failures: bool = False,
) -> dict[str, Any]:
    if mode == "live":
        if not preflight_record:
            raise RuntimeError("live mode requires --preflight-record")
        preflight = _validate_preflight(preflight_record, expected_model_alias)
    else:
        preflight = {"status": "MOCK", "exact_model_available": False}

    facts_by_sample = _program_facts_by_sample(input_summary)
    summary_rows_by_sample = _summary_rows_by_sample(input_summary)
    neutral_by_sample = _neutral_ids(manifest)
    samples: list[dict[str, Any]] = []
    totals = {
        "samples_requested": 0,
        "samples_completed": 0,
        "samples_resumed": 0,
        "execution_failure_alerts_retried": 0,
        "equivalent_reviews_reused": 0,
        "a2_canonical": 0,
        "alerts_with_checks": 0,
        "check_candidates": 0,
        "collection_truncated": 0,
        "review_completed": 0,
        "trupocs": 0,
        "rejected": 0,
        "unresolved": 0,
        "validation_queue": 0,
        "reviewer_stage_invocations": 0,
        "review_batches": 0,
        "llm_calls": 0,
        "public_cves_reproduced_before_review": 0,
        "public_cves_retained_as_trupoc": 0,
        "public_cves_retained_after_review": 0,
        "public_cves_unresolved_after_review": 0,
    }
    workspace_manifest: list[dict[str, Any]] = []
    # Keep equivalent-review reuse disk-backed. Full reviewed artifacts can be
    # several MiB each once every canonical Alert is reviewed, so retaining a
    # deep copy per firmware causes corpus-scale memory growth.
    review_cache: dict[str, tuple[str, Path]] = {}

    for sample in list(manifest.get("samples", []) or []):
        totals["samples_requested"] += 1
        started = time.monotonic()
        sample_id = str(sample.get("sample_id", ""))
        neutral_id = neutral_by_sample.get(sample_id, "")
        facts_path = facts_by_sample.get(sample_id)
        decompiled_path = _resolve_decompiled_c_path(
            sample,
            summary_rows_by_sample.get(sample_id, {}),
            facts_path,
        )
        summary_row = summary_rows_by_sample.get(sample_id, {})
        static_artifact_dir = str(sample.get("static_artifact_dir", "") or "")
        if not static_artifact_dir:
            artifact_path = str(summary_row.get("artifact_path", "") or "")
            if artifact_path:
                static_artifact_dir = str(Path(artifact_path).parent)
        static_dir = (
            Path(static_artifact_dir)
            if static_artifact_dir
            else static_root / "per_sample" / sample_id
        )
        a2_artifact_path = str(sample.get("a2_artifact_path", "") or "")
        a2_path = (
            Path(a2_artifact_path)
            if a2_artifact_path
            else a2_root / "per_sample" / sample_id / "alert_filter.json"
        )
        review_paths = {
            "a2": a2_path,
            "chains": static_dir / "chains.json",
            "sinks": static_dir / "sinks.json",
            "program_facts": facts_path,
            "decompiled_c": decompiled_path,
        }
        public_match_path = static_dir / "public_match.json"
        missing = [
            f"{name}:{path if path is not None else '<unresolved>'}"
            for name, path in {
                **review_paths,
                "public_match": public_match_path,
            }.items()
            if path is None or not path.is_file()
        ]
        if missing:
            samples.append(
                {
                    "sample_id": sample_id,
                    "status": "INPUT_MISSING",
                    "missing": missing,
                }
            )
            continue

        assert facts_path is not None
        assert decompiled_path is not None
        neutral_code = workspace_root / neutral_id / "decompiled.c"
        try:
            code_meta = prepare_sanitized_decompiled_c(decompiled_path, neutral_code)
        except Exception as exc:  # noqa: BLE001 - sanitizer failure is explicit.
            samples.append(
                {
                    "sample_id": sample_id,
                    "status": "SANITIZATION_FAILED",
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
            continue
        program_facts = read_json(facts_path)
        a2_doc = read_json(review_paths["a2"])
        chains_doc = read_json(review_paths["chains"])
        sinks_doc = read_json(review_paths["sinks"])
        enriched = collect_canonical_alerts(
            a2_doc,
            chains_doc=chains_doc,
            sinks_doc=sinks_doc,
            program_facts=program_facts,
            max_context_ops=max_context_ops,
            max_check_candidates=max_check_candidates,
            max_helper_depth=max_helper_depth,
        )
        base_store = ReviewEvidenceStore(
            neutral_firmware_id=neutral_id,
            decompiled_c_path=neutral_code,
            program_facts=program_facts,
        )
        reviewed_path = (
            output_root / "per_sample" / sample_id / "reviewed_alerts.json"
        )
        review_input_hashes = {
            key: _sha256_file(path) for key, path in review_paths.items()
        }
        review_fingerprint = _review_fingerprint(
            binary_sha256=str(sample.get("sha256", "") or ""),
            decompiled_sha256=code_meta["sha256"],
            program_facts_sha256=review_input_hashes["program_facts"],
            enriched=enriched,
            mode=mode,
            model=model,
            review_settings={
                "max_context_ops": max_context_ops,
                "max_check_candidates": max_check_candidates,
                "max_helper_depth": max_helper_depth,
                "max_batch_size": max_batch_size,
                "reasoning_effort": reasoning_effort,
            },
        )
        resumed = resume and reviewed_path.is_file()
        reused_equivalent = False
        if resumed:
            reviewed = read_json(reviewed_path)
            prior_run = dict(reviewed.get("run", {}) or {})
            if str(prior_run.get("review_policy_version", "")) != REVIEW_POLICY_VERSION:
                raise RuntimeError(
                    f"resume review policy mismatch for {sample_id}: "
                    f"{prior_run.get('review_policy_version')} != {REVIEW_POLICY_VERSION}"
                )
            if str(prior_run.get("mode", "")) != mode.upper():
                raise RuntimeError(
                    f"resume mode mismatch for {sample_id}: "
                    f"{prior_run.get('mode')} != {mode.upper()}"
                )
            if mode == "live" and str(
                prior_run.get("expected_model_alias", "")
            ) != expected_model_alias:
                raise RuntimeError(
                    f"resume model mismatch for {sample_id}"
                )
            if str(prior_run.get("review_fingerprint", "")) != review_fingerprint:
                raise RuntimeError(
                    f"resume input fingerprint mismatch for {sample_id}"
                )
            rows = [
                *list(reviewed.get("trupocs", []) or []),
                *list(reviewed.get("rejected_alerts", []) or []),
                *list(reviewed.get("unresolved_alerts", []) or []),
            ]
            failed_rows = [row for row in rows if _is_review_execution_failure(row)]
            if retry_execution_failures and failed_rows:
                failed_ids = {
                    str(dict(row.get("alert", {}) or {}).get("alert_id", ""))
                    for row in failed_rows
                }
                retry_enriched = [
                    row
                    for row in enriched
                    if str(dict(row.get("alert", {}) or {}).get("alert_id", ""))
                    in failed_ids
                ]
                if mode == "live":
                    reviewer = SourceAgentBatchRunner(
                        sourceagent_root=sourceagent_root,
                        model=model,
                        reasoning_effort=reasoning_effort,
                    )
                else:
                    reviewer = _mock_batch
                retried_rows = await _review_rows(
                    retry_enriched,
                    base_store=base_store,
                    reviewer=reviewer,
                    max_concurrency=max_concurrency,
                    max_batch_size=max_batch_size,
                )
                rows = _merge_execution_failure_retries(rows, retried_rows)
                reviewed = group_reviewed_alerts(rows)
                reviewed["firmware"] = {
                    "neutral_id": neutral_id,
                    "binary_sha256": str(sample.get("sha256", "") or ""),
                }
                reviewed["run"] = prior_run
                reviewed["run"]["execution_failure_alerts_retried"] = len(
                    failed_rows
                )
                totals["execution_failure_alerts_retried"] += len(failed_rows)
            totals["samples_resumed"] += 1
        elif review_fingerprint in review_cache:
            source_sample_id, cached_path = review_cache[review_fingerprint]
            reviewed = _clone_reused_review(
                read_json(cached_path), source_sample_id=source_sample_id
            )
            rows = [
                *list(reviewed.get("trupocs", []) or []),
                *list(reviewed.get("rejected_alerts", []) or []),
                *list(reviewed.get("unresolved_alerts", []) or []),
            ]
            reused_equivalent = True
            totals["equivalent_reviews_reused"] += 1
        else:
            if mode == "live":
                reviewer = SourceAgentBatchRunner(
                    sourceagent_root=sourceagent_root,
                    model=model,
                    reasoning_effort=reasoning_effort,
                )
            else:
                reviewer = _mock_batch
            rows = await _review_rows(
                enriched,
                base_store=base_store,
                reviewer=reviewer,
                max_concurrency=max_concurrency,
                max_batch_size=max_batch_size,
            )
            if mode == "mock":
                for row in rows:
                    provenance = dict(row.get("review_provenance", {}) or {})
                    simulated = int(
                        provenance.get("reviewer_stage_invocations", 0) or 0
                    )
                    provenance["mock_stage_invocations"] = simulated
                    provenance["llm_calls"] = 0
                    row["review_provenance"] = provenance
            reviewed = group_reviewed_alerts(rows)
            simulated_invocations = sum(
                int(
                    dict(row.get("review_provenance", {}) or {}).get(
                        "mock_stage_invocations", 0
                    )
                    or 0
                )
                for row in rows
            )
            if mode == "mock":
                reviewed["counts"]["reviewer_stage_invocations"] = simulated_invocations
            reviewed["firmware"] = {
                "neutral_id": neutral_id,
                "binary_sha256": str(sample.get("sha256", "") or ""),
            }
            reviewed["run"] = {
                "mode": mode.upper(),
                "review_policy_version": REVIEW_POLICY_VERSION,
                "model_requested": model if mode == "live" else "",
                "expected_model_alias": expected_model_alias if mode == "live" else "",
                "preflight": preflight,
                "review_settings": {
                    "max_context_ops": max_context_ops,
                    "max_check_candidates": max_check_candidates,
                    "max_helper_depth": max_helper_depth,
                    "max_batch_size": max_batch_size,
                    "validation_queue_size": validation_queue_size,
                    "reasoning_effort": reasoning_effort,
                },
                # Public CVE evidence is deliberately absent. It is read only by
                # the post-review evaluation below and never enters an LLM packet.
                "review_inputs": review_input_hashes,
                "usage": _usage_totals(reviewed),
            }
        reviewed["firmware"] = {
            "neutral_id": neutral_id,
            "binary_sha256": str(sample.get("sha256", "") or ""),
        }
        reviewed_run = dict(reviewed.get("run", {}) or {})
        reviewed_run.update(
            {
                "mode": mode.upper(),
                "review_policy_version": REVIEW_POLICY_VERSION,
                "model_requested": model if mode == "live" else "",
                "expected_model_alias": expected_model_alias if mode == "live" else "",
                "reasoning_effort": reasoning_effort if mode == "live" else "",
                "preflight": preflight,
                "review_inputs": review_input_hashes,
                "review_fingerprint": review_fingerprint,
                "equivalent_review_reused": reused_equivalent,
                "usage": _usage_totals(reviewed),
            }
        )
        reviewed["run"] = reviewed_run
        _assert_complete_review(enriched, reviewed)
        reviewed["validation_queue"] = build_validation_queue(
            list(reviewed.get("trupocs", []) or []),
            limit=max(0, validation_queue_size),
        )
        reviewed_counts = dict(reviewed.get("counts", {}) or {})
        reviewed_counts["validation_queue"] = len(reviewed["validation_queue"])
        reviewed["counts"] = reviewed_counts
        write_json(reviewed_path, reviewed)
        review_cache.setdefault(review_fingerprint, (sample_id, reviewed_path))

        public_ids = _public_reproduction_ids(
            chains_doc, read_json(public_match_path)
        )
        canonical_ids = _represented_ids(
            list(a2_doc.get("canonical_alerts", []) or [])
        )
        trupoc_ids = _reviewed_ids(list(reviewed.get("trupocs", []) or []))
        unresolved_ids = _reviewed_ids(
            list(reviewed.get("unresolved_alerts", []) or [])
        )
        reproduced = bool(public_ids & canonical_ids)
        retained_as_trupoc = bool(public_ids & trupoc_ids)
        retained_unresolved = bool(public_ids & unresolved_ids)
        retained_after_review = retained_as_trupoc or retained_unresolved
        check_count = sum(
            int(dict(row.get("check_evidence", {}) or {}).get("check_candidate_count", 0) or 0)
            for row in enriched
        )
        with_checks = sum(
            int(dict(row.get("check_evidence", {}) or {}).get("check_candidate_count", 0) or 0) > 0
            for row in enriched
        )
        truncated = sum(
            str(dict(row.get("check_evidence", {}) or {}).get("collection_status", "")) != "COMPLETE"
            for row in enriched
        )
        sample_row = {
            "sample_id": sample_id,
            "status": "OK",
            "neutral_firmware_id": neutral_id,
            "a2_canonical": len(enriched),
            "alerts_with_checks": with_checks,
            "check_candidates": check_count,
            "collection_truncated": truncated,
            "review_batches": (
                (len(enriched) + min(MAX_BATCH_SIZE, max_batch_size) - 1)
                // min(MAX_BATCH_SIZE, max_batch_size)
                if enriched
                else 0
            ),
            **reviewed["counts"],
            "public_cve_reproduced_before_review": reproduced,
            "public_cve_retained_as_trupoc": retained_as_trupoc,
            "public_cve_retained_after_review": retained_after_review,
            "public_cve_unresolved_after_review": retained_unresolved,
            "equivalent_review_reused": reused_equivalent,
            "runtime_seconds": round(time.monotonic() - started, 3),
        }
        samples.append(sample_row)
        totals["samples_completed"] += 1
        totals["a2_canonical"] += len(enriched)
        totals["alerts_with_checks"] += with_checks
        totals["check_candidates"] += check_count
        totals["collection_truncated"] += truncated
        totals["review_batches"] += int(sample_row["review_batches"])
        totals["review_completed"] += int(reviewed["counts"]["reviewed"])
        totals["trupocs"] += int(reviewed["counts"]["trupocs"])
        totals["rejected"] += int(reviewed["counts"]["rejected"])
        totals["unresolved"] += int(reviewed["counts"]["unresolved"])
        totals["validation_queue"] += int(
            reviewed["counts"]["validation_queue"]
        )
        totals["reviewer_stage_invocations"] += int(
            reviewed["counts"]["reviewer_stage_invocations"]
        )
        totals["llm_calls"] += int(reviewed["counts"]["llm_calls"])
        totals["public_cves_reproduced_before_review"] += int(reproduced)
        totals["public_cves_retained_as_trupoc"] += int(retained_as_trupoc)
        totals["public_cves_retained_after_review"] += int(retained_after_review)
        totals["public_cves_unresolved_after_review"] += int(retained_unresolved)
        workspace_manifest.append(
            {
                "neutral_firmware_id": neutral_id,
                "binary_sha256": str(sample.get("sha256", "") or ""),
                "decompiled_c_sha256": code_meta["sha256"],
            }
        )
        print(
            json.dumps(
                {
                    "event": "sample_review_complete",
                    "sample_id": sample_id,
                    "completed": totals["samples_completed"],
                    "requested": len(list(manifest.get("samples", []) or [])),
                    "trupocs": sample_row["trupocs"],
                    "rejected": sample_row["rejected"],
                    "unresolved": sample_row["unresolved"],
                    "llm_calls": sample_row["llm_calls"],
                    "resumed": resumed,
                    "equivalent_review_reused": reused_equivalent,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        # ProgramFacts and evidence slices are intentionally sample-local.
        # Release cyclic containers before loading the next firmware image.
        del base_store, program_facts, a2_doc, chains_doc, sinks_doc, enriched
        del reviewed, rows
        gc.collect()

    pipeline = "\n".join(
        [
            f"A2 Canonical Alerts [{totals['a2_canonical']}]",
            f"  -> Check Candidate Collection [checks={totals['check_candidates']}, alerts-with-checks={totals['alerts_with_checks']}]",
            (
                "  -> Whole-Alert LLM Review "
                f"[batches={totals['review_batches']}, "
                f"stage invocations={totals['reviewer_stage_invocations']}, "
                f"real model calls={totals['llm_calls']}]"
            ),
            f"  -> TruPoCs [{totals['trupocs']}]",
            f"     Rejected [{totals['rejected']}]",
            f"     Unresolved retained [{totals['unresolved']}]",
            (
                "  -> Post-review Validation Queue "
                f"[selected={totals['validation_queue']}, "
                f"Top-{max(0, validation_queue_size)} per firmware]"
            ),
        ]
    )
    complete = (
        totals["samples_completed"] == totals["samples_requested"]
        and totals["review_completed"] == totals["a2_canonical"]
    )
    summary = {
        "schema_version": "ct-mini-check-review-corpus-v4",
        "mode": mode.upper(),
        "status": "COMPLETE" if complete else "INCOMPLETE",
        "counts": totals,
        "pipeline": pipeline,
        "samples": samples,
    }
    write_json(output_root / "summary.json", summary)
    (output_root / "pipeline.txt").write_text(pipeline + "\n", encoding="utf-8")
    write_json(
        workspace_root / "workspace_manifest.json",
        {
            "schema_version": "ct-mini-sanitized-review-workspace-v1",
            "firmwares": workspace_manifest,
        },
    )
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--input-summary", required=True, type=Path)
    parser.add_argument("--static-root", required=True, type=Path)
    parser.add_argument("--a2-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--mode", choices=["mock", "live"], default="mock")
    parser.add_argument("--sourceagent-root", type=Path, default=ROOT)
    parser.add_argument("--model", default="openai/gpt-5.6-sol")
    parser.add_argument("--expected-model-alias", default="gpt-5.6-sol")
    parser.add_argument(
        "--reasoning-effort",
        choices=["low", "medium", "high", "xhigh"],
        default="high",
    )
    parser.add_argument("--preflight-record", type=Path, default=None)
    parser.add_argument("--max-concurrency", type=int, default=4)
    parser.add_argument("--max-context-ops", type=int, default=128)
    parser.add_argument("--max-check-candidates", type=int, default=16)
    parser.add_argument("--max-helper-depth", type=int, default=2)
    parser.add_argument("--max-batch-size", type=int, default=1)
    parser.add_argument("--validation-queue-size", type=int, default=20)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--retry-execution-failures", action="store_true")
    args = parser.parse_args()
    summary = asyncio.run(
        run_corpus(
            manifest=read_json(args.manifest),
            input_summary=read_json(args.input_summary),
            static_root=args.static_root,
            a2_root=args.a2_root,
            output_root=args.out,
            workspace_root=args.workspace,
            mode=args.mode,
            sourceagent_root=args.sourceagent_root,
            model=args.model,
            expected_model_alias=args.expected_model_alias,
            preflight_record=args.preflight_record,
            max_concurrency=max(1, args.max_concurrency),
            max_context_ops=max(1, args.max_context_ops),
            max_check_candidates=max(1, args.max_check_candidates),
            reasoning_effort=args.reasoning_effort,
            max_helper_depth=max(0, args.max_helper_depth),
            max_batch_size=min(MAX_BATCH_SIZE, max(1, args.max_batch_size)),
            validation_queue_size=max(0, args.validation_queue_size),
            resume=bool(args.resume),
            retry_execution_failures=bool(args.retry_execution_failures),
        )
    )
    print(json.dumps(summary["counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
