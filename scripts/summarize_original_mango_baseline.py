#!/usr/bin/env python3
"""Summarize an Original Mango campaign against post-analysis CVE profiles."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SUPPORTED_CALLEE_CATEGORIES = {
    "memcpy": "memcpy",
    "strcpy": "overflow",
    "strcat": "strcat",
    "sprintf": "strfmt",
    "snprintf": "strfmt",
}
MANGO_INPUT_FUNCTIONS = {
    "read",
    "fread",
    "fgets",
    "recv",
    "recvfrom",
    "custom_param_parser",
    "getenv",
    "GetValue",
    "acosNvramConfig_get",
    "acosNvramConfig_read",
    "nvram_get",
    "nvram_safe_get",
    "bcm_nvram_get",
    "envram_get",
    "wlcsm_nvram_get",
    "dni_nvram_get",
    "PTI_nvram_get",
}
SITE_RE = re.compile(r"site:[0-9a-fA-F]+:([0-9a-fA-F]+):")


def classify_run_failure(
    *,
    status: dict[str, Any] | None,
    mango_error: Any,
    log_text: str,
) -> str:
    """Classify an Original Mango failure without changing its semantics."""

    combined = "\n".join(
        (
            str(mango_error or ""),
            str((status or {}).get("failure", "")),
            log_text,
        )
    )
    if str((status or {}).get("status", "")) == "TIMEOUT" or "wall_timeout_" in combined:
        return "WALL_TIMEOUT"
    if "KeyError: 'Linux'" in combined or 'KeyError: "Linux"' in combined:
        return "ANGR_CALLING_CONVENTION_ERROR"
    if "RecursionError: maximum recursion depth exceeded" in combined:
        return "ANGR_RECURSION_ERROR"
    if "cannot pickle '_cffi_backend._CDataBase' object" in combined:
        return "VRA_MULTIPROCESSING_ERROR"
    if "VRA TIMED OUT" in combined:
        return "VRA_TIMEOUT"
    if (status or {}).get("return_code") in {137, 143} or "OOMKilled" in combined:
        return "RESOURCE_LIMIT_OR_TERMINATION"
    if str((status or {}).get("failure", "")).startswith("runner_exception:"):
        return "RUNNER_EXCEPTION"
    if mango_error:
        return "MANGO_REPORTED_ERROR"
    if status:
        return "MANGO_EXIT_WITHOUT_RESULT"
    return "NOT_RUN"


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def address(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        return None


def normalized_code_address(value: Any) -> int | None:
    parsed = address(value)
    return None if parsed is None else parsed & ~1


def endpoint_address(endpoint: dict[str, Any]) -> int | None:
    for key in ("site_id", "site_id_regex"):
        match = SITE_RE.search(str(endpoint.get(key, "")))
        if match:
            return int(match.group(1), 16) & ~1
    for key in ("callsite", "address", "ins_addr"):
        parsed = normalized_code_address(endpoint.get(key))
        if parsed is not None:
            return parsed
    return None


def has_mango_source(closure: dict[str, Any]) -> bool:
    inputs = dict(closure.get("inputs", {}) or {})
    return bool(inputs.get("likely") or inputs.get("possibly"))


def is_mango_trupoc(closure: dict[str, Any]) -> bool:
    try:
        return float(closure.get("rank", 0) or 0) >= 7.0
    except (TypeError, ValueError):
        return False


def trace_functions(closure: dict[str, Any]) -> set[str]:
    return {
        str(row.get("function", ""))
        for row in list(closure.get("trace", []) or [])
        if str(row.get("function", ""))
    }


def endpoint_matches_closure(
    endpoint: dict[str, Any], closure: dict[str, Any]
) -> bool:
    expected_callee = str(endpoint.get("callee", ""))
    if expected_callee and str(dict(closure.get("sink", {}) or {}).get("function", "")) != expected_callee:
        return False
    expected_address = endpoint_address(endpoint)
    actual_address = normalized_code_address(
        dict(closure.get("sink", {}) or {}).get("ins_addr")
    )
    if expected_address is not None:
        return actual_address == expected_address
    expected_function = str(endpoint.get("function_name", ""))
    return bool(expected_function and expected_function in trace_functions(closure))


def load_source_profiles(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.is_file():
        return {}
    return dict(read_json(path).get("profiles", {}) or {})


def source_model_status(
    source_profile: dict[str, Any] | None,
) -> str:
    if not source_profile:
        return "UNKNOWN_NO_PUBLIC_SOURCE_PROFILE"
    sources = list(source_profile.get("sources", []) or [])
    if not sources:
        return "UNKNOWN_NO_PUBLIC_SOURCE"
    for source in sources:
        if str(source.get("callee", "")) in MANGO_INPUT_FUNCTIONS:
            return "MODELED_BY_MANGO_HANDLER"
    return "NOT_MODELED_BY_MANGO_HANDLER"


def load_results(campaign_root: Path, campaign: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for item in list(campaign.get("inventory", []) or []):
        digest = str(item.get("binary_sha256", ""))
        for category in list(campaign.get("categories", []) or []):
            job_dir = campaign_root / "per_elf" / digest[:12] / category
            path = job_dir / f"{category}_results.json"
            status_path = job_dir / "run_status.json"
            log_path = job_dir / "runner.log"
            status_payload = read_json(status_path) if status_path.is_file() else None
            log_text = log_path.read_text(errors="replace") if log_path.is_file() else ""
            recorded_status = str((status_payload or {}).get("status", ""))
            # A timed-out Docker client can leave a container alive long enough
            # to write a syntactically valid partial result. The runner status is
            # authoritative, so partial output cannot promote a failed run.
            if recorded_status in {"TIMEOUT", "ANALYSIS_FAILED"}:
                rows[(digest, category)] = {
                    "status": "ANALYSIS_FAILED",
                    "closures": [],
                    "result_path": str(path),
                    "failure_reason": classify_run_failure(
                        status=status_payload,
                        mango_error=None,
                        log_text=log_text,
                    ),
                    "run_status_path": str(status_path),
                }
                continue
            if not path.is_file():
                failure_reason = classify_run_failure(
                    status=status_payload,
                    mango_error=None,
                    log_text=log_text,
                )
                rows[(digest, category)] = {
                    "status": "NOT_RUN" if failure_reason == "NOT_RUN" else "ANALYSIS_FAILED",
                    "closures": [],
                    "result_path": str(path),
                    "failure_reason": failure_reason,
                    "run_status_path": str(status_path),
                }
                continue
            try:
                payload = read_json(path)
            except (OSError, json.JSONDecodeError) as exc:
                rows[(digest, category)] = {
                    "status": "ANALYSIS_FAILED",
                    "closures": [],
                    "result_path": str(path),
                    "error": f"{type(exc).__name__}:{exc}",
                    "failure_reason": "INVALID_RESULT_JSON",
                    "run_status_path": str(status_path),
                }
                continue
            mango_error = payload.get("error")
            rows[(digest, category)] = {
                "status": "COMPLETED" if mango_error is None else "ANALYSIS_FAILED",
                "closures": list(payload.get("closures", []) or []),
                "result_path": str(path),
                "error": mango_error,
                "failure_reason": (
                    None
                    if mango_error is None
                    else classify_run_failure(
                        status=status_payload,
                        mango_error=mango_error,
                        log_text=log_text,
                    )
                ),
                "run_status_path": str(status_path),
                "cfg_time": payload.get("cfg_time"),
                "vra_time": payload.get("vra_time"),
                "mango_time": payload.get("mango_time"),
            }
    return rows


def manifest_rows(manifest: Path) -> list[dict[str, Any]]:
    rows = []
    for sample in list(read_json(manifest).get("samples", []) or []):
        row = dict(sample)
        row["dataset"] = manifest.stem
        rows.append(row)
    return rows


def summarize_dataset(
    *,
    name: str,
    samples: list[dict[str, Any]],
    results: dict[tuple[str, str], dict[str, Any]],
    source_profiles: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    unique_hashes = sorted({str(sample.get("sha256", "")) for sample in samples})
    all_closures: list[dict[str, Any]] = []
    run_status = Counter()
    analysis_failure_reasons = Counter()
    elapsed = 0.0
    for digest in unique_hashes:
        for category in sorted(set(SUPPORTED_CALLEE_CATEGORIES.values())):
            result = results.get((digest, category), {"status": "ANALYSIS_FAILED", "closures": []})
            run_status[str(result.get("status", ""))] += 1
            if str(result.get("status", "")) == "ANALYSIS_FAILED":
                analysis_failure_reasons[str(result.get("failure_reason", "UNKNOWN"))] += 1
            all_closures.extend(list(result.get("closures", []) or []))
            for key in ("cfg_time", "vra_time", "mango_time"):
                value = result.get(key)
                if isinstance(value, list):
                    elapsed += sum(float(item or 0) for item in value)
                elif isinstance(value, (int, float)):
                    elapsed += float(value)

    cve_rows: list[dict[str, Any]] = []
    endpoint_rows: list[dict[str, Any]] = []
    final_tp_closure_ids: set[tuple[str, str, str]] = set()
    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        by_cve[str(sample.get("cve", sample.get("cve_id", "")))].append(sample)

    for cve, cve_samples in sorted(by_cve.items()):
        cve_endpoints: list[dict[str, Any]] = []
        for sample in cve_samples:
            digest = str(sample.get("sha256", ""))
            profile_path = Path(str(sample.get("expected_profile_path", "")))
            profile = read_json(profile_path) if profile_path.is_file() else {"sinks": []}
            for endpoint in list(profile.get("sinks", []) or []):
                endpoint = dict(endpoint)
                callee = str(endpoint.get("callee", ""))
                category = SUPPORTED_CALLEE_CATEGORIES.get(callee)
                supported = bool(category)
                result = results.get((digest, category), {}) if category else {}
                closures = list(result.get("closures", []) or [])
                matching = [row for row in closures if endpoint_matches_closure(endpoint, row)]
                source_matching = [row for row in matching if has_mango_source(row)]
                final_matching = [row for row in source_matching if is_mango_trupoc(row)]
                for closure in final_matching:
                    sink = dict(closure.get("sink", {}) or {})
                    final_tp_closure_ids.add(
                        (digest, category or "", str(sink.get("ins_addr", "")))
                    )
                row = {
                    "cve": cve,
                    "sample_id": str(sample.get("sample_id", "")),
                    "binary_sha256": digest,
                    "sink_id": str(endpoint.get("sink_id", "")),
                    "label": str(endpoint.get("label", "")),
                    "function_name": str(endpoint.get("function_name", "")),
                    "callee": callee,
                    "category": category,
                    "supported": supported,
                    "run_status": str(result.get("status", "UNSUPPORTED")) if supported else "UNSUPPORTED",
                    "run_failure_reason": result.get("failure_reason") if supported else None,
                    "raw_matching_closures": len(matching),
                    "source_associated_matching_closures": len(source_matching),
                    "final_matching_trupocs": len(final_matching),
                }
                endpoint_rows.append(row)
                cve_endpoints.append(row)

        final_refound = any(row["final_matching_trupocs"] for row in cve_endpoints)
        static_refound = any(row["source_associated_matching_closures"] for row in cve_endpoints)
        sink_localized = any(row["raw_matching_closures"] for row in cve_endpoints)
        supported = any(row["supported"] for row in cve_endpoints)
        completed = any(row["run_status"] == "COMPLETED" for row in cve_endpoints if row["supported"])
        run_failure_reasons = sorted(
            {
                str(row["run_failure_reason"])
                for row in cve_endpoints
                if row.get("run_failure_reason")
            }
        )
        sample_id = str(cve_samples[0].get("sample_id", ""))
        model_status = source_model_status(source_profiles.get(sample_id))
        if final_refound:
            outcome = "CVE_FOUND"
        elif not supported:
            outcome = "SINK_NOT_RECOGNIZED"
        elif not completed:
            outcome = "ANALYSIS_FAILED"
        elif not sink_localized:
            outcome = "SINK_NOT_RECOGNIZED"
        elif model_status == "NOT_MODELED_BY_MANGO_HANDLER":
            outcome = "SOURCE_NOT_MODELED"
        elif model_status == "MODELED_BY_MANGO_HANDLER":
            outcome = "DATA_FLOW_INCOMPLETE"
        else:
            outcome = "DIAGNOSTIC_REQUIRED"
        cve_rows.append(
            {
                "cve": cve,
                "sample_ids": sorted(str(row.get("sample_id", "")) for row in cve_samples),
                "endpoint_count": len(cve_endpoints),
                "supported_endpoint_count": sum(bool(row["supported"]) for row in cve_endpoints),
                "sink_localized": sink_localized,
                "static_refound": static_refound,
                "final_refound": final_refound,
                "source_model_status": model_status,
                "run_failure_reasons": run_failure_reasons,
                "outcome": outcome,
            }
        )

    final_closures: list[tuple[str, str, dict[str, Any]]] = []
    raw_count = 0
    source_count = 0
    for digest in unique_hashes:
        for category in sorted(set(SUPPORTED_CALLEE_CATEGORIES.values())):
            closures = list(results.get((digest, category), {}).get("closures", []) or [])
            raw_count += len(closures)
            source_count += sum(has_mango_source(row) for row in closures)
            final_closures.extend(
                (digest, category, row) for row in closures if is_mango_trupoc(row)
            )
    final_tp = 0
    for digest, category, closure in final_closures:
        sink = dict(closure.get("sink", {}) or {})
        if (digest, category, str(sink.get("ins_addr", ""))) in final_tp_closure_ids:
            final_tp += 1
    totals = {
        "cves": len(cve_rows),
        "unique_elfs": len(unique_hashes),
        "category_runs": len(unique_hashes) * len(set(SUPPORTED_CALLEE_CATEGORIES.values())),
        "completed_category_runs": run_status.get("COMPLETED", 0),
        "analysis_failed_category_runs": run_status.get("ANALYSIS_FAILED", 0),
        "not_run_category_runs": run_status.get("NOT_RUN", 0),
        "raw_closures": raw_count,
        "source_associated_closures": source_count,
        "mango_trupocs": len(final_closures),
        "final_tp_alerts": final_tp,
        "final_fp_alerts": len(final_closures) - final_tp,
        "public_sink_endpoints": len(endpoint_rows),
        "public_sink_endpoints_supported": sum(bool(row["supported"]) for row in endpoint_rows),
        "public_sink_endpoints_localized": sum(bool(row["raw_matching_closures"]) for row in endpoint_rows),
        "static_cves_refound": sum(bool(row["static_refound"]) for row in cve_rows),
        "final_cves_refound": sum(bool(row["final_refound"]) for row in cve_rows),
        "cves_missed": sum(not bool(row["final_refound"]) for row in cve_rows),
        "native_analysis_cpu_seconds_reported": elapsed,
    }
    totals["final_precision_proxy"] = (
        final_tp / len(final_closures) if final_closures else None
    )
    return {
        "dataset": name,
        "totals": totals,
        "analysis_failure_reasons": dict(sorted(analysis_failure_reasons.items())),
        "failure_reasons": dict(sorted(Counter(row["outcome"] for row in cve_rows if not row["final_refound"]).items())),
        "cves": cve_rows,
        "endpoints": endpoint_rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign-root", required=True, type=Path)
    parser.add_argument("--development-manifest", required=True, type=Path)
    parser.add_argument("--evaluation-manifest", required=True, type=Path)
    parser.add_argument("--source-profiles", type=Path)
    parser.add_argument("--scope-manifest", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    root = args.campaign_root.resolve()
    campaign = read_json(root / "campaign.json")
    results = load_results(root, campaign)
    source_profiles = load_source_profiles(args.source_profiles)
    development_samples = manifest_rows(args.development_manifest)
    evaluation_samples = manifest_rows(args.evaluation_manifest)
    evaluated: set[str] | None = None
    if args.scope_manifest:
        scope = read_json(args.scope_manifest)
        evaluated = {
            str(row.get("cve", ""))
            for row in list(scope.get("cves", []) or [])
            if row.get("scope") == "IN_SCOPE"
            and row.get("sample_validity", "VALID") == "VALID"
        }
        development_samples = [
            row for row in development_samples if str(row.get("cve", "")) in evaluated
        ]
        evaluation_samples = [
            row for row in evaluation_samples if str(row.get("cve", "")) in evaluated
        ]
    development = summarize_dataset(
        name="Development",
        samples=development_samples,
        results=results,
        source_profiles=source_profiles,
    )
    evaluation = summarize_dataset(
        name="Evaluation",
        samples=evaluation_samples,
        results=results,
        source_profiles=source_profiles,
    )
    write_json(
        args.output,
        {
            "schema_version": "ct-mini-original-mango-public-cve-summary-v2",
            "campaign_root": str(root),
            "benchmark_fp_definition": "final Mango TruPoC not matched to an included public CVE endpoint",
            "scope": {
                "manifest": str(args.scope_manifest.resolve()) if args.scope_manifest else "",
                "evaluated_in_scope_cves": len(evaluated) if evaluated is not None else None,
            },
            "datasets": {"development": development, "evaluation": evaluation},
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
