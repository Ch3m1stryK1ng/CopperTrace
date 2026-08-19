#!/usr/bin/env python3
"""Evaluate CopperTrace Mini sink mining against public CVE sink profiles.

This evaluates sink mining only. It does not evaluate source reachability,
guard correctness, exploitability, or runtime validation.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any


MINI_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = MINI_ROOT / "datasets/source_mining_direct_taint_no_microbench.json"
DEFAULT_EXPECTED_PROFILE_ROOT = MINI_ROOT / "datasets/public_expected_sinks"
DEFAULT_OUTPUT = MINI_ROOT / "artifacts/eval_cve_sink_mining"
DEFAULT_FACTS_CACHE = MINI_ROOT / "artifacts/ghidra_source_facts_cache"
BUILD_SCRIPT = MINI_ROOT / "scripts/build_sink_artifacts.py"

MINI_LABELS = {
    "COPY_SINK",
    "MEMSET_SINK",
    "STORE_SINK",
    "LOOP_WRITE_SINK",
    "FORMAT_STRING_SINK",
    "FUNC_PTR_SINK",
    "LIFETIME_SINK",
}


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(errors="replace"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")


def sample_id_from_gt(gt: dict[str, Any], fallback: str) -> str:
    return str(gt.get("sample_id") or gt.get("sample_meta", {}).get("sample_id") or fallback)


def is_trigger_chain(chain: dict[str, Any]) -> bool:
    return (
        str(chain.get("expected_final_verdict", "")).upper() == "CONFIRMED"
        or str(chain.get("expected_verdict", "")).upper() == "CONFIRMED"
        or str(chain.get("expected_final_risk_band", "")).upper() == "HIGH"
        or str(chain.get("expected_review_priority", "")).upper() == "P0"
    )


def sink_label_for_match(sink: dict[str, Any]) -> str:
    hint = str(sink.get("pipeline_label_hint") or "").strip()
    label = str(sink.get("label") or "").strip()
    if hint in MINI_LABELS:
        return hint
    if label in MINI_LABELS:
        return label
    return hint or label


def unique_expected_sinks(gt: dict[str, Any], *, trigger_only: bool) -> list[dict[str, Any]]:
    sinks_by_id = {str(s.get("sink_id", "")): s for s in list(gt.get("sinks", []) or [])}
    chains = list(gt.get("chains", []) or [])
    if trigger_only:
        chains = [c for c in chains if is_trigger_chain(c)]

    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for chain in chains:
        sink_id = str(chain.get("sink_id", ""))
        if not sink_id or sink_id in seen:
            continue
        sink = dict(sinks_by_id.get(sink_id, {}))
        if not sink:
            sink = {"sink_id": sink_id}
        sink["chain_ids"] = [
            str(c.get("chain_id", ""))
            for c in chains
            if str(c.get("sink_id", "")) == sink_id and str(c.get("chain_id", ""))
        ]
        sink["trigger_chain"] = any(
            is_trigger_chain(c) for c in list(gt.get("chains", []) or []) if str(c.get("sink_id", "")) == sink_id
        )
        sink["match_label"] = sink_label_for_match(sink)
        seen.add(sink_id)
        out.append(sink)
    return out


def selected_by_focus(sample: dict[str, Any], focus: str) -> bool:
    if focus in {"", "all", "*"}:
        return True
    raw = sample.get("eval_focus", "")
    if isinstance(raw, list):
        return focus in {str(item) for item in raw}
    return str(raw) == focus


def optional_path(raw: Any) -> Path | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    return Path(text)


def find_decompiled(sample: dict[str, Any]) -> Path | None:
    override = optional_path(sample.get("decompiled_c_path"))
    if override and override.exists():
        return override
    return None


def run_mini(
    sample: dict[str, Any], decompiled: Path, program_facts: Path, out_dir: Path
) -> dict[str, Any]:
    sinks_json = out_dir / "sinks.json"
    unconfirmed_json = out_dir / "sink_unconfirmed.json"
    log_path = out_dir / "run.log"
    cmd = [
        "python3",
        str(BUILD_SCRIPT),
        "--input",
        str(decompiled),
        "--sinks-json",
        str(sinks_json),
        "--sink-unconfirmed-json",
        str(unconfirmed_json),
        "--elf",
        str(sample.get("binary_path", "")),
        "--program-facts",
        str(program_facts),
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()
    proc = subprocess.run(cmd, cwd=str(MINI_ROOT), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    elapsed = time.time() - started
    log_path.write_text(
        "CMD: " + " ".join(cmd) + "\n\nSTDOUT:\n" + proc.stdout + "\nSTDERR:\n" + proc.stderr
    )
    return {
        "returncode": proc.returncode,
        "runtime_seconds": elapsed,
        "sinks_json": str(sinks_json),
        "sink_unconfirmed_json": str(unconfirmed_json),
        "run_log": str(log_path),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def reuse_mini_artifacts(out_dir: Path) -> dict[str, Any]:
    sinks_json = out_dir / "sinks.json"
    unconfirmed_json = out_dir / "sink_unconfirmed.json"
    return {
        "returncode": 0,
        "runtime_seconds": None,
        "sinks_json": str(sinks_json),
        "sink_unconfirmed_json": str(unconfirmed_json),
        "run_log": "",
        "stdout": "",
        "stderr": "",
        "reused_existing_artifacts": True,
    }


def labels_compatible(expected_label: str, observed_label: str) -> bool:
    if not expected_label:
        return True
    return expected_label == observed_label


def row_matches_expected_site(expected: dict[str, Any], row: dict[str, Any]) -> bool:
    callee = str(expected.get("callee") or "").strip()
    if callee and str(row.get("callee") or "") != callee:
        return False

    expr = str(row.get("expr") or row.get("callsite") or "")
    all_terms = [str(v) for v in (expected.get("expr_contains_all") or []) if str(v)]
    if any(term not in expr for term in all_terms):
        return False

    any_terms = [str(v) for v in (expected.get("expr_contains_any") or []) if str(v)]
    if any_terms and not any(term in expr for term in any_terms):
        return False

    expr_regex = str(expected.get("expr_regex") or "").strip()
    if expr_regex:
        try:
            if re.search(expr_regex, expr) is None:
                return False
        except re.error:
            return False

    site_regex = str(expected.get("site_id_regex") or "").strip()
    if site_regex:
        try:
            if re.search(site_regex, str(row.get("site_id", ""))) is None:
                return False
        except re.error:
            return False

    return True


def expected_has_site_filter(expected: dict[str, Any]) -> bool:
    return any(
        expected.get(key)
        for key in (
            "callee", "expr_contains_all", "expr_contains_any", "expr_regex",
            "site_id_regex",
        )
    )


def deterministic_sink_views(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Expose canonical effects and proved wrapper boundaries to the evaluator."""

    out: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("decision", "")) != "ACCEPT_DETERMINISTIC":
            continue
        out.append(dict(row))
        for boundary in list(row.get("boundary_callsites", []) or []):
            view = dict(row)
            view.update(dict(boundary))
            view["id"] = str(row.get("id", ""))
            view["decision"] = "ACCEPT_DETERMINISTIC"
            view["label"] = str(row.get("label", ""))
            view["matched_via"] = "body_derived_boundary"
            out.append(view)
    return out


def match_expected_sink(
    expected: dict[str, Any],
    confirmed: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    expected_function = str(expected.get("function_name") or "")
    expected_label = str(expected.get("match_label") or "")
    has_site_filter = expected_has_site_filter(expected)

    same_function = [row for row in confirmed if str(row.get("function", "")) == expected_function]
    same_site = [row for row in same_function if row_matches_expected_site(expected, row)]
    site_scope = same_site if has_site_filter else same_function
    same_function_label = [
        row for row in site_scope if labels_compatible(expected_label, str(row.get("label", "")))
    ]
    same_function_candidates = [
        row for row in candidates if str(row.get("function", "")) == expected_function
    ]
    if has_site_filter:
        same_function_candidates = [
            row for row in same_function_candidates if row_matches_expected_site(expected, row)
        ]

    if same_function_label:
        with_roles = [row for row in same_function_label if row.get("roles")]
        best = with_roles[0] if with_roles else same_function_label[0]
        status = "CONFIRMED_ROLE_MATCH" if with_roles else "CONFIRMED_MATCH"
        return {
            "status": status,
            "confirmed": True,
            "need_confirmation": False,
            "role_match": bool(with_roles),
            "matched_sink": best,
            "notes": "function and label match; role_match requires non-empty MINI roles",
        }

    if same_function_candidates:
        return {
            "status": "NEED_CONFIRMATION",
            "confirmed": False,
            "need_confirmation": True,
            "role_match": False,
            "matched_candidate": same_function_candidates[0],
            "notes": "expected sink function/site appears in sink_unconfirmed.json",
        }

    note = "no confirmed or need-confirmation MINI sink in expected function/site"
    if same_function:
        note = (
            "confirmed sinks exist in the expected function, but none match the "
            f"expected label/site: expected={expected_label}; site_filter={has_site_filter}"
        )

    return {
        "status": "MISS",
        "confirmed": False,
        "need_confirmation": False,
        "role_match": False,
        "notes": note,
    }


def evaluate_scope(
    expected_sinks: list[dict[str, Any]],
    confirmed: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    rows = []
    for expected in expected_sinks:
        match = match_expected_sink(expected, confirmed, candidates)
        rows.append({"expected_sink": expected, "match": match})

    total = len(rows)
    confirmed = sum(1 for r in rows if r["match"].get("confirmed"))
    need_confirmation = sum(1 for r in rows if r["match"].get("need_confirmation"))
    role = sum(1 for r in rows if r["match"].get("role_match"))
    miss = total - confirmed - need_confirmation
    return {
        "expected_sink_count": total,
        "confirmed": confirmed,
        "need_confirmation": need_confirmation,
        "miss": miss,
        "role_match": role,
        "confirmed_rate": confirmed / total if total else None,
        "candidate_inclusive_rate": (confirmed + need_confirmation) / total if total else None,
        "role_match_rate_among_confirmed": role / confirmed if confirmed else None,
        "matches": rows,
    }


def pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value * 100:.1f}%"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST, type=Path)
    parser.add_argument(
        "--expected-profile-root",
        default=DEFAULT_EXPECTED_PROFILE_ROOT,
        type=Path,
        help="Reserved for future profile discovery. The public-only manifest must provide explicit expected_profile_path for every sample.",
    )
    parser.add_argument("--out", default=DEFAULT_OUTPUT, type=Path)
    parser.add_argument("--facts-cache", default=DEFAULT_FACTS_CACHE, type=Path)
    parser.add_argument(
        "--focus",
        default=None,
        help="Legacy filter for old manifests. The main sink-mining manifest evaluates every sample by default.",
    )
    parser.add_argument(
        "--include-disabled",
        action="store_true",
        help="Attempt samples explicitly marked mini_eval_enabled=false in legacy manifests.",
    )
    parser.add_argument(
        "--reuse-existing-artifacts",
        action="store_true",
        help="Read existing per-sample sinks.json/sink_unconfirmed.json instead of rebuilding them.",
    )
    args = parser.parse_args()

    manifest = read_json(args.manifest)
    samples = list(manifest.get("samples", []) or [])
    focus = str(args.focus or manifest.get("default_focus") or "all")
    args.out.mkdir(parents=True, exist_ok=True)

    inventory = []
    gt_sink_records = []
    per_sample_results = []

    for sample in samples:
        sample_id = str(sample.get("sample_id", ""))
        expected_profile_path = optional_path(sample.get("expected_profile_path"))
        expected_profile_stem = expected_profile_path.stem if expected_profile_path else ""
        decompiled = find_decompiled(sample)
        sample_out = args.out / "per_sample" / sample_id
        enabled = bool(sample.get("mini_eval_enabled", True))
        selected = selected_by_focus(sample, focus)
        binary_path = str(sample.get("binary_path", ""))
        static_artifacts_available = bool(
            expected_profile_path
            and expected_profile_path.exists()
            and decompiled
            and Path(decompiled).exists()
        )

        entry = {
            "sample_id": sample_id,
            "cve": str(sample.get("cve") or sample_id),
            "provider": str(sample.get("provider") or ""),
            "os_or_stack": str(sample.get("os_or_stack") or ""),
            "eval_focus": sample.get("eval_focus", ""),
            "bug_class": str(sample.get("bug_class") or ""),
            "artifact_status": str(sample.get("artifact_status") or ""),
            "mini_eval_enabled": enabled,
            "selected_by_focus": selected,
            "expected_profile_stem": expected_profile_stem,
            "binary_path": binary_path,
            "expected_profile_path": str(expected_profile_path) if expected_profile_path else "",
            "decompiled_c": str(decompiled) if decompiled else "",
            "static_artifacts_available": static_artifacts_available,
            "testable": bool(selected and (enabled or args.include_disabled) and static_artifacts_available),
        }
        inventory.append(entry)

        if not selected:
            per_sample_results.append(
                {
                    "sample_id": sample_id,
                    "status": "SKIPPED_FOCUS",
                    "inventory": entry,
                    "reason": f"sample eval_focus={sample.get('eval_focus', '')!r} not selected by --focus {focus!r}",
                }
            )
            continue

        if not enabled and not args.include_disabled:
            per_sample_results.append(
                {
                    "sample_id": sample_id,
                    "status": "SKIPPED_DISABLED",
                    "inventory": entry,
                    "reason": "mini_eval_enabled is false; sample is usually pending import or pending public-evidence review",
                }
            )
            continue

        if not entry["testable"]:
            per_sample_results.append(
                {
                    "sample_id": sample_id,
                    "status": "UNTESTABLE",
                    "inventory": entry,
                    "reason": "missing explicit public expected-sink profile or decompiled C",
                }
            )
            continue

        gt = read_json(expected_profile_path)
        trigger_sinks = unique_expected_sinks(gt, trigger_only=True)
        all_chain_sinks = unique_expected_sinks(gt, trigger_only=False)
        for sink in trigger_sinks:
            gt_sink_records.append({"sample_id": sample_id, "scope": "trigger", **sink})
        for sink in all_chain_sinks:
            gt_sink_records.append({"sample_id": sample_id, "scope": "all_chains", **sink})

        if args.reuse_existing_artifacts and (sample_out / "sinks.json").exists() and (sample_out / "sink_unconfirmed.json").exists():
            run = reuse_mini_artifacts(sample_out)
        else:
            import run_mini_pipeline as pipeline

            facts_run = pipeline.prepare_full_program_facts(
                sample=sample, cache_dir=args.facts_cache, out_dir=sample_out
            )
            if int(facts_run.get("returncode", 1)) != 0:
                result = {
                    "sample_id": sample_id,
                    "status": "PROGRAM_FACTS_FAILED",
                    "inventory": entry,
                    "facts": facts_run,
                }
                write_json(sample_out / "match.json", result)
                per_sample_results.append(result)
                continue
            run = run_mini(
                sample, Path(decompiled), Path(str(facts_run["program_facts"])), sample_out
            )
        if run["returncode"] != 0:
            result = {
                "sample_id": sample_id,
                "status": "MINI_RUN_FAILED",
                "inventory": entry,
                "run": {k: v for k, v in run.items() if k not in {"stdout", "stderr"}},
                "stderr": run["stderr"][-4000:],
            }
            write_json(sample_out / "match.json", result)
            per_sample_results.append(result)
            continue

        mini_sinks = read_json(Path(run["sinks_json"]))
        if str(mini_sinks.get("schema_version", "")) != "ct-mini-deterministic-sinks-v1":
            result = {
                "sample_id": sample_id,
                "status": "INCOMPATIBLE_SINK_ARTIFACT",
                "inventory": entry,
                "reason": "standalone evaluation requires strict deterministic Sink schema",
            }
            write_json(sample_out / "match.json", result)
            per_sample_results.append(result)
            continue
        confirmed = deterministic_sink_views(
            list(mini_sinks.get("sink_startpoints", []) or [])
        )
        candidates: list[dict[str, Any]] = []

        trigger_eval = evaluate_scope(trigger_sinks, confirmed, candidates)
        all_eval = evaluate_scope(all_chain_sinks, confirmed, candidates)
        result = {
            "sample_id": sample_id,
            "status": "EVALUATED",
            "inventory": entry,
            "run": {k: v for k, v in run.items() if k not in {"stdout", "stderr"}},
            "mini_counts": mini_sinks.get("counts", {}),
            "mini_next_stage_ready": mini_sinks.get("next_stage_ready"),
            "trigger_scope": trigger_eval,
            "all_chain_scope": all_eval,
            "notes": {
                "trigger_scope_definition": (
                    "chains with expected_final_verdict=CONFIRMED, expected_verdict=CONFIRMED, "
                    "expected_final_risk_band=HIGH, or expected_review_priority=P0"
                ),
                "match_granularity": (
                    "Strict match requires a deterministic High-P-code effect or body-derived "
                    "boundary with the expected function, label, callee, and configured site text."
                ),
            },
        }
        write_json(sample_out / "match.json", result)
        per_sample_results.append(result)

    evaluated = [r for r in per_sample_results if r.get("status") == "EVALUATED"]
    trigger_eval_samples = [
        r for r in evaluated if r["trigger_scope"]["expected_sink_count"] > 0
    ]
    all_eval_samples = [
        r for r in evaluated if r["all_chain_scope"]["expected_sink_count"] > 0
    ]

    def aggregate(scope_name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
        total = sum(r[scope_name]["expected_sink_count"] for r in rows)
        confirmed = sum(r[scope_name]["confirmed"] for r in rows)
        need_confirmation = sum(r[scope_name]["need_confirmation"] for r in rows)
        role = sum(r[scope_name]["role_match"] for r in rows)
        miss = sum(r[scope_name]["miss"] for r in rows)
        return {
            "sample_count": len(rows),
            "expected_sink_count": total,
            "confirmed": confirmed,
            "need_confirmation": need_confirmation,
            "miss": miss,
            "role_match": role,
            "confirmed_rate": confirmed / total if total else None,
            "candidate_inclusive_rate": (confirmed + need_confirmation) / total if total else None,
            "role_match_rate_among_confirmed": role / confirmed if confirmed else None,
        }

    summary = {
        "schema_version": "ct-mini-cve-sink-eval-v1",
        "manifest": str(args.manifest),
        "manifest_name": str(manifest.get("manifest_name") or ""),
        "focus": focus,
        "sample_count": len(samples),
        "selected_count": sum(1 for i in inventory if i["selected_by_focus"]),
        "testable_count": sum(1 for i in inventory if i["testable"]),
        "evaluated_count": len(evaluated),
        "skipped_focus_count": sum(1 for r in per_sample_results if r.get("status") == "SKIPPED_FOCUS"),
        "skipped_disabled_count": sum(1 for r in per_sample_results if r.get("status") == "SKIPPED_DISABLED"),
        "untestable_count": sum(1 for r in per_sample_results if r.get("status") == "UNTESTABLE"),
        "failed_count": sum(1 for r in per_sample_results if r.get("status") == "MINI_RUN_FAILED"),
        "trigger_scope_aggregate": aggregate("trigger_scope", trigger_eval_samples),
        "all_chain_scope_aggregate": aggregate("all_chain_scope", all_eval_samples),
        "per_sample": [
            {
                "sample_id": r["sample_id"],
                "status": r["status"],
                "trigger_expected": r.get("trigger_scope", {}).get("expected_sink_count"),
                "trigger_confirmed": r.get("trigger_scope", {}).get("confirmed"),
                "trigger_need_confirmation": r.get("trigger_scope", {}).get("need_confirmation"),
                "trigger_miss": r.get("trigger_scope", {}).get("miss"),
                "trigger_confirmed_rate": r.get("trigger_scope", {}).get("confirmed_rate"),
                "all_expected": r.get("all_chain_scope", {}).get("expected_sink_count"),
                "all_confirmed": r.get("all_chain_scope", {}).get("confirmed"),
                "all_need_confirmation": r.get("all_chain_scope", {}).get("need_confirmation"),
                "all_miss": r.get("all_chain_scope", {}).get("miss"),
                "confirmed_sink_calls": r.get("mini_counts", {}).get("confirmed_sink_calls"),
                "unconfirmed_candidates": r.get("mini_counts", {}).get("unconfirmed_candidates"),
                "runtime_seconds": r.get("run", {}).get("runtime_seconds"),
            }
            for r in per_sample_results
        ],
    }

    write_json(args.out / "cve_samples.json", inventory)
    write_json(args.out / "cve_expected_sinks.json", gt_sink_records)
    write_json(args.out / "summary.json", summary)

    lines = [
        "# CopperTrace Mini CVE Sink Mining Evaluation",
        "",
        f"Manifest: `{args.manifest}`",
        f"Samples: {summary['sample_count']} total, "
        f"{summary['evaluated_count']} evaluated, {summary['untestable_count']} untestable, "
        f"{summary['failed_count']} failed.",
        "",
        "## Trigger Reference",
        "",
    ]
    trigger_ref = summary["trigger_scope_aggregate"]
    trigger_total = trigger_ref["expected_sink_count"]
    lines.extend(
        [
            f"- confirmed: {trigger_ref['confirmed']} / {trigger_total}",
            f"- need confirmation: {trigger_ref['need_confirmation']} / {trigger_total}",
            f"- miss: {trigger_ref['miss']} / {trigger_total}",
            "",
            "Here, `confirmed` means the public expected sink function/site and CopperTrace-compatible label appear in `sinks.json`; `need confirmation` means it appears only in `sink_unconfirmed.json`.",
            "",
        ]
    )
    lines.extend(
        [
        "## Aggregate",
        "",
        "| Scope | Samples | Expected sinks | Confirmed | Need confirmation | Miss | Confirmed rate | Candidate-inclusive rate | Role match / confirmed |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for title, key in [("Trigger", "trigger_scope_aggregate"), ("All chains", "all_chain_scope_aggregate")]:
        agg = summary[key]
        lines.append(
            f"| {title} | {agg['sample_count']} | {agg['expected_sink_count']} | "
            f"{agg['confirmed']} | {agg['need_confirmation']} | "
            f"{agg['miss']} | {pct(agg['confirmed_rate'])} | {pct(agg['candidate_inclusive_rate'])} | "
            f"{pct(agg['role_match_rate_among_confirmed'])} |"
        )

    lines.extend(
        [
            "",
            "## Per Sample",
            "",
            "| Sample | Trigger expected | Trigger confirmed/need/miss | All expected | All confirmed/need/miss | MINI confirmed | MINI need confirmation | Runtime (s) |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for row in summary["per_sample"]:
        rt = row.get("runtime_seconds")
        rt_s = f"{rt:.3f}" if isinstance(rt, (int, float)) else "n/a"
        lines.append(
            f"| {row['sample_id']} | {row.get('trigger_expected', 'n/a')} | "
            f"{row.get('trigger_confirmed', 'n/a')}/{row.get('trigger_need_confirmation', 'n/a')}/"
            f"{row.get('trigger_miss', 'n/a')} | "
            f"{row.get('all_expected', 'n/a')} | {row.get('all_confirmed', 'n/a')}/"
            f"{row.get('all_need_confirmation', 'n/a')}/"
            f"{row.get('all_miss', 'n/a')} | {row.get('confirmed_sink_calls', 'n/a')} | "
            f"{row.get('unconfirmed_candidates', 'n/a')} | {rt_s} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation Notes",
            "",
            "- This evaluates sink mining only, not vulnerability confirmation.",
            "- Confirmed means public expected function/site + expected/MINI label match in `sinks.json`.",
            "- The strict evaluator has no need-confirmation or front-LLM path.",
            "- Body-derived wrapper boundaries retain their exact High P-code callsite and primitive proof path.",
            "- The main manifest includes only samples with ELF/decompiled-C/public expected-sink profile available.",
        ]
    )
    (args.out / "summary.md").write_text("\n".join(lines) + "\n")

    print(json.dumps(summary["trigger_scope_aggregate"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
