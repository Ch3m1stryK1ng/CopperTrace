#!/usr/bin/env python3
"""Post-hoc CVE matching for code-only LLM reports."""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "ct-mini-llm-only-score-v1"
ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalized(value: Any) -> str:
    return re.sub(r"[^a-z0-9_$]+", "", str(value or "").lower())


def report_matches_sink(report: dict[str, Any], expected: dict[str, Any]) -> bool:
    sink = dict(report.get("sink", {}) or {})
    expected_function = normalized(expected.get("function_name"))
    reported_function = normalized(sink.get("function"))
    if not expected_function or reported_function != expected_function:
        return False
    expected_callee = normalized(expected.get("callee"))
    if not expected_callee:
        expected_label = str(expected.get("label", "") or "")
        reported_class = str(report.get("vulnerability_class", "") or "")
        if expected_label in {"COPY_SINK", "MEMSET_SINK", "BUFFER_STATE_SINK"}:
            return reported_class in {"OOB_READ", "OOB_WRITE"}
        return expected_label == "FORMAT_SINK" and reported_class == "FORMAT_STRING"
    operation_text = normalized(
        " ".join(
            [
                str(sink.get("operation", "") or ""),
                str(sink.get("expression", "") or ""),
            ]
        )
    )
    return expected_callee in operation_text


def aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cves": len(rows),
        "cves_refound": sum(bool(row.get("refound")) for row in rows),
        "cves_missed": sum(not bool(row.get("refound")) for row in rows),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve-views", type=Path, required=True)
    parser.add_argument("--llm-root", type=Path, action="append", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--scope-manifest",
        type=Path,
        default=ROOT / "datasets/ground_truth_scope_manifest.json",
    )
    args = parser.parse_args()

    scope_rows = {
        str(row.get("cve", "")): dict(row)
        for row in list(read_json(args.scope_manifest).get("cves", []) or [])
    }
    evaluated = {
        cve for cve, row in scope_rows.items()
        if row.get("scope") == "IN_SCOPE"
        and row.get("sample_validity", "VALID") == "VALID"
    }
    reports_by_firmware: dict[str, list[dict[str, Any]]] = {}
    rows: list[dict[str, Any]] = []
    for raw_view in list(read_json(args.cve_views).get("cve_views", []) or []):
        view = dict(raw_view)
        cve = str(view.get("cve", ""))
        if cve not in evaluated:
            continue
        firmware_id = str(view["review_sample_id"])
        if firmware_id not in reports_by_firmware:
            candidates = [
                root / "per_sample" / firmware_id / "report.json"
                for root in args.llm_root
            ]
            result_path = next((path for path in candidates if path.is_file()), None)
            if result_path is None:
                raise FileNotFoundError(
                    f"missing LLM-only output for {firmware_id}: {candidates}"
                )
            result = read_json(result_path)
            reports_by_firmware[firmware_id] = list(
                dict(result.get("report", {}) or {}).get("reports", []) or []
            )
        expected_profile = read_json(Path(str(view["expected_profile_path"])))
        expected_sinks = [dict(row) for row in list(expected_profile.get("sinks", []) or [])]
        matches: list[dict[str, str]] = []
        for report in reports_by_firmware[firmware_id]:
            for expected in expected_sinks:
                if report_matches_sink(dict(report), expected):
                    matches.append(
                        {
                            "report_id": str(report.get("report_id", "") or ""),
                            "expected_sink_id": str(expected.get("sink_id", "") or ""),
                        }
                    )
        rows.append(
            {
                "corpus": view["corpus"],
                "sample_id": view["sample_id"],
                "firmware_id": firmware_id,
                "cve": cve,
                "scope": "IN_SCOPE",
                "refound": bool(matches),
                "matches": matches,
            }
        )

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped["all"].append(row)
        grouped[str(row["corpus"])].append(row)
        if row["scope"] == "IN_SCOPE":
            grouped["in_scope"].append(row)
            grouped[f"{row['corpus']}_in_scope"].append(row)
    output = {
        "schema_version": SCHEMA_VERSION,
        "matching_policy": "Exact normalized Sink function plus callee/semantic class; applied only after all LLM runs.",
        "summary": {name: aggregate(group) for name, group in sorted(grouped.items())},
        "cves": rows,
        "scope": {
            "manifest": str(args.scope_manifest.resolve()),
            "evaluated_in_scope_cves": len(evaluated),
            "excluded_cves_not_scored": len(scope_rows) - len(evaluated),
        },
    }
    write_json(args.out, output)
    print(json.dumps(output["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
