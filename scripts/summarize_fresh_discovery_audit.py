#!/usr/bin/env python3
"""Summarize the Fresh Discovery Audit into review-ready tables."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields: list[str] = []
    for row in rows:
        for field in row:
            if field not in fields:
                fields.append(field)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def percent(value: int, total: int) -> float:
    return round(value * 100.0 / total, 1) if total else 0.0


def markdown_table(rows: list[dict[str, Any]], fields: list[tuple[str, str]]) -> str:
    headers = [label for _key, label in fields]
    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        values = [str(row.get(key, "")).replace("|", "\\|") for key, _ in fields]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def review_rows(reviewed: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [
        *[("TRUPOC", row) for row in list(reviewed.get("trupocs", []) or [])],
        *[("REJECT", row) for row in list(reviewed.get("rejected_alerts", []) or [])],
        *[("UNRESOLVED", row) for row in list(reviewed.get("unresolved_alerts", []) or [])],
    ]


def summarize(
    *,
    input_root: Path,
    review_root: Path,
    output_root: Path,
    markdown_path: Path,
) -> dict[str, Any]:
    selection = read_json(input_root / "selection_report.json")
    manifest = read_json(input_root / "manifest.json")
    manifest_by_id = {
        str(row["sample_id"]): row for row in list(manifest.get("samples", []) or [])
    }
    selected_by_id = {
        (str(row["sample_id"]), str(alert["alert_id"])): alert
        for row in list(selection.get("samples", []) or [])
        for alert in list(row.get("alerts", []) or [])
    }

    decisions = Counter()
    by_project: dict[str, Counter[str]] = defaultdict(Counter)
    by_sink: dict[str, Counter[str]] = defaultdict(Counter)
    by_recognition: dict[str, Counter[str]] = defaultdict(Counter)
    firmware_rows: list[dict[str, Any]] = []
    queue_rows: list[dict[str, Any]] = []
    usage = Counter()
    check_counts = Counter()
    execution_failures = 0

    for selection_row in list(selection.get("samples", []) or []):
        sample_id = str(selection_row["sample_id"])
        sample = manifest_by_id[sample_id]
        project = str(sample["project"])
        reviewed_path = review_root / "per_sample" / sample_id / "reviewed_alerts.json"
        reviewed = read_json(reviewed_path)
        sample_counts = dict(reviewed.get("counts", {}) or {})
        run = dict(reviewed.get("run", {}) or {})
        for key, value in dict(run.get("usage", {}) or {}).items():
            usage[key] += int(value or 0)
        firmware_rows.append(
            {
                "project": project,
                "sample_id": sample_id,
                "application_input": str(sample.get("application_input", "")),
                "trupocs": int(sample_counts.get("trupocs", 0) or 0),
                "rejected": int(sample_counts.get("rejected", 0) or 0),
                "unresolved": int(sample_counts.get("unresolved", 0) or 0),
                "llm_calls": int(sample_counts.get("llm_calls", 0) or 0),
            }
        )

        sinks_doc = read_json(Path(str(sample["static_artifact_dir"])) / "sinks.json")
        sinks = {
            str(row.get("id", "")): row
            for row in list(sinks_doc.get("sink_startpoints", []) or [])
        }
        for decision, reviewed_row in review_rows(reviewed):
            alert = dict(reviewed_row.get("alert", {}) or {})
            alert_id = str(alert.get("alert_id", ""))
            selected = selected_by_id[(sample_id, alert_id)]
            sink = dict(sinks.get(str(alert.get("sink_id", "")), {}) or {})
            whole = dict(reviewed_row.get("whole_review", {}) or {})
            checks = dict(reviewed_row.get("check_evidence", {}) or {})
            provenance = dict(reviewed_row.get("review_provenance", {}) or {})
            execution_failure = (
                str(reviewed_row.get("review_status", "")) == "REVIEW_EXECUTION_FAILED"
                or "REVIEW_EXECUTION_FAILED" in str(reviewed_row.get("review_reason", ""))
            )
            execution_failures += int(execution_failure)
            decisions[decision] += 1
            by_project[project][decision] += 1
            by_sink[str(alert.get("sink_label", ""))][decision] += 1
            by_recognition[str(sink.get("recognition", "unknown"))][decision] += 1
            check_counts["alerts_with_checks"] += int(
                int(checks.get("check_candidate_count", 0) or 0) > 0
            )
            check_counts["check_candidates"] += int(
                checks.get("check_candidate_count", 0) or 0
            )
            check_counts["truncated"] += int(
                str(checks.get("collection_status", "")) == "TRUNCATED"
            )
            queue_rows.append(
                {
                    "review_order": {"TRUPOC": 1, "UNRESOLVED": 2, "REJECT": 3}[decision],
                    "project": project,
                    "sample_id": sample_id,
                    "application_input": str(sample.get("application_input", "")),
                    "audit_rank": int(selected.get("audit_rank", 0) or 0),
                    "source_a2_rank": int(selected.get("source_a2_rank", 0) or 0),
                    "decision": decision,
                    "alert_id": alert_id,
                    "sink_label": str(alert.get("sink_label", "")),
                    "sink_recognition": str(sink.get("recognition", "unknown")),
                    "sink_function": str(sink.get("function", "")),
                    "sink_callee": str(sink.get("callee", "")),
                    "sink_site": str(sink.get("site_id", "")),
                    "sink_address": str(sink.get("instruction_address", "")),
                    "decompiled_line": int(sink.get("plain_line", 0) or 0),
                    "sink_expression": str(sink.get("expr", "")),
                    "vulnerable_roles": ",".join(
                        str(value)
                        for value in list(alert.get("vulnerable_parameter_roles", []) or [])
                    ),
                    "uses_channelgraph": bool(
                        dict(alert.get("evidence", {}) or {}).get("uses_channelgraph", False)
                    ),
                    "check_collection": str(checks.get("collection_status", "")),
                    "check_candidates": int(checks.get("check_candidate_count", 0) or 0),
                    "dangerous_condition": str(whole.get("dangerous_condition", "")),
                    "blocking_relation": str(whole.get("blocking_relation", "")),
                    "missing_evidence": " || ".join(
                        str(value) for value in list(whole.get("missing_evidence", []) or [])
                    ),
                    "review_reason": str(reviewed_row.get("review_reason", "")),
                    "evidence_refs": ",".join(
                        str(value) for value in list(whole.get("evidence_refs", []) or [])
                    ),
                    "llm_calls": int(provenance.get("llm_calls", 0) or 0),
                    "execution_failure": execution_failure,
                    "human_review": "PENDING",
                    "novelty_status": "NOT_ASSESSED",
                }
            )

    queue_rows.sort(
        key=lambda row: (
            int(row["review_order"]),
            str(row["project"]),
            str(row["sample_id"]),
            int(row["audit_rank"]),
        )
    )
    total = sum(decisions.values())
    decision_rows = [
        {
            "decision": decision,
            "alerts": decisions[decision],
            "percent": percent(decisions[decision], total),
        }
        for decision in ("TRUPOC", "REJECT", "UNRESOLVED")
    ]

    def grouped_rows(grouped: dict[str, Counter[str]], key: str) -> list[dict[str, Any]]:
        return [
            {
                key: name,
                "alerts": sum(counts.values()),
                "trupocs": counts["TRUPOC"],
                "rejected": counts["REJECT"],
                "unresolved": counts["UNRESOLVED"],
            }
            for name, counts in sorted(grouped.items())
        ]

    project_rows = grouped_rows(by_project, "project")
    sink_rows = grouped_rows(by_sink, "sink_label")
    recognition_rows = grouped_rows(by_recognition, "recognition")
    summary = {
        "schema_version": "ct-mini-fresh-discovery-audit-results-v1",
        "scope": {
            "firmwares": len(firmware_rows),
            "selected_static_alerts": total,
            "selection": "5 projects x 4 firmware x Top-5 distinct Sink callsites",
            "human_review_status": "PENDING",
            "zero_day_claims": 0,
        },
        "review": {
            "model": "gpt-5.6-sol",
            "reasoning_effort": "medium",
            "policy": "whole-alert-single-review-v3.9",
            "decisions": dict(decisions),
            "execution_failures": execution_failures,
            "llm_calls": sum(int(row["llm_calls"]) for row in firmware_rows),
            "usage": dict(usage),
        },
        "checks": dict(check_counts),
        "by_project": project_rows,
        "by_sink_label": sink_rows,
        "by_sink_recognition": recognition_rows,
        "firmwares": firmware_rows,
        "alerts": queue_rows,
    }
    write_json(output_root / "summary.json", summary)
    write_csv(output_root / "decision_distribution.csv", decision_rows)
    write_csv(output_root / "project_distribution.csv", project_rows)
    write_csv(output_root / "firmware_distribution.csv", firmware_rows)
    write_csv(output_root / "sink_distribution.csv", sink_rows)
    write_csv(output_root / "recognition_distribution.csv", recognition_rows)
    write_csv(output_root / "human_review_queue.csv", queue_rows)
    write_json(
        output_root / "human_review_queue.json",
        {"schema_version": "ct-mini-human-review-queue-v1", "alerts": queue_rows},
    )

    sections = [
        "# Fresh Discovery Audit 100 Results",
        "",
        "This run reviews 100 selected Static Alerts. LLM `TruPoC` decisions are not confirmed vulnerabilities or zero-days.",
        "",
        "## Pipeline",
        "",
        "```text",
        "Fresh Set [100 ELFs / 2,626 A2 canonical Alerts]",
        " -> Frozen selection [5 projects x 4 firmware]",
        " -> Top-5 per firmware [100 Alerts / 100 distinct Sink callsites]",
        f" -> Check Binding [{check_counts['alerts_with_checks']} with Checks / {check_counts['check_candidates']} candidates / {check_counts['truncated']} truncated]",
        " -> gpt-5.6-sol Medium Review [100/100]",
        f" -> TruPoCs [{decisions['TRUPOC']}] / Reject [{decisions['REJECT']}] / Unresolved [{decisions['UNRESOLVED']}]",
        " -> Human Expert Review [PENDING]",
        " -> Confirmed new vulnerabilities [0 so far]",
        "```",
        "",
        "## Review Decisions",
        "",
        markdown_table(decision_rows, [("decision", "Decision"), ("alerts", "Alerts"), ("percent", "Percent")]),
        "",
        "## Review Execution",
        "",
        "| Setting | Value |",
        "|---|---:|",
        f"| Model | `{summary['review']['model']}` |",
        f"| Reasoning effort | `{summary['review']['reasoning_effort']}` |",
        f"| LLM calls | {summary['review']['llm_calls']} |",
        f"| Prompt tokens | {summary['review']['usage']['prompt_tokens']:,} |",
        f"| Completion tokens | {summary['review']['usage']['completion_tokens']:,} |",
        f"| Total tokens | {summary['review']['usage']['total_tokens']:,} |",
        f"| Execution failures | {summary['review']['execution_failures']} |",
        "",
        "## By Project",
        "",
        markdown_table(project_rows, [("project", "Project"), ("alerts", "Alerts"), ("trupocs", "TruPoCs"), ("rejected", "Rejected"), ("unresolved", "Unresolved")]),
        "",
        "## By Firmware",
        "",
        markdown_table(firmware_rows, [("project", "Project"), ("sample_id", "Firmware"), ("application_input", "Input"), ("trupocs", "TruPoCs"), ("rejected", "Rejected"), ("unresolved", "Unresolved"), ("llm_calls", "LLM Calls")]),
        "",
        "## By Sink Type",
        "",
        markdown_table(sink_rows, [("sink_label", "Sink Type"), ("alerts", "Alerts"), ("trupocs", "TruPoCs"), ("rejected", "Rejected"), ("unresolved", "Unresolved")]),
        "",
        "## By Sink Recognition",
        "",
        markdown_table(recognition_rows, [("recognition", "Recognition"), ("alerts", "Alerts"), ("trupocs", "TruPoCs"), ("rejected", "Rejected"), ("unresolved", "Unresolved")]),
        "",
        "## Human Review",
        "",
        "All 100 Alerts remain available for Human Expert Review. The queue orders TruPoCs first, Unresolved second, and Rejected last. It is stored in `human_review_queue.csv` and `human_review_queue.json`.",
        "",
        f"Model requests: `{summary['review']['llm_calls']}`. Execution failures: `{execution_failures}`. Human-reviewed defects and novelty status are not yet available.",
    ]
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text("\n".join(sections) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", required=True, type=Path)
    parser.add_argument("--review-root", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--markdown", required=True, type=Path)
    args = parser.parse_args()
    summary = summarize(
        input_root=args.input_root,
        review_root=args.review_root,
        output_root=args.out,
        markdown_path=args.markdown,
    )
    print(json.dumps({"scope": summary["scope"], "review": summary["review"], "checks": summary["checks"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
