#!/usr/bin/env python3
"""Build a cross-firmware audit index for reviewed CopperTrace TruPoCs."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def family_key(sink: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(sink.get("label", "") or ""),
        str(sink.get("function", "") or ""),
        str(sink.get("callee", "") or ""),
    )


def family_id(key: tuple[str, str, str]) -> str:
    digest = hashlib.sha256("\x1f".join(key).encode()).hexdigest()[:20]
    return f"trupoc-family:{digest}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--review-root", required=True, type=Path)
    parser.add_argument("--static-root", required=True, type=Path)
    parser.add_argument("--out-json", required=True, type=Path)
    parser.add_argument("--out-md", required=True, type=Path)
    args = parser.parse_args()

    rows: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    reviewed_paths = sorted(
        (args.review_root / "per_sample").glob("*/reviewed_alerts.json")
    )
    for reviewed_path in reviewed_paths:
        sample_id = reviewed_path.parent.name
        reviewed = read_json(reviewed_path)
        sinks = read_json(args.static_root / "per_sample" / sample_id / "sinks.json")
        sink_by_id = {
            str(row.get("id", "")): dict(row)
            for row in list(sinks.get("sinks", []) or [])
        }
        for unresolved in list(reviewed.get("unresolved_alerts", []) or []):
            if "REVIEW_EXECUTION_FAILED" in set(
                dict(unresolved.get("whole_review", {}) or {}).get(
                    "missing_evidence", []
                )
            ):
                failures.append(
                    {
                        "sample_id": sample_id,
                        "alert_id": str(
                            dict(unresolved.get("alert", {}) or {}).get(
                                "alert_id", ""
                            )
                        ),
                    }
                )
        for reviewed_row in list(reviewed.get("trupocs", []) or []):
            alert = dict(reviewed_row.get("alert", {}) or {})
            sink = sink_by_id.get(str(alert.get("sink_id", "")), {})
            key = family_key(sink)
            rows.append(
                {
                    "sample_id": sample_id,
                    "alert_id": str(alert.get("alert_id", "")),
                    "family_id": family_id(key),
                    "sink_id": str(alert.get("sink_id", "")),
                    "sink_label": str(sink.get("label", alert.get("sink_label", ""))),
                    "sink_function": str(sink.get("function", "")),
                    "sink_callee": str(sink.get("callee", "")),
                    "sink_expr": str(sink.get("expr", "")),
                    "sink_site_id": str(sink.get("site_id", alert.get("sink_boundary_site_id", ""))),
                    "sink_instruction_address": str(sink.get("instruction_address", "")),
                    "sink_recognition": str(sink.get("recognition", "")),
                    "a2_rank": int(alert.get("rank", 0) or 0),
                    "uses_channelgraph": bool(
                        dict(alert.get("evidence", {}) or {}).get(
                            "uses_channelgraph", False
                        )
                    ),
                    "check_collection_status": str(
                        dict(reviewed_row.get("check_evidence", {}) or {}).get(
                            "collection_status", ""
                        )
                    ),
                    "reason": str(
                        dict(reviewed_row.get("whole_review", {}) or {}).get(
                            "reason", ""
                        )
                    ),
                    "evidence_refs": list(
                        dict(reviewed_row.get("whole_review", {}) or {}).get(
                            "evidence_refs", []
                        )
                        or []
                    ),
                    "reviewed_artifact": str(reviewed_path.resolve()),
                }
            )

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["family_id"]].append(row)
    families = []
    for current_id, members in grouped.items():
        representative = min(
            members,
            key=lambda row: (
                row["a2_rank"] if row["a2_rank"] > 0 else 1 << 30,
                row["sample_id"],
            ),
        )
        families.append(
            {
                "family_id": current_id,
                "sink_label": representative["sink_label"],
                "sink_function": representative["sink_function"],
                "sink_callee": representative["sink_callee"],
                "alerts": len(members),
                "firmwares": len({row["sample_id"] for row in members}),
                "channelgraph_alerts": sum(
                    int(row["uses_channelgraph"]) for row in members
                ),
                "representative_alert_id": representative["alert_id"],
                "representative_sample_id": representative["sample_id"],
                "representative_reason": representative["reason"],
                "representative_reviewed_artifact": representative[
                    "reviewed_artifact"
                ],
                "members": members,
            }
        )
    families.sort(
        key=lambda row: (-row["firmwares"], -row["alerts"], row["family_id"])
    )

    output = {
        "schema_version": "ct-mini-trupoc-audit-index-v1",
        "review_root": str(args.review_root.resolve()),
        "counts": {
            "firmwares": len(reviewed_paths),
            "trupocs": len(rows),
            "implementation_families": len(families),
            "execution_failures": len(failures),
            "sink_labels": dict(Counter(row["sink_label"] for row in rows)),
        },
        "families": families,
        "trupocs": rows,
        "execution_failures": failures,
    }
    write_json(args.out_json, output)

    lines = [
        "# Fresh TruPoC Audit Index",
        "",
        f"- Firmware: {len(reviewed_paths)}",
        f"- TruPoCs: {len(rows)}",
        f"- Implementation families: {len(families)}",
        f"- Remaining review execution failures: {len(failures)}",
        "",
        "| Family | Sink | Function | Callee | Alerts | Firmware | Representative |",
        "|---|---|---|---|---:|---:|---|",
    ]
    for family in families:
        artifact = family["representative_reviewed_artifact"]
        link = f"[{family['representative_sample_id']}]({artifact})"
        lines.append(
            "| {family_id} | {sink_label} | `{sink_function}` | `{sink_callee}` | "
            "{alerts} | {firmwares} | {link} |".format(link=link, **family)
        )
    args.out_md.parent.mkdir(parents=True, exist_ok=True)
    args.out_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(output["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
