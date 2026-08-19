#!/usr/bin/env python3
"""Match frozen blind validation results to a withheld public CVE profile."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Any

from validation_common import (
    load_json,
    reviewed_validation_entries,
    sha256_file,
    write_json,
)


def endpoint_matches(endpoint: dict[str, Any], chain: dict[str, Any]) -> bool:
    if str(chain.get("sink_function", "")) != str(endpoint.get("function_name", "")):
        return False
    if endpoint.get("callee") and str(chain.get("sink_callee", "")) != str(endpoint["callee"]):
        return False
    expected_label = str(endpoint.get("label") or endpoint.get("pipeline_label_hint") or "")
    if expected_label and str(chain.get("sink_label", "")) != expected_label:
        return False
    pattern = str(endpoint.get("site_id_regex", ""))
    return not pattern or re.fullmatch(pattern, str(chain.get("sink_site_id", ""))) is not None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--reviewed-alerts", required=True, type=Path)
    parser.add_argument("--chains", required=True, type=Path)
    parser.add_argument("--validation-summary", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    profile = load_json(args.profile)
    binary_hash = sha256_file(args.binary)
    if binary_hash != str(profile.get("binary_sha256", "")):
        raise ValueError("public profile binary hash does not match blind sample")
    queued = reviewed_validation_entries(load_json(args.reviewed_alerts))
    chains = {
        str(row.get("chain_id", "")): row
        for row in load_json(args.chains).get("chains", []) or []
    }
    runtime = {
        str(row.get("alert_id", "")): row
        for row in load_json(args.validation_summary).get("results", []) or []
    }
    matches: list[dict[str, Any]] = []
    for endpoint in profile.get("sinks", []) or []:
        endpoint_rows: list[dict[str, Any]] = []
        for queue_row, selection in queued:
            rank = int(queue_row["queue_rank"])
            alert_id = str(selection.get("alert_id", ""))
            chain = chains.get(alert_id, {})
            if not endpoint_matches(endpoint, chain):
                continue
            result = runtime.get(alert_id, {})
            endpoint_rows.append(
                {
                    "alert_id": alert_id,
                    "rank": rank,
                    "sink_site_id": chain.get("sink_site_id", ""),
                    "validation_status": result.get("result_class", "INCONCLUSIVE"),
                    "validation_reason": result.get("reason_code", "RESULT_MISSING"),
                    "known_vulnerability_match": "MATCHED",
                    "novelty_status": "KNOWN",
                }
            )
        matches.append(
            {
                "public_sink_id": endpoint.get("sink_id", ""),
                "matched": bool(endpoint_rows),
                "alerts": endpoint_rows,
            }
        )
    write_json(
        args.out,
        {
            "schema_version": "ct-mini-posthoc-public-match-v1",
            "sample_id": args.sample_id,
            "cve": profile.get("cve", ""),
            "binary_sha256": binary_hash,
            "profile": str(args.profile),
            "policy": {
                "profile_used_after_blind_planning_and_replay": True,
                "profile_data_entered_execution_plan": False,
            },
            "endpoint_matches": matches,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
