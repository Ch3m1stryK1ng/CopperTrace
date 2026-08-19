#!/usr/bin/env python3
"""Apply the Mango-equivalent A1 policy to CopperTrace Static Alerts."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


SOURCE_REACHED_STATUSES = frozenset(
    {"SOURCE_REACHED_DETERMINISTIC", "SOURCE_REACHED_HEURISTIC"}
)

# Mirrored from Operation Mango's argument_resolver/utils/rank.py. A1 keeps
# these Linux-oriented categories intentionally; MCU-specific Sources remain
# unknown until a later CopperTrace policy is enabled.
MANGO_SOURCE_WEIGHTS = {
    "env": 0.7,
    "network": 0.6,
    "file": 0.5,
    "argv": 0.4,
    "unknown": 0.0,
}
MANGO_SOURCE_NAMES = {
    "env": frozenset({"env", "getenv", "nvram", "frontend_param", "getvalue"}),
    "file": frozenset({"fopen", "read", "open", "fread", "fgets", "stdin"}),
    "argv": frozenset({"argv"}),
    "network": frozenset({"socket", "accept", "recv", "nflog_get_payload"}),
}
MCU_ONLY_SOURCE_LABELS = frozenset(
    {
        "MMIO_READ",
        "ISR_MMIO_READ",
        "ISR_FILLED_BUFFER",
        "DMA_BACKED_BUFFER",
        "CONTROL_STATE",
        "SENSOR_INPUT",
    }
)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_key(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:20]


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)


def _mango_name_from_text(text: str, *, explicit_provenance: bool) -> str:
    lowered = str(text or "").strip().lower()
    if not lowered:
        return ""

    summary = re.search(r"mango-compat[.:/]([a-z0-9_]+)", lowered)
    if summary:
        lowered = summary.group(1)
    elif explicit_provenance:
        handler = re.search(r"handle_([a-z0-9_]+)", lowered)
        if handler:
            lowered = handler.group(1)
        else:
            lowered = lowered.split("(", 1)[0].rsplit(".", 1)[-1]
    else:
        lowered = lowered.split("(", 1)[0]

    if "nvram" in lowered:
        return "nvram"
    if "recv" in lowered:
        return "recv"
    return lowered


def classify_mango_source(source: dict[str, Any]) -> dict[str, Any]:
    """Classify one Source using only Mango's original Source vocabulary."""

    label = str(source.get("label", ""))
    if label in MCU_ONLY_SOURCE_LABELS:
        return {
            "category": "unknown",
            "weight": MANGO_SOURCE_WEIGHTS["unknown"],
            "matched_name": "",
            "evidence": "mcu_source_not_modeled_by_mango",
        }

    candidates: list[tuple[str, bool, str]] = []
    for field in ("callee", "function", "source_kind", "detection_kind"):
        text = str(source.get(field, "") or "")
        if text:
            candidates.append((text, False, field))

    proof = source.get("proof", {}) or {}
    for text in _walk_strings(proof):
        if "mango-compat" in text.lower() or "handle_" in text.lower():
            candidates.append((text, True, "proof"))

    best = {
        "category": "unknown",
        "weight": MANGO_SOURCE_WEIGHTS["unknown"],
        "matched_name": "",
        "evidence": "no_mango_source_category",
    }
    for text, explicit, origin in candidates:
        name = _mango_name_from_text(text, explicit_provenance=explicit)
        for category, names in MANGO_SOURCE_NAMES.items():
            if name not in names:
                continue
            weight = MANGO_SOURCE_WEIGHTS[category]
            if weight > float(best["weight"]):
                best = {
                    "category": category,
                    "weight": weight,
                    "matched_name": name,
                    "evidence": origin,
                }
    return best


def _source_backed_parameters(chain: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        row
        for row in list(chain.get("parameter_results", []) or [])
        if str(row.get("status", "")) in SOURCE_REACHED_STATUSES
        and list(row.get("paths", []) or [])
    ]


def source_ids_for_chain(chain: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(path.get("source_id", ""))
                for parameter in _source_backed_parameters(chain)
                for path in list(parameter.get("paths", []) or [])
                if str(path.get("source_id", ""))
            }
        )
    )


def _parameter_roles(chain: dict[str, Any]) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                str(row.get("role", "") or "unknown")
                for row in _source_backed_parameters(chain)
            }
        )
    )


def _effect_site(chain: dict[str, Any], sink: dict[str, Any]) -> str:
    return str(
        sink.get("effect_site_id")
        or chain.get("sink_site_id")
        or sink.get("site_id")
        or ""
    )


def closure_equivalence_key(
    chain: dict[str, Any], sink: dict[str, Any]
) -> tuple[str, str, tuple[str, ...]]:
    """Mango-style equivalence: same concrete Sink effect and argument roles."""

    return (
        str(chain.get("sink_label") or sink.get("label") or ""),
        _effect_site(chain, sink),
        _parameter_roles(chain),
    )


def _rank_source_set(
    source_ids: tuple[str, ...], source_rows: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    evidence: list[dict[str, Any]] = []
    for source_id in source_ids:
        row = source_rows.get(source_id, {})
        classification = classify_mango_source(row) if row else {
            "category": "unknown",
            "weight": 0.0,
            "matched_name": "",
            "evidence": "source_id_not_bound",
        }
        evidence.append({"source_id": source_id, **classification})
    weight = max((float(row["weight"]) for row in evidence), default=0.0)
    categories = sorted(
        {str(row["category"]) for row in evidence if float(row["weight"]) == weight}
    )
    return {"weight": weight, "top_categories": categories, "sources": evidence}


def _candidate_view(
    chain: dict[str, Any],
    sink: dict[str, Any],
    source_rows: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    source_ids = source_ids_for_chain(chain)
    ranking = _rank_source_set(source_ids, source_rows)
    closure_key = closure_equivalence_key(chain, sink)
    return {
        "alert_id": str(chain.get("chain_id", "")),
        "sink_id": str(chain.get("sink_id", "")),
        "sink_effect_site_id": _effect_site(chain, sink),
        "sink_boundary_site_id": str(chain.get("sink_site_id", "")),
        "sink_label": str(chain.get("sink_label") or sink.get("label") or ""),
        "vulnerable_parameter_roles": list(_parameter_roles(chain)),
        "source_ids": list(source_ids),
        "source_set": frozenset(source_ids),
        "source_ranking": ranking,
        "closure_key": closure_key,
        "closure_group_id": f"closure:{stable_key(closure_key)}",
    }


def _subsumption_groups(
    candidates: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str, tuple[str, ...]], list[dict[str, Any]]] = {}
    for candidate in candidates:
        grouped.setdefault(candidate["closure_key"], []).append(candidate)

    canonical: list[dict[str, Any]] = []
    merged: list[dict[str, Any]] = []
    for closure_key in sorted(grouped, key=repr):
        rows = sorted(
            grouped[closure_key],
            key=lambda row: (
                len(row["source_set"]),
                -float(row["source_ranking"]["weight"]),
                row["alert_id"],
            ),
        )
        representatives: list[dict[str, Any]] = []
        for row in rows:
            parent = next(
                (
                    existing
                    for existing in representatives
                    if existing["source_set"] <= row["source_set"]
                ),
                None,
            )
            if parent is None:
                item = dict(row)
                item["represented_alert_ids"] = [row["alert_id"]]
                representatives.append(item)
                continue
            parent["represented_alert_ids"].append(row["alert_id"])
            merged.append(
                {
                    "canonical_alert_id": parent["alert_id"],
                    "subsumed_alert_id": row["alert_id"],
                    "closure_group_id": row["closure_group_id"],
                    "canonical_source_ids": sorted(parent["source_set"]),
                    "subsumed_source_ids": sorted(row["source_set"]),
                    "reason": "MANGO_SOURCE_SET_SUBSUMPTION",
                }
            )
        canonical.extend(representatives)
    return canonical, merged


def _public_candidate(row: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in row.items()
        if key not in {"source_set", "closure_key"}
    }


def filter_static_alerts(
    chains_doc: dict[str, Any],
    sinks_doc: dict[str, Any],
    sources_doc: dict[str, Any],
    *,
    max_selected: int,
) -> dict[str, Any]:
    """Return an auditable A1 view without modifying any input Alert."""

    chains_before = copy.deepcopy(chains_doc)
    sink_rows = {
        str(row.get("id", "")): row
        for row in list(sinks_doc.get("sink_startpoints", []) or [])
        if str(row.get("id", ""))
    }
    source_rows = {
        str(row.get("id", "")): row
        for row in list(sources_doc.get("source_sites", []) or [])
        if str(row.get("id", ""))
    }

    candidates: list[dict[str, Any]] = []
    non_alerts: list[dict[str, Any]] = []
    contradictions: list[dict[str, Any]] = []
    for chain in list(chains_doc.get("chains", []) or []):
        alert_id = str(chain.get("chain_id", ""))
        sink_id = str(chain.get("sink_id", ""))
        sink = sink_rows.get(sink_id)
        if not alert_id or sink is None:
            contradictions.append(
                {
                    "alert_id": alert_id,
                    "reason": "ALERT_ENDPOINT_NOT_BOUND_TO_SINK_ARTIFACT",
                }
            )
            continue
        if str(chain.get("status", "")) not in SOURCE_REACHED_STATUSES:
            non_alerts.append(
                {"chain_id": alert_id, "reason": "SOURCE_NOT_REACHED"}
            )
            continue
        source_ids = source_ids_for_chain(chain)
        if not source_ids:
            contradictions.append(
                {"alert_id": alert_id, "reason": "SOURCE_ASSOCIATION_MISSING"}
            )
            continue
        candidates.append(_candidate_view(chain, sink, source_rows))

    canonical, merged = _subsumption_groups(candidates)
    canonical.sort(
        key=lambda row: (
            -float(row["source_ranking"]["weight"]),
            len(row["source_set"]),
            row["alert_id"],
        )
    )

    selected: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    for index, row in enumerate(canonical, start=1):
        public_row = _public_candidate(row)
        public_row["rank"] = index
        public_row["reason"] = "MANGO_SOURCE_RANK"
        if index <= max_selected:
            selected.append(public_row)
        else:
            deferred.append({**public_row, "reason": "EXECUTION_BUDGET"})

    if chains_doc != chains_before:
        raise AssertionError("A1 Filter modified the input Static Alerts")

    return {
        "schema_version": "ct-mini-alert-filter-a1-v1",
        "policy": {
            "name": "MANGO_EQUIVALENT_A1",
            "constant_resolution": "reuse_sink_miner_vulnerable_parameters",
            "source_association": "reuse_bfs_rda_parameter_paths",
            "deduplication": "mango_source_set_subsumption",
            "source_ranking": dict(MANGO_SOURCE_WEIGHTS),
            "keyword_dictionary": "disabled",
            "mcu_source_categories": "unknown",
            "checks_used": False,
            "channelgraph_evidence_used_for_ranking": False,
            "public_profiles_used": False,
            "low_rank_is_deferred": True,
            "input_alerts_modified": False,
        },
        "counts": {
            "input_chains": len(list(chains_doc.get("chains", []) or [])),
            "input_static_alerts": len(candidates),
            "non_alert_chains": len(non_alerts),
            "canonical_alerts": len(canonical),
            "source_set_subsumed": len(merged),
            "selected": len(selected),
            "deferred": len(deferred),
            "artifact_contradictions": len(contradictions),
        },
        "selected": selected,
        "deferred": deferred,
        "merged_duplicates": merged,
        "non_alert_chains": non_alerts,
        "artifact_contradictions": contradictions,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chains", required=True, type=Path)
    parser.add_argument("--sinks", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--max-selected", type=int, default=20)
    args = parser.parse_args()

    result = filter_static_alerts(
        load_json(args.chains),
        load_json(args.sinks),
        load_json(args.sources),
        max_selected=max(1, args.max_selected),
    )
    result["inputs"] = {
        "chains_sha256": sha256_file(args.chains),
        "sinks_sha256": sha256_file(args.sinks),
        "sources_sha256": sha256_file(args.sources),
    }
    write_json(args.out, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
