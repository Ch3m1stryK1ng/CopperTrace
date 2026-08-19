#!/usr/bin/env python3
"""Merge LLM/review sink decisions into confirmed sinks.json.

Expected response_LLM.txt shape:

U0001:
  decision: confirmed | rejected | unresolved
  sink_label: COPY_SINK
  roles:
    dst: ...
    src: ...
    len: ...
  evidence_refs:
    - ...
  notes: ...
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


COPPERTRACE_SINK_LABELS = {
    "COPY_SINK",
    "MEMSET_SINK",
    "STORE_SINK",
    "LOOP_WRITE_SINK",
    "FORMAT_STRING_SINK",
    "FUNC_PTR_SINK",
    "LIFETIME_SINK",
    "UNKNOWN_SINK",
}


DEFAULT_VULNERABLE_ROLES_BY_LABEL = {
    "COPY_SINK": ["src", "len"],
    "MEMSET_SINK": ["len"],
    "STORE_SINK": ["dst", "value"],
    "LOOP_WRITE_SINK": ["dst", "src", "value", "len", "index", "bound"],
    "FORMAT_STRING_SINK": ["fmt"],
    "FUNC_PTR_SINK": ["target", "index"],
    "LIFETIME_SINK": ["object"],
}


def _clean_expr(expr: Any) -> str:
    return re.sub(r"\s+", " ", str(expr or "").strip())


def _normalize_expr(expr: Any) -> str:
    return re.sub(r"\s+", "", _clean_expr(expr))


def _strip_casts_and_parens(expr: Any) -> str:
    text = _clean_expr(expr)
    changed = True
    while changed:
        changed = False
        new_text = re.sub(r"^\(\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s*\)\s*", "", text).strip()
        if new_text != text:
            text = new_text
            changed = True
        if text.startswith("(") and text.endswith(")"):
            text = text[1:-1].strip()
            changed = True
    return text


def _is_constant_expr(expr: Any) -> bool:
    text = _strip_casts_and_parens(expr)
    if not text:
        return False
    if re.fullmatch(r'"(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*', text):
        return True
    if re.fullmatch(r"'(?:[^'\\]|\\.)*'", text):
        return True
    if re.fullmatch(r"[+-]?(?:0x[0-9a-fA-F]+|\d+)(?:[uUlL]*)", text):
        return True
    if text in {"NULL", "true", "false"}:
        return True
    if re.fullmatch(r"sizeof\s*\([^)]*\)", text):
        return True
    return False


def _role_index_from_args(args: list[Any], expr: Any) -> int | None:
    norm = _normalize_expr(expr)
    for idx, arg in enumerate(args):
        if _normalize_expr(arg) == norm:
            return idx
    return None


def vulnerable_roles_for_label(label: str) -> list[str]:
    return list(DEFAULT_VULNERABLE_ROLES_BY_LABEL.get(label, []))


def build_vulnerable_parameters(label: str, args: list[Any], roles: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for role in vulnerable_roles_for_label(label):
        expr = _clean_expr(roles.get(role, ""))
        if not expr:
            continue
        item: dict[str, Any] = {
            "role": role,
            "expr": expr,
            "constant": _is_constant_expr(expr),
        }
        idx = _role_index_from_args(args, expr)
        if idx is not None:
            item["index"] = idx
        out.append(item)
    return out


def _clean_label(value: Any) -> str:
    label = str(value or "").strip()
    return label if label else "UNKNOWN_SINK"


def inferred_compat_label_from_candidate(candidate: dict[str, Any]) -> str:
    reason = str(candidate.get("reason") or "")
    pattern = str(candidate.get("pattern") or "")
    if reason == "pattern_parser_store" or pattern == "parser_field_store":
        return "STORE_SINK"
    if reason == "pattern_unbounded_walk" or pattern == "unbounded_walk":
        return "LOOP_WRITE_SINK"
    if reason == "pattern_loop_write":
        return "COPY_SINK" if pattern == "loop_copy" else "LOOP_WRITE_SINK"
    return "UNKNOWN_SINK"


def resolve_labels(candidate: dict[str, Any], decision: dict[str, Any]) -> dict[str, str]:
    """Resolve top-level vs. comment-level sink labels.

    The top-level `label` is intentionally CopperTrace-compatible.  Finer
    semantic terms produced by LLM/review are preserved as annotation fields;
    they should not drive matching, migration, or downstream enum handling.
    """
    llm_label = _clean_label(decision.get("sink_label") or decision.get("label"))
    compat_label = _clean_label(candidate.get("compat_sink_label") or inferred_compat_label_from_candidate(candidate))
    suggested_label = _clean_label(candidate.get("suggested_sink_label"))
    reason = str(candidate.get("reason") or "")

    if (
        reason.startswith("pattern_")
        and compat_label in COPPERTRACE_SINK_LABELS
        and compat_label != "UNKNOWN_SINK"
    ):
        label = compat_label
        label_source = "candidate_compat_sink_label"
    elif llm_label in COPPERTRACE_SINK_LABELS and llm_label != "UNKNOWN_SINK":
        label = llm_label
        label_source = "llm_sink_label"
    elif compat_label in COPPERTRACE_SINK_LABELS and compat_label != "UNKNOWN_SINK":
        label = compat_label
        label_source = "candidate_compat_sink_label"
    elif suggested_label in COPPERTRACE_SINK_LABELS and suggested_label != "UNKNOWN_SINK":
        label = suggested_label
        label_source = "candidate_suggested_sink_label"
    elif llm_label in COPPERTRACE_SINK_LABELS:
        label = llm_label
        label_source = "llm_sink_label"
    else:
        label = "UNKNOWN_SINK"
        label_source = "fallback_unknown"

    semantic_label = str(decision.get("semantic_label") or "").strip()
    if not semantic_label and llm_label not in COPPERTRACE_SINK_LABELS:
        semantic_label = llm_label
    if not semantic_label and llm_label in COPPERTRACE_SINK_LABELS and llm_label != label:
        semantic_label = llm_label
    if not semantic_label:
        semantic_label = str(candidate.get("semantic_hint_label") or "").strip()

    return {
        "label": label,
        "label_source": label_source,
        "semantic_label": semantic_label,
    }


def parse_response(path: Path) -> dict[str, dict[str, Any]]:
    decisions: dict[str, dict[str, Any]] = {}
    current_id = ""
    section = ""

    for raw_line in path.read_text(errors="replace").splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        item_match = re.match(r"^(U\d+):\s*$", stripped)
        if item_match:
            current_id = item_match.group(1)
            decisions[current_id] = {"roles": {}, "evidence_refs": []}
            section = ""
            continue

        if not current_id:
            continue

        key_match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", stripped)
        if key_match and not raw_line.startswith("    "):
            key, value = key_match.group(1), key_match.group(2).strip()
            if key in {"roles", "evidence_refs"}:
                section = key
                if key == "roles":
                    decisions[current_id].setdefault("roles", {})
                else:
                    decisions[current_id].setdefault("evidence_refs", [])
                continue
            decisions[current_id][key] = value
            section = ""
            continue

        if section == "roles":
            role_match = re.match(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$", stripped)
            if role_match:
                decisions[current_id].setdefault("roles", {})[role_match.group(1)] = role_match.group(2).strip()
            continue

        if section == "evidence_refs" and stripped.startswith("-"):
            decisions[current_id].setdefault("evidence_refs", []).append(stripped[1:].strip())

    return decisions


def next_sink_id(confirmed: list[dict[str, Any]]) -> int:
    highest = 0
    for row in confirmed:
        match = re.match(r"^S(\d+)$", str(row.get("id", "")))
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def confirmed_row_from_candidate(
    *,
    sink_id: str,
    candidate: dict[str, Any],
    decision: dict[str, Any],
    response_path: Path,
) -> dict[str, Any]:
    roles = decision.get("roles", {})
    if not isinstance(roles, dict):
        roles = {}
    label_info = resolve_labels(candidate, decision)
    cleaned_roles = {str(k): str(v) for k, v in roles.items()}
    args = list(candidate.get("actual_args", []) or [])
    row = {
        "id": sink_id,
        "detection_kind": "semantic_candidate",
        "confirmation_source": "llm_review",
        "label": label_info["label"],
        "sink_kind": "llm_confirmed_semantic_sink",
        "callee": str(candidate.get("callee", "")),
        "function": str(candidate.get("function", "")),
        "plain_line": int(candidate.get("plain_line") or 0),
        "args": args,
        "roles": cleaned_roles,
        "vulnerable_parameter_roles": vulnerable_roles_for_label(label_info["label"]),
        "vulnerable_parameters": build_vulnerable_parameters(label_info["label"], args, cleaned_roles),
        "expr": str(candidate.get("callsite", "")),
        "taint_status": "not_evaluated",
        "guard_status": "unknown",
        "vulnerability_status": "not_evaluated",
        "source_candidate_id": str(candidate.get("id", "")),
        "llm_response_file": str(response_path),
        "llm_evidence_refs": list(decision.get("evidence_refs", []) or []),
        "llm_notes": str(decision.get("notes", "")),
        "label_resolution": {
            "label_source": label_info["label_source"],
            "llm_sink_label": str(decision.get("sink_label") or decision.get("label") or ""),
            "candidate_compat_sink_label": str(candidate.get("compat_sink_label") or ""),
            "candidate_suggested_sink_label": str(candidate.get("suggested_sink_label") or ""),
        },
    }
    if label_info["semantic_label"]:
        row["semantic_label"] = label_info["semantic_label"]
        row["semantic_comment"] = "Fine-grained reviewer/LLM semantic note; top-level label remains CopperTrace-compatible."
    return row


def normalize_existing_confirmed_row(
    row: dict[str, Any],
    *,
    candidate_by_id: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    row = dict(row)
    row.pop("semantic_subtype", None)
    row.pop("label_compatibility", None)
    source_candidate_id = str(row.get("source_candidate_id") or "")
    candidate = candidate_by_id.get(source_candidate_id, {})
    if source_candidate_id and not row.get("label_resolution"):
        row["label_resolution"] = {
            "label_source": "existing_confirmed_row",
            "llm_sink_label": str(row.get("label") or ""),
            "candidate_compat_sink_label": str(candidate.get("compat_sink_label") or inferred_compat_label_from_candidate(candidate)),
            "candidate_suggested_sink_label": str(candidate.get("suggested_sink_label") or ""),
        }
    if row.get("semantic_label") and not row.get("semantic_comment"):
        row["semantic_comment"] = "Fine-grained reviewer/LLM semantic note; top-level label remains CopperTrace-compatible."
    return row


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sinks-json", required=True, type=Path)
    parser.add_argument("--sink-unconfirmed-json", required=True, type=Path)
    parser.add_argument("--response", required=True, type=Path)
    parser.add_argument("--output-sinks-json", default=None, type=Path)
    args = parser.parse_args()

    sinks = json.loads(args.sinks_json.read_text())
    unconfirmed = json.loads(args.sink_unconfirmed_json.read_text())
    decisions = parse_response(args.response)
    candidate_by_id = {
        str(candidate.get("id", "")): candidate
        for candidate in list(unconfirmed.get("candidates", []) or [])
        if str(candidate.get("id", ""))
    }

    confirmed = [
        normalize_existing_confirmed_row(row, candidate_by_id=candidate_by_id)
        for row in list(sinks.get("confirmed_sink_calls", []) or [])
    ]
    existing_candidate_ids = {
        str(row.get("source_candidate_id", ""))
        for row in confirmed
        if str(row.get("source_candidate_id", ""))
    }
    next_id = next_sink_id(confirmed)

    confirmed_count = 0
    rejected_count = 0
    unresolved_count = 0
    confirmed_candidate_ids: list[str] = []
    rejected_candidate_ids: list[str] = []
    unresolved_candidate_ids: list[str] = []

    for candidate in list(unconfirmed.get("candidates", []) or []):
        candidate_id = str(candidate.get("id", ""))
        decision = decisions.get(candidate_id)
        if not decision:
            unresolved_count += 1
            if candidate_id:
                unresolved_candidate_ids.append(candidate_id)
            continue
        outcome = str(decision.get("decision", "")).strip().lower()
        if outcome == "confirmed":
            if candidate_id not in existing_candidate_ids:
                sink_id = f"S{next_id:04d}"
                next_id += 1
                confirmed.append(
                    confirmed_row_from_candidate(
                        sink_id=sink_id,
                        candidate=candidate,
                        decision=decision,
                        response_path=args.response,
                    )
                )
                existing_candidate_ids.add(candidate_id)
            confirmed_count += 1
            if candidate_id:
                confirmed_candidate_ids.append(candidate_id)
        elif outcome == "rejected":
            rejected_count += 1
            if candidate_id:
                rejected_candidate_ids.append(candidate_id)
        else:
            unresolved_count += 1
            if candidate_id:
                unresolved_candidate_ids.append(candidate_id)

    sinks["confirmed_sink_calls"] = confirmed
    sinks["resolution"] = {
        "unconfirmed_total": len(list(unconfirmed.get("candidates", []) or [])),
        "llm_confirmed_total": confirmed_count,
        "rejected_total": rejected_count,
        "unresolved_blockers": unresolved_count,
        "response_file": str(args.response),
        "confirmed_candidate_ids": confirmed_candidate_ids,
        "rejected_candidate_ids": rejected_candidate_ids,
        "unresolved_candidate_ids": unresolved_candidate_ids,
    }
    sinks["next_stage_ready"] = unresolved_count == 0
    sinks.setdefault("counts", {})["confirmed_sink_calls"] = len(confirmed)

    output = args.output_sinks_json or args.sinks_json
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(sinks, indent=2, sort_keys=False) + "\n")
    print(json.dumps(sinks["resolution"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
