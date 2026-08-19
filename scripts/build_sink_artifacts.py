#!/usr/bin/env python3
"""Build CopperTrace Mini Sink artifacts.

The default pipeline is High-P-code-first and deterministic.  Decompiled C is
attached only as readable evidence.  The older pseudo-C/heuristic pipeline is
kept behind an explicit diagnostic flag and is not used by evaluation.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from elf_literal_enrichment import enrich_program_facts_with_elf_literals


CONTROL_WORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
}

SEMANTIC_CANDIDATE_TOKENS = {
    "append",
    "put",
    "write",
    "add",
    "push",
    "copy",
    "insert",
    "enqueue",
}

POINTER_HINT_TOKENS = {
    "buf",
    "buff",
    "buffer",
    "data",
    "payload",
    "packet",
    "pkt",
    "msg",
    "mem",
    "ptr",
    "rx",
    "tx",
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

SIZE_HINT_TOKENS = {
    "len",
    "length",
    "size",
    "count",
    "cnt",
    "num",
    "n",
    "rem",
    "remain",
    "capacity",
    "cap",
}


DEFAULT_REGISTRY_PATH = (
    Path(__file__).resolve().parents[1]
    / "registries"
    / "sink_patterns.v2.json"
)

PRIMITIVE_SINK_SPECS: dict[str, dict[str, Any]] = {}
FRAMEWORK_SINK_SPECS: dict[str, dict[str, Any]] = {}


@dataclass
class FunctionRecord:
    name: str
    signature: str
    params: list[str]
    start_line: int
    body_start_line: int
    end_line: int
    lines: list[str]


@dataclass
class Callsite:
    callee: str
    args: list[str]
    function: str
    line: int
    expr: str
    call_start: int = 0


@dataclass
class WrapperSummary:
    id: str
    function: str
    function_line: int
    kind: str
    inner_sink: dict[str, Any]
    roles: dict[str, str]
    evidence: list[str]


def _entries_by_name(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if entry.get("enabled", True) is False:
            continue
        name = str(entry.get("name", "")).strip()
        if not name:
            continue
        spec = {k: v for k, v in entry.items() if k not in {"name", "enabled"}}
        out[name] = spec
    return out


def load_sink_registry(path: Path) -> dict[str, Any]:
    from sink_artifact_schema import load_sink_registry as load_v2_registry

    return load_v2_registry(path)


def partition_audit_only_heuristics(
    rows: list[dict[str, Any]],
    rule_specs: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], set[str]]:
    """Keep audit-only findings out of Sink startpoints.

    ``--audit-heuristics`` controls which recognizers execute. It must not by
    itself promote an unaudited finding into the graph searched by BFS/RDA.
    Promotion is controlled separately by the registry's ``enabled`` field.
    """

    audit_only_methods = {
        str(spec.get("id", ""))
        for spec in rule_specs
        if spec.get("audit_only", False) is True and str(spec.get("id", ""))
    }
    startpoints: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        method = str(row.get("recognition_method", ""))
        if method in audit_only_methods or row.get("audit_only", False) is True:
            row["audit_only"] = True
            row["eligible_for_bfs_rda"] = False
            audit_rows.append(row)
        else:
            startpoints.append(row)
    return startpoints, audit_rows, audit_only_methods


def read_json(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    return json.loads(path.read_text())


def clean_expr(expr: str) -> str:
    expr = re.sub(r"\s+", " ", expr.strip())
    expr = expr.strip()
    if expr.startswith("(") and expr.endswith(")"):
        return expr
    return expr


def normalize_expr_for_key(expr: str) -> str:
    return re.sub(r"\s+", "", clean_expr(expr))


def is_string_literal_expr(expr: str) -> bool:
    text = clean_expr(expr)
    # Accept ordinary C literal and concatenated literals.  Casted format
    # pointers are deliberately not treated as literals by this lightweight
    # scanner.
    return bool(re.fullmatch(r'"(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*', text))


def is_char_literal_expr(expr: str) -> bool:
    return bool(re.fullmatch(r"'(?:[^'\\]|\\.)*'", clean_expr(expr)))


def is_numeric_literal_expr(expr: str) -> bool:
    return bool(re.fullmatch(r"[+-]?(?:0x[0-9a-fA-F]+|\d+)(?:[uUlL]*)", clean_expr(expr)))


def is_constant_expr(expr: str) -> bool:
    text = strip_casts_and_parens(expr)
    if not text:
        return False
    if is_string_literal_expr(text) or is_char_literal_expr(text) or is_numeric_literal_expr(text):
        return True
    if text in {"NULL", "true", "false"}:
        return True
    if re.fullmatch(r"sizeof\s*\([^)]*\)", text):
        return True
    if re.fullmatch(r"(?:sizeof\s*\([^)]*\)|[0-9xXa-fA-FuUlL+\-*/%()&|<>\s]+)+", text):
        return True
    return False


def is_literal_format_call(call: Callsite, spec: dict[str, Any]) -> bool:
    if str(spec.get("label", "")) != "FORMAT_STRING_SINK":
        return False
    fmt = role_from_spec(call.args, spec, "fmt")
    return bool(fmt and is_string_literal_expr(fmt))


def literal_format_has_conversion(expr: str) -> bool:
    """Return true when a C string literal consumes at least one argument."""

    text = clean_expr(expr)
    if not is_string_literal_expr(text):
        return False
    # This is intentionally a lexical gate, not a full printf parser. Escaped
    # percent signs are removed before looking for a conversion terminator.
    text = text.replace("%%", "")
    return re.search(r"%(?:[-+ #0']|\d|\.|\*|h|hh|l|ll|j|z|t|L)*[diuoxXfFeEgGaAcspn]", text) is not None


def literal_format_output_roles(call: Callsite, spec: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    """Model constant-format output as a buffer-write sink when it has data args."""

    roles = roles_for_call(call, spec)
    fmt_index = role_index_from_spec(spec, "fmt")
    if fmt_index is None:
        return roles, []
    dynamic_args = [arg for arg in call.args[fmt_index + 1:] if str(arg).strip()]
    if not dynamic_args or not literal_format_has_conversion(str(roles.get("fmt", ""))):
        return roles, []
    vulnerable = []
    for index, argument in enumerate(dynamic_args):
        role = f"src_vararg_{index}"
        roles[role] = argument
        vulnerable.append(role)
    if roles.get("len"):
        vulnerable.append("len")
    return roles, vulnerable


def vulnerable_roles_for_label(label: str) -> list[str]:
    return list(DEFAULT_VULNERABLE_ROLES_BY_LABEL.get(label, []))


def vulnerable_roles_for_spec(label: str, spec: dict[str, Any] | None = None) -> list[str]:
    spec = spec or {}
    if "vulnerable_parameter_roles" not in spec:
        return vulnerable_roles_for_label(label)
    raw = spec.get("vulnerable_parameter_roles")
    if isinstance(raw, list):
        return [str(role).strip() for role in raw if str(role).strip()]
    return []


def role_index_from_spec(spec: dict[str, Any] | None, role: str) -> int | None:
    spec = spec or {}
    idx = spec.get(f"{role}_arg")
    return idx if isinstance(idx, int) else None


def role_index_from_args(args: list[str], expr: str) -> int | None:
    norm_expr = normalize_expr_for_key(expr)
    for idx, arg in enumerate(args):
        if normalize_expr_for_key(arg) == norm_expr:
            return idx
    return None


def build_vulnerable_parameters(
    *,
    label: str,
    args: list[str],
    roles: dict[str, str],
    spec: dict[str, Any] | None = None,
    vulnerable_roles: list[str] | None = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    selected_roles = (
        vulnerable_roles
        if vulnerable_roles is not None
        else vulnerable_roles_for_spec(label, spec)
    )
    for role in selected_roles:
        expr = str(roles.get(role, "") or "").strip()
        if not expr:
            continue
        idx = role_index_from_spec(spec, role)
        if idx is None:
            idx = role_index_from_args(args, expr)
        item: dict[str, Any] = {
            "role": role,
            "expr": expr,
            "constant": is_constant_expr(expr),
        }
        if idx is not None:
            item["index"] = idx
        out.append(item)
    return out


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sink_site_key(row: dict[str, Any]) -> str:
    roles = {
        key: normalize_expr_for_key(str(value))
        for key, value in dict(row.get("roles", {}) or {}).items()
    }
    parts = [
        str(row.get("label", "")),
        str(row.get("detection_kind", "")),
        str(row.get("function", "")),
        str(row.get("plain_line", "")),
        str(row.get("callee", "")),
        normalize_expr_for_key(str(row.get("expr", ""))),
        stable_json(roles),
    ]
    return "|".join(parts)


def candidate_site_key(candidate: dict[str, Any]) -> str:
    parts = [
        str(candidate.get("reason", "")),
        str(candidate.get("compat_sink_label") or candidate.get("suggested_sink_label", "")),
        str(candidate.get("function", "")),
        str(candidate.get("plain_line", "")),
        str(candidate.get("callee", "")),
        normalize_expr_for_key(str(candidate.get("callsite", ""))),
        str(candidate.get("pattern", "")),
    ]
    return "|".join(parts)


def dedupe_sink_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    by_key: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = sink_site_key(row)
        row["site_key"] = key
        row["dedupe_key"] = key
        existing = by_key.get(key)
        if existing is None:
            row["duplicate_count"] = 1
            by_key[key] = row
            deduped.append(row)
            continue
        existing["duplicate_count"] = int(existing.get("duplicate_count", 1)) + 1
        duplicate_ids = list(existing.get("duplicate_ids", []) or [])
        duplicate_ids.append(str(row.get("id", "")))
        existing["duplicate_ids"] = [dup for dup in duplicate_ids if dup]
    return deduped


def dedupe_candidates(candidates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    by_key: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        key = candidate_site_key(candidate)
        candidate["site_key"] = key
        candidate["dedupe_key"] = key
        existing = by_key.get(key)
        if existing is None:
            candidate["duplicate_count"] = 1
            by_key[key] = candidate
            deduped.append(candidate)
            continue
        existing["duplicate_count"] = int(existing.get("duplicate_count", 1)) + 1
        duplicate_ids = list(existing.get("duplicate_ids", []) or [])
        duplicate_ids.append(str(candidate.get("id", "")))
        existing["duplicate_ids"] = [dup for dup in duplicate_ids if dup]
    return deduped


def withdraw_reason_for_confirmed_sink(row: dict[str, Any]) -> str:
    vuln = list(row.get("vulnerable_parameters", []) or [])
    label = str(row.get("label", "") or "")
    roles = dict(row.get("roles", {}) or {})

    if vuln and all(bool(item.get("constant")) for item in vuln if str(item.get("expr", "")).strip()):
        return "all_vulnerable_parameters_constant"

    if label == "MEMSET_SINK":
        length = str(roles.get("len", "") or "")
        value = str(roles.get("value", "") or "")
        if length and is_constant_expr(length) and (not value or is_constant_expr(value)):
            return "constant_len_memset"

    return ""


def _pcode_call_rows(program_facts: dict[str, Any]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    rows: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for function in list(program_facts.get("functions", []) or []):
        function_name = str(function.get("name", ""))
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "CALL":
                continue
            call = dict(op.get("call", {}) or {})
            callee = str(call.get("target_function", ""))
            if not function_name or not callee:
                continue
            rows.setdefault((function_name, callee), []).append(
                {
                    "function_id": str(function.get("function_id", "")),
                    "site_id": str(op.get("site_id", "")),
                    "instruction_address": str(op.get("instruction_address", "")),
                    "callee_function_id": str(call.get("target_function_id", "")),
                    "argument_object_ids": list(call.get("argument_object_ids", []) or []),
                    "argument_value_ids": list(call.get("argument_value_ids", []) or []),
                    "argument_nodes": [dict(node or {}) for node in list(op.get("inputs", []) or [])[1:]],
                }
            )
    for calls in rows.values():
        calls.sort(key=lambda row: (row["instruction_address"], row["site_id"]))
    return rows


STORE_BINDING_KINDS = {"field_update_store", "loop_copy", "loop_write"}
STORE_SLICE_OPS = {
    "CAST",
    "COPY",
    "INDIRECT",
    "INT_ADD",
    "INT_AND",
    "INT_LEFT",
    "INT_MULT",
    "INT_OR",
    "INT_RIGHT",
    "INT_SEXT",
    "INT_SUB",
    "INT_XOR",
    "INT_ZEXT",
    "MULTIEQUAL",
    "PIECE",
    "PTRADD",
    "PTRSUB",
    "SUBPIECE",
}
IGNORED_STORE_ANCHORS = {
    "do",
    "else",
    "for",
    "if",
    "index",
    "j",
    "k",
    "null",
    "return",
    "sizeof",
    "unnamed",
    "while",
}


def _expr_identifiers(expr: str) -> set[str]:
    return {
        name
        for name in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", str(expr or ""))
        if name.lower() not in IGNORED_STORE_ANCHORS
        and name.lower() not in SIZE_HINT_TOKENS
        and not re.fullmatch(r"i\d*", name.lower())
    }


def _pcode_high_name(node: dict[str, Any]) -> str:
    name = str(node.get("high_name", "") or "").strip()
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) else ""


def _backward_slice_high_names(
    start_node: dict[str, Any], definitions: dict[str, dict[str, Any]], *, max_nodes: int = 96
) -> set[str]:
    """Collect exact High-variable names along a value-only backward slice."""

    names: set[str] = set()
    pending = [dict(start_node or {})]
    visited_values: set[str] = set()
    while pending and len(visited_values) < max_nodes:
        node = pending.pop()
        name = _pcode_high_name(node)
        if name and name.lower() not in IGNORED_STORE_ANCHORS:
            names.add(name)
        value_id = str(node.get("value_id", "") or "")
        if not value_id or value_id in visited_values:
            continue
        visited_values.add(value_id)
        producer = definitions.get(value_id)
        if not producer or str(producer.get("mnemonic", "")) not in STORE_SLICE_OPS:
            continue
        pending.extend(
            dict(item or {})
            for item in list(producer.get("inputs", []) or [])
            if not bool(dict(item or {}).get("is_constant"))
        )
    return names


def _store_bindings_by_function(program_facts: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    by_name: dict[str, list[dict[str, Any]]] = {}
    for function in list(program_facts.get("functions", []) or []):
        function_name = str(function.get("name", "") or "")
        if not function_name:
            continue
        ops = [dict(op or {}) for op in list(function.get("pcode_ops", []) or [])]
        definitions = {
            str(output.get("value_id", "")): op
            for op in ops
            if isinstance(op.get("output"), dict)
            for output in [dict(op.get("output") or {})]
            if str(output.get("value_id", ""))
        }
        stores: list[dict[str, Any]] = []
        for op in ops:
            if str(op.get("mnemonic", "")) != "STORE":
                continue
            inputs = [dict(node or {}) for node in list(op.get("inputs", []) or [])]
            if len(inputs) < 3:
                continue
            address_node = inputs[-2]
            value_node = inputs[-1]
            stores.append(
                {
                    "function_id": str(function.get("function_id", "")),
                    "site_id": str(op.get("site_id", "")),
                    "instruction_address": str(op.get("instruction_address", "")),
                    "address_node": address_node,
                    "value_node": value_node,
                    "address_high_names": _backward_slice_high_names(address_node, definitions),
                    "value_high_names": _backward_slice_high_names(value_node, definitions),
                }
            )
        by_name.setdefault(function_name, []).append(
            {
                "function_id": str(function.get("function_id", "")),
                "stores": stores,
            }
        )
    return by_name


def _store_binding_anchors(row: dict[str, Any]) -> tuple[set[str], set[str]]:
    kind = str(row.get("detection_kind", ""))
    if kind == "field_update_store":
        copied_local = str(row.get("copied_local", "") or "").strip()
        return ({copied_local} if copied_local else set()), set()

    roles = dict(row.get("roles", {}) or {})
    dst_names = _expr_identifiers(str(roles.get("dst", "")))
    value_expr = str(roles.get("src") or roles.get("value") or "")
    value_names = _expr_identifiers(value_expr)
    shared = dst_names & value_names
    return value_names - shared, dst_names - shared


def _node_identity(node: dict[str, Any]) -> dict[str, str]:
    return {
        key: str(node.get(key, "") or "")
        for key in ("object_id", "value_id")
        if str(node.get(key, "") or "")
    }


def _bind_store_sink_rows(rows: list[dict[str, Any]], program_facts: dict[str, Any]) -> None:
    functions = _store_bindings_by_function(program_facts)
    for row in rows:
        kind = str(row.get("detection_kind", ""))
        if kind not in STORE_BINDING_KINDS:
            continue
        function_name = str(row.get("function", "") or "")
        function_matches = functions.get(function_name, [])
        if len(function_matches) != 1:
            row["binding_status"] = (
                "ambiguous_store_function" if len(function_matches) > 1 else "unresolved_store_binding"
            )
            continue
        value_anchors, dst_anchors = _store_binding_anchors(row)
        if not value_anchors:
            row["binding_status"] = "unresolved_store_binding"
            continue
        candidates: list[dict[str, Any]] = []
        for store in list(function_matches[0].get("stores", []) or []):
            value_hits = value_anchors & set(store.get("value_high_names", set()) or set())
            if not value_hits:
                continue
            if kind in {"loop_copy", "loop_write"} and dst_anchors:
                dst_hits = dst_anchors & set(store.get("address_high_names", set()) or set())
                if not dst_hits:
                    continue
            candidate = dict(store)
            candidate["matched_value_high_names"] = sorted(value_hits)
            candidates.append(candidate)
        if len(candidates) != 1:
            row["binding_status"] = (
                "ambiguous_store_binding" if len(candidates) > 1 else "unresolved_store_binding"
            )
            row["store_binding_candidate_count"] = len(candidates)
            continue

        binding = candidates[0]
        old_site = str(row.get("site_id", "") or "")
        if old_site.startswith("textsite:"):
            row["text_site_id"] = old_site
        row["function_id"] = str(binding.get("function_id", ""))
        row["site_id"] = str(binding.get("site_id", ""))
        row["instruction_address"] = str(binding.get("instruction_address", ""))
        row["binding_status"] = "verified_high_pcode_store"
        row["binding_method"] = "unique_store_value_backward_slice"
        row["matched_value_high_names"] = list(binding.get("matched_value_high_names", []) or [])

        dst_identity = _node_identity(dict(binding.get("address_node", {}) or {}))
        value_identity = _node_identity(dict(binding.get("value_node", {}) or {}))
        role_bindings = {
            "dst": dst_identity,
            "value": value_identity,
        }
        if kind == "loop_copy":
            role_bindings["src"] = value_identity
        row["role_bindings"] = role_bindings
        for parameter in list(row.get("vulnerable_parameters", []) or []):
            role = str(parameter.get("role", ""))
            identity = dst_identity if role == "dst" else value_identity if role in {"src", "value"} else {}
            parameter.update(identity)


def bind_sink_rows_to_program_facts(
    rows: list[dict[str, Any]], program_facts: dict[str, Any]
) -> None:
    """Attach stable callsite and actual-argument identities to sink rows.

    Decompiled-C line numbers remain review evidence. High P-code SiteId and
    ValueId are the analysis identities consumed by the backward DFA.
    """
    if not program_facts:
        return
    calls_by_key = _pcode_call_rows(program_facts)
    rows_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        if str(row.get("detection_kind", "")) in STORE_BINDING_KINDS:
            continue
        callee = str(row.get("callee", ""))
        function = str(row.get("function", ""))
        if callee and function:
            rows_by_key.setdefault((function, callee), []).append(row)

    def binding_score(row: dict[str, Any], binding: dict[str, Any]) -> int:
        score = 0
        nodes = list(binding.get("argument_nodes", []) or [])
        args = list(row.get("args", []) or [])
        for index, expr in enumerate(args):
            if index >= len(nodes):
                continue
            expression_constant = is_constant_expr(str(expr))
            node = dict(nodes[index] or {})
            node_constant = bool(node.get("is_constant")) or str(node.get("space", "")) == "const"
            score += 4 if expression_constant == node_constant else -4
            high_name = normalize_expr_for_key(str(node.get("high_name", "")))
            if high_name and high_name in normalize_expr_for_key(str(expr)):
                score += 2
        return score

    for key, grouped_rows in rows_by_key.items():
        grouped_rows.sort(key=lambda row: (int(row.get("plain_line", 0) or 0), str(row.get("expr", ""))))
        all_calls = list(calls_by_key.get(key, []))
        remaining_calls = list(all_calls)
        ordinal_binding = len(grouped_rows) == len(all_calls) and bool(all_calls)
        for ordinal, row in enumerate(grouped_rows):
            if not remaining_calls:
                row.setdefault("binding_status", "unresolved_callsite")
                continue
            scored = [(binding_score(row, item), item) for item in remaining_calls]
            best_score = max(score for score, _item in scored)
            best = [item for score, item in scored if score == best_score]
            if len(best) == 1:
                binding = best[0]
                binding_method = "unique_best_argument_shape"
            elif ordinal_binding:
                ordinal_candidate = all_calls[ordinal]
                binding = (
                    ordinal_candidate
                    if ordinal_candidate in remaining_calls
                    else remaining_calls[0]
                )
                binding_method = "decompiler_call_ordinal_tiebreak"
            else:
                    row.setdefault("binding_status", "ambiguous_callsite")
                    row["binding_score"] = best_score
                    continue
            best_score = binding_score(row, binding)
            if best_score <= 0:
                row.setdefault("binding_status", "unresolved_callsite")
                row["binding_score"] = best_score
                continue
            remaining_calls.remove(binding)
            row["function_id"] = binding["function_id"]
            row["site_id"] = binding["site_id"]
            row["callee_function_id"] = binding["callee_function_id"]
            row["binding_status"] = "verified_high_pcode_callsite"
            row["binding_score"] = best_score
            row["binding_method"] = binding_method
            object_ids = binding["argument_object_ids"]
            value_ids = binding["argument_value_ids"]
            for parameter in list(row.get("vulnerable_parameters", []) or []):
                arg_index = parameter.get("index")
                if not isinstance(arg_index, int) or arg_index < 0:
                    continue
                if arg_index < len(object_ids):
                    parameter["object_id"] = str(object_ids[arg_index])
                if arg_index < len(value_ids):
                    parameter["value_id"] = str(value_ids[arg_index])
    _bind_store_sink_rows(rows, program_facts)


def _assignment_roles(expr: str) -> dict[str, str]:
    first = str(expr or "").split(";", 1)[0].strip()
    parsed = assignment_parts(first + ";")
    if not parsed:
        return {}
    lhs, rhs = parsed
    return {"dst": lhs, "src": rhs, "value": rhs}


def heuristic_sink_row(candidate: dict[str, Any], sink_id: str) -> dict[str, Any] | None:
    """Promote generalized structural candidates to DFA startpoints.

    Name-only semantic API candidates are intentionally not promoted. The
    accepted classes are based on assignment/loop/parser structure and remain
    explicitly heuristic; they do not assert vulnerability semantics.
    """
    reason = str(candidate.get("reason", ""))
    semantic_hint = str(candidate.get("semantic_hint_label", ""))
    if semantic_hint == "peripheral_buffer_fill":
        return None
    accepted_reasons = {
        "pattern_loop_write",
        "pattern_parser_store",
        "pattern_unbounded_walk",
    }
    if reason not in accepted_reasons:
        return None
    label = str(candidate.get("compat_sink_label") or candidate.get("suggested_sink_label") or "")
    if label not in DEFAULT_VULNERABLE_ROLES_BY_LABEL:
        return None
    expr = str(candidate.get("callsite", ""))
    roles = _assignment_roles(expr)
    if reason == "pattern_unbounded_walk":
        roles = {"src": expr, "len": expr}
    elif reason == "pattern_parser_store" and roles:
        roles = {"dst": roles["dst"], "value": roles["value"], "src": roles["src"]}
    vulnerable_roles = [role for role in vulnerable_roles_for_label(label) if role in roles]
    if not vulnerable_roles:
        vulnerable_roles = list(roles)
    row = confirmed_sink_row(
        sink_id=sink_id,
        detection_kind=str(candidate.get("pattern", "structural_pattern")),
        confirmation_source="generalized_structural_heuristic",
        label=label,
        sink_kind="structural_heuristic_sink_startpoint",
        callee=str(candidate.get("callee", "")),
        function=str(candidate.get("function", "")),
        plain_line=int(candidate.get("plain_line", 0) or 0),
        args=list(candidate.get("actual_args", []) or []),
        roles=roles,
        expr=expr,
        vulnerable_roles=vulnerable_roles,
        extra={
            "decision": "ACCEPT_HEURISTIC",
            "evidence_level": "HEURISTIC_STRUCTURAL",
            "rule_id": f"SINK_{str(candidate.get('pattern', reason)).upper()}",
            "origin_candidate_id": str(candidate.get("id", "")),
            "known_facts": list(candidate.get("known_facts", []) or []),
        },
    )
    row["site_id"] = str(candidate.get("site_id", "") or f"textsite:{candidate_site_key(candidate)}")
    return row


def filter_confirmed_sink_startpoints(
    rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, int]]:
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    withdrawn: dict[str, int] = {}
    for row in rows:
        reason = withdraw_reason_for_confirmed_sink(row)
        if reason:
            withdrawn[reason] = withdrawn.get(reason, 0) + 1
            rejected = dict(row)
            rejected["decision"] = "DROP_LOCAL_HEURISTIC"
            rejected["drop_reason"] = reason
            rejected["evidence_level"] = "LOCAL_CONSTANT_ARGUMENT_FILTER"
            dropped.append(rejected)
            continue
        kept.append(row)
    return kept, dropped, withdrawn


def count_braces(line: str) -> int:
    line = re.sub(r"/\*.*?\*/", "", line)
    line = re.sub(r'".*?"', '""', line)
    line = re.sub(r"'.*?'", "''", line)
    return line.count("{") - line.count("}")


def split_args(arg_text: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depth = 0
    in_string = False
    in_char = False
    escape = False
    for ch in arg_text:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == "\\":
            current.append(ch)
            escape = True
            continue
        if ch == '"' and not in_char:
            in_string = not in_string
            current.append(ch)
            continue
        if ch == "'" and not in_string:
            in_char = not in_char
            current.append(ch)
            continue
        if in_string or in_char:
            current.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            args.append(clean_expr("".join(current)))
            current = []
        else:
            current.append(ch)
    tail = clean_expr("".join(current))
    if tail:
        args.append(tail)
    return args


def extract_signature(lines: list[str], brace_idx: int) -> tuple[int, str, str, list[str]]:
    start = brace_idx - 1
    while start >= 0:
        stripped = lines[start].strip()
        if not stripped:
            if start < brace_idx - 1:
                break
        elif stripped == "}" or stripped.startswith("} /*"):
            break
        elif stripped.startswith("/*") and stripped.endswith("*/"):
            if start < brace_idx - 1:
                break
        start -= 1
    start += 1

    sig_lines = [ln.strip() for ln in lines[start:brace_idx] if ln.strip()]
    signature = " ".join(sig_lines)
    signature = re.sub(r"/\*.*?\*/", " ", signature)
    signature = re.sub(r"\s+", " ", signature).strip()
    name = parse_function_name(signature)
    params = parse_params(signature)
    return start + 1, name, signature, params


def parse_function_name(signature: str) -> str:
    if "(" not in signature:
        return ""
    before = signature.split("(", 1)[0]
    names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", before)
    if not names:
        return ""
    return names[-1]


def parse_params(signature: str) -> list[str]:
    if "(" not in signature or ")" not in signature:
        return []
    params_text = signature.split("(", 1)[1].rsplit(")", 1)[0]
    params: list[str] = []
    for raw in split_args(params_text):
        raw = raw.strip()
        if not raw or raw == "void":
            continue
        ids = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", raw)
        if not ids:
            continue
        name = ids[-1]
        if name in {"void", "int", "char", "long", "short", "const", "volatile", "unsigned", "signed"}:
            continue
        params.append(name)
    return params


def parse_functions(lines: list[str]) -> list[FunctionRecord]:
    functions: list[FunctionRecord] = []
    current_start = 0
    current_body = 0
    current_name = ""
    current_sig = ""
    current_params: list[str] = []
    depth = 0
    in_func = False
    for idx, line in enumerate(lines):
        line_no = idx + 1
        stripped = line.strip()
        if not in_func and stripped == "{":
            start_line, name, signature, params = extract_signature(lines, idx)
            if name and name not in CONTROL_WORDS:
                in_func = True
                depth = 1
                current_start = start_line
                current_body = line_no
                current_name = name
                current_sig = signature
                current_params = params
            continue
        if not in_func:
            continue
        depth += count_braces(line)
        if stripped == "{":
            depth = 1
        if depth <= 0:
            functions.append(
                FunctionRecord(
                    name=current_name,
                    signature=current_sig,
                    params=current_params,
                    start_line=current_start,
                    body_start_line=current_body,
                    end_line=line_no,
                    lines=lines[current_start - 1:line_no],
                )
            )
            in_func = False
            depth = 0
    return functions


def find_matching_paren(text: str, open_idx: int) -> int:
    depth = 0
    in_string = False
    in_char = False
    escape = False
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == '"' and not in_char:
            in_string = not in_string
            continue
        if ch == "'" and not in_string:
            in_char = not in_char
            continue
        if in_string or in_char:
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def line_for_offset(text: str, base_line: int, offset: int) -> int:
    return base_line + text.count("\n", 0, offset)


def mask_non_code(text: str) -> str:
    """Replace comments and literal contents with spaces while preserving offsets."""

    out = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        ch = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "*":
                out[index] = out[index + 1] = " "
                state = "block_comment"
                index += 2
                continue
            if ch == "/" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "line_comment"
                index += 2
                continue
            if ch in {'"', "'"}:
                quote = ch
                out[index] = " "
                state = "literal"
                index += 1
                continue
        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "code"
                index += 2
                continue
            if ch != "\n":
                out[index] = " "
        elif state == "line_comment":
            if ch == "\n":
                state = "code"
            else:
                out[index] = " "
        elif state == "literal":
            if ch == "\\" and index + 1 < len(text):
                out[index] = " "
                if text[index + 1] != "\n":
                    out[index + 1] = " "
                index += 2
                continue
            if ch == quote:
                out[index] = " "
                state = "code"
            elif ch != "\n":
                out[index] = " "
        index += 1
    return "".join(out)


def find_calls_in_function(func: FunctionRecord, callees: set[str]) -> list[Callsite]:
    text = "".join(func.lines)
    searchable = mask_non_code(text)
    base_line = func.start_line
    calls: list[Callsite] = []
    seen: set[tuple[str, int, str]] = set()
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in pattern.finditer(searchable):
        callee = match.group(1)
        if callee not in callees:
            continue
        open_idx = searchable.find("(", match.start(1))
        close_idx = find_matching_paren(searchable, open_idx)
        if close_idx < 0:
            continue
        arg_text = text[open_idx + 1:close_idx]
        args = split_args(arg_text)
        line = line_for_offset(text, base_line, match.start())
        expr_end = close_idx + 1
        expr = clean_expr(text[match.start():expr_end])
        key = (callee, line, expr)
        if key in seen:
            continue
        seen.add(key)
        calls.append(Callsite(callee=callee, args=args, function=func.name, line=line, expr=expr, call_start=match.start()))
    return calls


def find_all_calls_in_function(func: FunctionRecord) -> list[Callsite]:
    text = "".join(func.lines)
    searchable = mask_non_code(text)
    base_line = func.start_line
    calls: list[Callsite] = []
    seen: set[tuple[str, int, str]] = set()
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in pattern.finditer(searchable):
        callee = match.group(1)
        if callee in CONTROL_WORDS:
            continue
        if callee == func.name and line_for_offset(text, base_line, match.start()) == func.start_line:
            continue
        open_idx = searchable.find("(", match.start(1))
        close_idx = find_matching_paren(searchable, open_idx)
        if close_idx < 0:
            continue
        arg_text = text[open_idx + 1:close_idx]
        args = split_args(arg_text)
        line = line_for_offset(text, base_line, match.start())
        expr_end = close_idx + 1
        expr = clean_expr(text[match.start():expr_end])
        key = (callee, line, expr)
        if key in seen:
            continue
        seen.add(key)
        calls.append(Callsite(callee=callee, args=args, function=func.name, line=line, expr=expr, call_start=match.start()))
    return calls


def role_from_spec(args: list[str], spec: dict[str, Any], key: str) -> str:
    expr_key = f"{key}_expr"
    if expr_key in spec:
        return str(spec[expr_key])
    idx = spec.get(f"{key}_arg")
    if idx is None:
        return ""
    if not isinstance(idx, int) or idx < 0 or idx >= len(args):
        return ""
    return args[idx]


def roles_for_call(call: Callsite, spec: dict[str, Any]) -> dict[str, str]:
    roles: dict[str, str] = {}
    for key in ("dst", "src", "len", "fmt", "value"):
        val = role_from_spec(call.args, spec, key)
        if val:
            roles[key] = val
    return roles


def map_expr_to_formals(expr: str, params: list[str], local_aliases: dict[str, str]) -> tuple[str, int]:
    mapped = expr
    hits = 0
    for local, replacement in local_aliases.items():
        mapped = re.sub(rf"\b{re.escape(local)}\b", replacement, mapped)
    for idx, param in enumerate(params):
        if re.search(rf"\b{re.escape(param)}\b", mapped):
            mapped = re.sub(rf"\b{re.escape(param)}\b", f"arg{idx}", mapped)
            hits += 1
    return mapped, hits


def local_aliases_for_function(func: FunctionRecord) -> dict[str, str]:
    aliases: dict[str, str] = {}
    text = "".join(func.lines)
    for idx, param in enumerate(func.params):
        for match in re.finditer(
            rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^;=]+\)\s*)?{re.escape(param)}\s*;",
            text,
        ):
            aliases[match.group(1)] = f"arg{idx}"
        for match in re.finditer(rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{re.escape(param)}->len\s*;", text):
            aliases[match.group(1)] = f"arg{idx}->len"
        for match in re.finditer(rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{re.escape(param)}->data\s*;", text):
            aliases[match.group(1)] = f"arg{idx}->data"
    return aliases


def discover_wrappers(functions: list[FunctionRecord], primitive_calls: list[Callsite]) -> list[WrapperSummary]:
    calls_by_func: dict[str, list[Callsite]] = {}
    for call in primitive_calls:
        calls_by_func.setdefault(call.function, []).append(call)
    funcs_by_name = {f.name: f for f in functions}
    wrappers: list[WrapperSummary] = []
    next_id = 1
    for func_name, calls in sorted(calls_by_func.items(), key=lambda item: funcs_by_name[item[0]].start_line):
        func = funcs_by_name.get(func_name)
        if not func or func_name in PRIMITIVE_SINK_SPECS:
            continue
        code_lines = [ln for ln in func.lines if ln.strip() and not ln.strip().startswith("/*")]
        if len(code_lines) > 140:
            continue
        aliases = local_aliases_for_function(func)
        for call in calls:
            spec = PRIMITIVE_SINK_SPECS[call.callee]
            raw_roles = roles_for_call(call, spec)
            mapped_roles: dict[str, str] = {}
            for role, expr in raw_roles.items():
                mapped, _ = map_expr_to_formals(expr, func.params, aliases)
                mapped_roles[role] = mapped
            required_roles = set(vulnerable_roles_for_spec(str(spec.get("label", "")), spec))
            if "dst" in raw_roles:
                required_roles.add("dst")
            roles_proved = all(
                role not in raw_roles
                or is_constant_expr(raw_roles[role])
                or re.search(r"\barg\d+\b", mapped_roles.get(role, "")) is not None
                for role in required_roles
            )
            if not roles_proved:
                continue
            wrapper_id = f"W{next_id:04d}"
            next_id += 1
            wrappers.append(
                WrapperSummary(
                    id=wrapper_id,
                    function=func.name,
                    function_line=func.start_line,
                    kind="wrapper_memory_sink",
                    inner_sink={
                        "callee": call.callee,
                        "line": call.line,
                        "expr": call.expr,
                        "label": str(spec.get("label", "")),
                        "kind": str(spec.get("kind", "")),
                        "vulnerable_parameter_roles": vulnerable_roles_for_spec(
                            str(spec.get("label", "")), spec
                        ),
                    },
                    roles=mapped_roles,
                    evidence=[call.expr],
                )
            )
            break
    return wrappers


def detect_dispatches(functions: list[FunctionRecord]) -> list[dict[str, Any]]:
    dispatches: list[dict[str, Any]] = []
    patterns = [
        ("casted_function_pointer_call", re.compile(r"\(\*\*\s*\(\s*code\s*\*\*\s*\)[^;]*\)\s*\(")),
        ("function_pointer_call", re.compile(r"\(\*\s*[A-Za-z_][A-Za-z0-9_]*\s*\)\s*\(")),
    ]
    seen: set[tuple[str, int, str]] = set()
    for func in functions:
        for offset, line in enumerate(func.lines):
            line_no = func.start_line + offset
            for kind, pattern in patterns:
                if not pattern.search(line):
                    continue
                expr = clean_expr(line.strip().rstrip(";"))
                key = (func.name, line_no, expr)
                if key in seen:
                    continue
                seen.add(key)
                dispatches.append(
                    {
                        "kind": "indirect_dispatch",
                        "pattern": kind,
                        "function": func.name,
                        "plain_line": line_no,
                        "expr": expr,
                        "status": "unresolved",
                    }
                )
    return dispatches


def comment_for_roles(roles: dict[str, str]) -> str:
    parts = []
    for key in ("dst", "src", "len", "fmt", "value"):
        if key in roles:
            parts.append(f"{key}={roles[key]}")
    return " ".join(parts)


def annotate_lines(lines: list[str], annotations: dict[int, list[str]]) -> list[str]:
    out = list(lines)
    for line_no in sorted(annotations):
        idx = line_no - 1
        if idx < 0 or idx >= len(out):
            continue
        line = out[idx].rstrip("\n")
        suffix = " ".join(f"/* {comment} */" for comment in annotations[line_no])
        out[idx] = f"{line} {suffix}\n"
    return out


def confirmation_source_for_primitive(callee: str, spec: dict[str, Any]) -> str:
    kind = str(spec.get("kind", ""))
    if callee.startswith("__") or "aeabi" in callee or kind.startswith("compiler_"):
        return "compiler_intrinsic"
    return "direct_api"


def confirmed_sink_row(
    *,
    sink_id: str,
    detection_kind: str,
    confirmation_source: str,
    label: str,
    sink_kind: str,
    callee: str,
    function: str,
    plain_line: int,
    args: list[str],
    roles: dict[str, str],
    expr: str,
    spec: dict[str, Any] | None = None,
    vulnerable_roles: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    vuln_roles = (
        vulnerable_roles
        if vulnerable_roles is not None
        else vulnerable_roles_for_spec(label, spec)
    )
    row: dict[str, Any] = {
        "id": sink_id,
        "detection_kind": detection_kind,
        "confirmation_source": confirmation_source,
        "label": label,
        "sink_kind": sink_kind,
        "callee": callee,
        "function": function,
        "plain_line": plain_line,
        "args": args,
        "roles": roles,
        "vulnerable_parameter_roles": vuln_roles,
        "vulnerable_parameters": build_vulnerable_parameters(
            label=label,
            args=args,
            roles=roles,
            spec=spec,
            vulnerable_roles=vuln_roles,
        ),
        "expr": expr,
        "taint_status": "not_evaluated",
        "guard_status": "unknown",
        "vulnerability_status": "not_evaluated",
        "decision": "ACCEPT_DETERMINISTIC",
        "evidence_level": "DETERMINISTIC_SEMANTICS",
        "rule_id": f"SINK_{detection_kind.upper()}",
    }
    if extra:
        row.update(extra)
    return row


def call_key(call: Callsite) -> tuple[str, int, str, str]:
    return (call.function, call.line, call.callee, call.expr)


def lowered_tokens(text: str) -> set[str]:
    return {tok.lower() for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)}


def has_semantic_callee_trigger(callee: str) -> bool:
    lowered = callee.lower()
    tokens = lowered_tokens(lowered)
    if tokens & SEMANTIC_CANDIDATE_TOKENS:
        return True
    return any(token in lowered for token in SEMANTIC_CANDIDATE_TOKENS)


def is_pointer_like_arg(arg: str) -> bool:
    lowered = arg.lower()
    if any(op in arg for op in ("&", "*", "->", "[", "]", "+")):
        return True
    return bool(lowered_tokens(lowered) & POINTER_HINT_TOKENS)


def is_size_like_arg(arg: str) -> bool:
    stripped = arg.strip()
    if re.fullmatch(r"(0x[0-9a-fA-F]+|\d+)", stripped):
        return True
    lowered = stripped.lower()
    return bool(lowered_tokens(lowered) & SIZE_HINT_TOKENS)


def function_definition(functions_by_name: dict[str, FunctionRecord], name: str) -> str:
    func = functions_by_name.get(name)
    if not func:
        return ""
    return "".join(func.lines).rstrip()


def nested_definitions_for_candidate(
    functions_by_name: dict[str, FunctionRecord],
    callee: str,
    *,
    known_names: set[str],
    limit: int = 3,
) -> list[dict[str, str]]:
    func = functions_by_name.get(callee)
    if not func:
        return []
    nested: list[dict[str, str]] = []
    seen: set[str] = set()
    for call in find_all_calls_in_function(func):
        if call.callee in seen or call.callee in known_names or call.callee == callee:
            continue
        if call.callee not in functions_by_name:
            continue
        seen.add(call.callee)
        nested.append(
            {
                "callee": call.callee,
                "callsite": call.expr,
                "definition": function_definition(functions_by_name, call.callee),
            }
        )
        if len(nested) >= limit:
            break
    return nested


def make_candidate(
    *,
    candidate_number: int,
    reason: str,
    function: str,
    plain_line: int,
    callee: str,
    callsite: str,
    actual_args: list[str],
    callee_definition: str,
    known_facts: list[str],
    questions: list[str],
    suggested_sink_label: str = "",
    compat_sink_label: str = "",
    semantic_hint_label: str = "",
    pattern: str = "",
    nested_definitions: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    candidate: dict[str, Any] = {
        "id": f"U{candidate_number:04d}",
        "reason": reason,
        "function": function,
        "plain_line": plain_line,
        "callee": callee,
        "callsite": callsite,
        "actual_args": actual_args,
        "callee_definition": callee_definition,
        "nested_definitions": nested_definitions or [],
        "known_facts": known_facts,
        "questions": questions,
        "resolution_status": "requires_llm_or_review",
    }
    if compat_sink_label:
        candidate["compat_sink_label"] = compat_sink_label
    if suggested_sink_label:
        candidate["suggested_sink_label"] = suggested_sink_label
    if semantic_hint_label:
        candidate["semantic_hint_label"] = semantic_hint_label
    if pattern:
        candidate["pattern"] = pattern
    return candidate


def strip_casts_and_parens(expr: str) -> str:
    text = clean_expr(expr)
    changed = True
    while changed:
        changed = False
        new_text = re.sub(r"^\(\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s*\)\s*", "", text).strip()
        if new_text != text:
            text = new_text
            changed = True
        if text.startswith("(") and text.endswith(")"):
            close = find_matching_paren(text, 0)
            if close == len(text) - 1:
                text = text[1:-1].strip()
                changed = True
    return text


def assignment_parts(line: str) -> tuple[str, str] | None:
    stripped = line.strip().rstrip(";")
    if not stripped or "=" not in stripped:
        return None
    if re.search(r"(==|!=|<=|>=|\+=|-=|\*=|/=|%=)", stripped):
        return None
    left, right = stripped.split("=", 1)
    left = clean_expr(left)
    right = clean_expr(right)
    if not left or not right:
        return None
    return left, right


def store_assignment_parts(line: str) -> tuple[str, str, str] | None:
    """Parse ordinary and compound assignment statements.

    This is intentionally statement-level and conservative.  It is used for
    STORE_SINK pattern mining, where field updates such as:

      obj->field = value + obj->field;
      obj->field += value;

    should be visible without inventing a new CopperTrace sink label.
    """
    stripped = line.strip().rstrip(";")
    if not stripped or "=" not in stripped:
        return None
    if re.search(r"(==|!=|<=|>=)", stripped):
        return None
    match = re.match(
        r"^(?P<lhs>.+?)\s*(?P<op>\+=|-=|\*=|/=|%=|=)\s*(?P<rhs>.+)$",
        stripped,
    )
    if not match:
        return None
    lhs = clean_expr(match.group("lhs"))
    op = match.group("op")
    rhs = clean_expr(match.group("rhs"))
    if not lhs or not rhs:
        return None
    return lhs, op, rhs


def line_has_loop_keyword(line: str) -> bool:
    stripped = line.strip()
    return bool(re.search(r"\b(for|while)\s*\(", stripped) or stripped.startswith("do"))


def nearest_loop_line(func: FunctionRecord, offset: int, *, radius: int = 8) -> tuple[int, str] | None:
    start = max(0, offset - radius)
    end = min(len(func.lines), offset + radius + 1)
    for idx in range(start, end):
        if line_has_loop_keyword(func.lines[idx]):
            return func.start_line + idx, clean_expr(func.lines[idx].strip())
    return None


def statement_context(func: FunctionRecord, offset: int, *, radius: int = 4) -> str:
    start = max(0, offset - radius)
    end = min(len(func.lines), offset + radius + 1)
    return "".join(func.lines[start:end]).strip()


def is_loop_write_lhs(lhs: str) -> bool:
    stripped = lhs.strip()
    if "[" in stripped and "]" in stripped:
        return True
    if stripped.startswith("*"):
        return True
    return False


def rhs_looks_like_source(rhs: str) -> bool:
    if "[" in rhs and "]" in rhs:
        return True
    if "*" in rhs:
        return True
    if "->" in rhs or "." in rhs:
        return True
    return bool(lowered_tokens(rhs) & POINTER_HINT_TOKENS)


def rhs_looks_peripheral_read(rhs: str) -> bool:
    text = rhs.upper()
    peripheral_markers = (
        "SPI_RDR",
        "_RDR",
        "UART",
        "USART",
        "FIFO",
        "I2C",
        "RXD",
        "RXDR",
    )
    marker_hit = any(marker in text for marker in peripheral_markers)
    pointer_register_access = "->" in rhs or re.search(r"\*\s*\([^)]*volatile", rhs, re.I)
    return bool(marker_hit and pointer_register_access)


def detect_loop_write_candidates(
    functions: list[FunctionRecord],
    functions_by_name: dict[str, FunctionRecord],
    *,
    start_index: int,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    next_id = start_index
    for func in functions:
        stores: list[dict[str, Any]] = []
        for offset, line in enumerate(func.lines):
            parts = assignment_parts(line)
            if not parts:
                continue
            lhs, rhs = parts
            if not is_loop_write_lhs(lhs):
                continue
            loop = nearest_loop_line(func, offset)
            if not loop:
                continue
            line_no = func.start_line + offset
            loop_line, loop_expr = loop
            pattern = "loop_copy" if rhs_looks_like_source(rhs) else "loop_write"
            stores.append(
                {
                    "line": line_no,
                    "lhs": lhs,
                    "rhs": rhs,
                    "loop_line": loop_line,
                    "loop_expr": loop_expr,
                    "pattern": pattern,
                }
            )
        if not stores:
            continue
        first = stores[0]
        has_copy = any(store["pattern"] == "loop_copy" for store in stores)
        has_peripheral_rhs = any(rhs_looks_peripheral_read(str(store["rhs"])) for store in stores)
        label = "COPY_SINK" if has_copy and not has_peripheral_rhs else "LOOP_WRITE_SINK"
        known_facts = [
            f"loop write/copy stores in function: {len(stores)}",
            "structural detector only; semantic confirmation is required",
        ]
        seen_loop_lines: set[int] = set()
        for store in stores[:10]:
            if int(store["loop_line"]) not in seen_loop_lines:
                known_facts.append(f"loop context at line {store['loop_line']}: {store['loop_expr']}")
                seen_loop_lines.add(int(store["loop_line"]))
            known_facts.append(f"loop store at line {store['line']}: {store['lhs']} = {store['rhs']}")
            rhs = str(store["rhs"])
            if "SPI_RDR" in rhs or "_RDR" in rhs or "UART" in rhs or "FIFO" in rhs:
                known_facts.append("rhs looks like a peripheral/MMIO register read; this may be producer evidence rather than final vulnerability sink")
        semantic_hint = "peripheral_buffer_fill" if has_peripheral_rhs else ""
        callsite = " ; ".join(
            f"{store['lhs']} = {store['rhs']}" for store in stores[:4]
        )
        candidates.append(
            make_candidate(
                candidate_number=next_id,
                reason="pattern_loop_write",
                function=func.name,
                plain_line=int(first["line"]),
                callee=func.name,
                callsite=callsite,
                actual_args=func.params,
                callee_definition=function_definition(functions_by_name, func.name),
                known_facts=known_facts,
                questions=[
                    "Does this function contain memory write/copy sink semantics in a loop?",
                    "If yes, identify dst/src/value/len or loop-bound roles.",
                    "If it is only peripheral producer evidence, mark unresolved or explain the limitation.",
                ],
                compat_sink_label=label,
                suggested_sink_label=label,
                semantic_hint_label=semantic_hint,
                pattern="loop_copy" if has_copy else "loop_write",
            )
        )
        next_id += 1
    return candidates


def buffer_like_params(func: FunctionRecord) -> set[str]:
    out: set[str] = set()
    for param in func.params:
        lowered = param.lower()
        if lowered_tokens(lowered) & POINTER_HINT_TOKENS:
            out.add(param)
        if lowered in {"buf", "buffer", "data", "payload", "packet", "pucbyte"}:
            out.add(param)
    return out


def field_name(expr: str) -> str:
    match = re.search(r"(?:->|\.)([A-Za-z_][A-Za-z0-9_]*)", expr)
    return match.group(1) if match else ""


def detect_parser_store_candidates(
    functions: list[FunctionRecord],
    functions_by_name: dict[str, FunctionRecord],
    *,
    start_index: int,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    next_id = start_index
    for func in functions:
        buffers = buffer_like_params(func)
        if not buffers:
            continue
        stores: list[dict[str, Any]] = []
        for offset, line in enumerate(func.lines):
            parts = assignment_parts(line)
            if not parts:
                continue
            lhs, rhs = parts
            if "->" not in lhs and "." not in lhs:
                continue
            src_tokens = lowered_tokens(rhs)
            matched_buffers = [buf for buf in buffers if re.search(rf"\b{re.escape(buf)}\b", rhs)]
            if not matched_buffers:
                continue
            if "[" not in rhs and "+" not in rhs and "*" not in rhs:
                continue
            stores.append(
                {
                    "line": func.start_line + offset,
                    "dst": lhs,
                    "src": rhs,
                    "field": field_name(lhs),
                    "buffers": matched_buffers,
                    "source_tokens": sorted(src_tokens),
                }
            )
        if not stores:
            continue
        used_later: list[str] = []
        for store in stores:
            field = str(store.get("field", ""))
            if not field:
                continue
            later_text = "\n".join(func.lines[max(0, int(store["line"]) - func.start_line + 1):])
            if re.search(rf"\b{re.escape(field)}\b", later_text):
                for raw_line in later_text.splitlines():
                    if field in raw_line and ("while" in raw_line or "for" in raw_line or "<" in raw_line or ">" in raw_line):
                        used_later.append(clean_expr(raw_line.strip()))
                        break
        callsite = " ; ".join(
            f"{s['dst']} = {s['src']}" for s in stores[:4]
        )
        known_facts = [
            f"buffer-like formal params: {', '.join(sorted(buffers))}",
            f"parser field stores from buffer: {len(stores)}",
        ]
        for store in stores[:8]:
            known_facts.append(f"line {store['line']}: {store['dst']} = {store['src']}")
        for use in used_later[:4]:
            known_facts.append(f"stored field appears in later bound/control expression: {use}")
        candidates.append(
            make_candidate(
                candidate_number=next_id,
                reason="pattern_parser_store",
                function=func.name,
                plain_line=int(stores[0]["line"]),
                callee=func.name,
                callsite=callsite,
                actual_args=func.params,
                callee_definition=function_definition(functions_by_name, func.name),
                known_facts=known_facts,
                questions=[
                    "Does this function parse external bytes into struct fields or parser state?",
                    "If yes, identify dst fields, src buffer bytes, and any length/bound/control fields.",
                    "Does this look like a parser/store sink or only benign decoding?",
                ],
                compat_sink_label="STORE_SINK",
                suggested_sink_label="STORE_SINK",
                semantic_hint_label="PARSING_OVERFLOW_SINK",
                pattern="parser_field_store",
            )
        )
        next_id += 1
    return candidates


def local_var_from_address_expr(expr: str) -> str:
    text = strip_casts_and_parens(expr)
    text = text.strip()
    # &credits, (void *)&credits, &(credits)
    match = re.match(r"^&\s*\(?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)?$", text)
    if match:
        return match.group(1)
    return ""


def expr_mentions_any_identifier(expr: str, names: set[str]) -> list[str]:
    hits: list[str] = []
    for name in sorted(names):
        if re.search(rf"\b{re.escape(name)}\b(?!\s*(?:->|\.|\[))", expr):
            hits.append(name)
    return hits


def src_looks_input_derived(src: str, func: FunctionRecord) -> bool:
    text = src.strip()
    if not text:
        return False
    for param in func.params:
        if re.search(rf"\b{re.escape(param)}\b", text):
            return True
    lowered = text.lower()
    if lowered_tokens(lowered) & POINTER_HINT_TOKENS:
        return True
    return False


def copied_locals_from_input(func: FunctionRecord) -> dict[str, dict[str, Any]]:
    """Recover simple local scalar definitions copied from input buffers.

    Example:
      memcpy(&credits, data + 5, 2);
      ... credits ...

    This keeps the new detector aligned with CopperTrace's existing COPY_SINK
    facts: we reuse primitive copy roles, then mine a STORE_SINK only when a
    copied local flows into a field update.
    """
    copied: dict[str, dict[str, Any]] = {}
    calls = find_calls_in_function(func, set(PRIMITIVE_SINK_SPECS))
    for call in calls:
        spec = PRIMITIVE_SINK_SPECS.get(call.callee, {})
        if str(spec.get("label", "")) != "COPY_SINK":
            continue
        roles = roles_for_call(call, spec)
        dst = roles.get("dst", "")
        src = roles.get("src", "")
        if not dst or not src:
            continue
        local = local_var_from_address_expr(dst)
        if not local:
            continue
        if not src_looks_input_derived(src, func):
            continue
        copied[local] = {
            "local": local,
            "src": src,
            "line": call.line,
            "expr": call.expr,
            "callee": call.callee,
            "roles": roles,
        }
    return copied


def lhs_is_field_store(lhs: str) -> bool:
    text = lhs.strip()
    if "->" in text or "." in text:
        return True
    return False


def detect_field_update_store_sinks(
    functions: list[FunctionRecord],
    *,
    start_sink_index: int,
) -> tuple[list[dict[str, Any]], dict[int, list[str]], int]:
    """Confirm STORE_SINK rows for input-derived local -> object field updates.

    This follows the existing CopperTrace taxonomy (`STORE_SINK`) and adds a
    missing detector pattern, not a new sink label.
    """
    confirmed: list[dict[str, Any]] = []
    annotations: dict[int, list[str]] = {}
    next_sink = start_sink_index
    seen: set[tuple[str, int, str]] = set()

    for func in functions:
        copied = copied_locals_from_input(func)
        if not copied:
            continue
        copied_names = set(copied)
        for offset, line in enumerate(func.lines):
            parsed = store_assignment_parts(line)
            if not parsed:
                continue
            lhs, op, rhs = parsed
            if not lhs_is_field_store(lhs):
                continue
            hits = expr_mentions_any_identifier(rhs, copied_names)
            if not hits:
                continue
            plain_line = func.start_line + offset
            expr = f"{lhs} {op} {rhs}"
            key = (func.name, plain_line, expr)
            if key in seen:
                continue
            seen.add(key)
            first_hit = hits[0]
            producer = copied[first_hit]
            roles = {
                "dst": lhs,
                "value": rhs,
            }
            sink_id = f"S{next_sink:04d}"
            next_sink += 1
            confirmed.append(
                confirmed_sink_row(
                    sink_id=sink_id,
                    detection_kind="field_update_store",
                    confirmation_source="deterministic_field_update_store",
                    label="STORE_SINK",
                    sink_kind="field_update_store_sink",
                    callee=func.name,
                    function=func.name,
                    plain_line=plain_line,
                    args=func.params,
                    roles=roles,
                    expr=expr,
                    vulnerable_roles=["dst", "value"],
                    extra={
                        "pattern": "field_update_store",
                        "decision": "ACCEPT_HEURISTIC",
                        "evidence_level": "HEURISTIC_STRUCTURAL",
                        "rule_id": "SINK_FIELD_UPDATE_STORE",
                        "site_id": f"textsite:{func.name}:{plain_line}:field-update",
                        "copied_local": first_hit,
                        "producer_copy": {
                            "line": producer.get("line"),
                            "expr": producer.get("expr"),
                            "callee": producer.get("callee"),
                            "roles": producer.get("roles"),
                        },
                    },
                )
            )
            annotations.setdefault(plain_line, []).append(
                f"CT-SINK {sink_id} pattern=field_update_store dst={lhs} value={rhs}".strip()
            )
    return confirmed, annotations, next_sink


def detect_unbounded_walk_candidates(
    functions: list[FunctionRecord],
    functions_by_name: dict[str, FunctionRecord],
    *,
    start_index: int,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    next_id = start_index
    for func in functions:
        lines = func.lines
        for offset, line in enumerate(lines):
            advance = re.search(
                r"\b(?P<ptr>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P=ptr)\s*\+\s*(?P<step>[A-Za-z_][A-Za-z0-9_]*)\s*\+\s*(?P<const>(?:0x[0-9a-fA-F]+|\d+))\s*;",
                line,
            )
            if not advance:
                continue
            ptr = advance.group("ptr")
            step = advance.group("step")
            loop = nearest_loop_line(func, offset, radius=6)
            if not loop:
                continue
            before = "\n".join(lines[max(0, offset - 8):offset])
            after = "\n".join(lines[offset + 1:min(len(lines), offset + 7)])
            step_from_ptr = re.search(rf"\b{re.escape(step)}\s*=\s*(?:\([^)]*\))?\s*\*\s*{re.escape(ptr)}\s*;", before + "\n" + after)
            deref_after = re.search(rf"\*\s*{re.escape(ptr)}\b", after)
            if not (step_from_ptr and deref_after):
                continue
            line_no = func.start_line + offset
            loop_line, loop_expr = loop
            known_facts = [
                f"loop context at line {loop_line}: {loop_expr}",
                f"data-derived pointer advance at line {line_no}: {clean_expr(line.strip())}",
                f"step variable {step} is loaded from *{ptr} near the loop",
                f"{ptr} is dereferenced again after being advanced",
                "no end pointer/capacity guard was proven by this detector",
            ]
            candidates.append(
                make_candidate(
                    candidate_number=next_id,
                    reason="pattern_unbounded_walk",
                    function=func.name,
                    plain_line=line_no,
                    callee=func.name,
                    callsite=clean_expr(line.strip()),
                    actual_args=func.params,
                    callee_definition=function_definition(functions_by_name, func.name),
                    known_facts=known_facts,
                    questions=[
                        "Does this parser loop walk a pointer by a data-derived length?",
                        "Is there an explicit end/capacity guard in the provided function body?",
                        "If sink semantics are present, identify pointer, step/len, and guard status.",
                    ],
                    compat_sink_label="LOOP_WRITE_SINK",
                    suggested_sink_label="LOOP_WRITE_SINK",
                    semantic_hint_label="UNBOUNDED_WALK_SINK",
                    pattern="unbounded_walk",
                )
            )
            next_id += 1
    return candidates


def detect_semantic_candidates(
    functions: list[FunctionRecord],
    functions_by_name: dict[str, FunctionRecord],
    *,
    known_confirmed_names: set[str],
    confirmed_call_keys: set[tuple[str, int, str, str]],
    start_index: int = 1,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, int, str, str]] = set()
    candidate_id = start_index
    for func in functions:
        for call in find_all_calls_in_function(func):
            key = call_key(call)
            if key in seen or key in confirmed_call_keys:
                continue
            seen.add(key)
            if call.callee in known_confirmed_names:
                continue
            if len(call.args) < 2 or not has_semantic_callee_trigger(call.callee):
                continue
            pointer_args = [arg for arg in call.args if is_pointer_like_arg(arg)]
            size_args = [arg for arg in call.args if is_size_like_arg(arg)]
            if not pointer_args or not size_args:
                continue
            known_facts = [
                f"callee name matches semantic trigger: {call.callee}",
                f"pointer-like args: {', '.join(pointer_args[:4])}",
                f"size-like args: {', '.join(size_args[:4])}",
            ]
            candidates.append(
                make_candidate(
                    candidate_number=candidate_id,
                    reason="semantic_candidate_trigger",
                    function=call.function,
                    plain_line=call.line,
                    callee=call.callee,
                    callsite=call.expr,
                    actual_args=call.args,
                    callee_definition=function_definition(functions_by_name, call.callee),
                    nested_definitions=nested_definitions_for_candidate(
                        functions_by_name,
                        call.callee,
                        known_names=known_confirmed_names,
                    ),
                    known_facts=known_facts,
                    questions=[
                        "Is this a memory/copy/write sink?",
                        "If yes, what are dst/src/len/value/fmt roles?",
                        "Which code lines support the decision?",
                    ],
                    suggested_sink_label="UNKNOWN_SINK",
                    pattern="semantic_api_name",
                )
            )
            candidate_id += 1
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--sinks-json", required=True, type=Path)
    parser.add_argument("--sink-unconfirmed-json", required=True, type=Path)
    parser.add_argument("--annotated-output", default=None, type=Path)
    parser.add_argument("--elf", default="", type=str)
    parser.add_argument("--registry", default=DEFAULT_REGISTRY_PATH, type=Path)
    parser.add_argument(
        "--program-facts",
        default=None,
        type=Path,
        help="Whole-image Ghidra High P-code facts required by the strict pipeline.",
    )
    parser.add_argument(
        "--sources-json",
        default=None,
        type=Path,
        help="Optional Source artifact used only to exclude proved MMIO ingress loops.",
    )
    parser.add_argument(
        "--channel-graph",
        default=None,
        type=Path,
        help=(
            "Optional existing Channelgraph artifact. Body-derived Sink "
            "heuristics consume only its Source associations."
        ),
    )
    parser.add_argument(
        "--hardware-metadata",
        default=None,
        type=Path,
        help="Optional register metadata used only for proved MMIO Source exclusion.",
    )
    parser.add_argument(
        "--audit-heuristics",
        action="store_true",
        help=(
            "Run experimental body-derived heuristics for an independent audit. "
            "Normal runs use only registry rules whose enabled flag is true."
        ),
    )
    parser.add_argument(
        "--heuristic-method",
        action="append",
        default=[],
        help=(
            "Audit the named registry rule in addition to rules already enabled "
            "by default. May be repeated; primarily used with --audit-heuristics."
        ),
    )
    parser.add_argument(
        "--allow-legacy-pseudoc-heuristics",
        action="store_true",
        help="Diagnostic compatibility mode only; never used by strict evaluation.",
    )
    parser.add_argument(
        "--disable-body-derived-sink-heuristics",
        action="store_true",
        help=(
            "Controlled ablation: retain primitive/intrinsic Sinks and "
            "recursive body-proved wrappers, but disable body-derived "
            "heuristic Sink patterns."
        ),
    )
    args = parser.parse_args()

    global PRIMITIVE_SINK_SPECS, FRAMEWORK_SINK_SPECS
    registry = load_sink_registry(args.registry)
    program_facts = read_json(args.program_facts)
    if program_facts and args.elf and Path(args.elf).exists():
        enrich_program_facts_with_elf_literals(program_facts, Path(args.elf))
    PRIMITIVE_SINK_SPECS = dict(registry["primitive_sinks"])
    FRAMEWORK_SINK_SPECS = dict(registry["framework_sinks"])

    lines = args.input.read_text(errors="replace").splitlines(keepends=True)
    functions = parse_functions(lines)
    functions_by_name = {f.name: f for f in functions}

    if program_facts and not args.allow_legacy_pseudoc_heuristics:
        from deterministic_sink_engine import analyze as analyze_deterministic_sinks
        from body_sink_heuristics import (
            analyze_program_facts as analyze_body_sinks,
            materialize_body_sink_calls,
        )
        from sink_artifact_schema import dedupe_rows

        display_calls = [
            {
                "callee": call.callee,
                "args": list(call.args),
                "function": call.function,
                "line": call.line,
                "expr": call.expr,
            }
            for function in functions
            for call in find_all_calls_in_function(function)
        ]
        artifact, unconfirmed_artifact = analyze_deterministic_sinks(
            program_facts=program_facts,
            registry=registry,
            display_calls=display_calls,
            input_metadata={
                "decompiled_c": str(args.input),
                "elf": args.elf,
                "program_facts": str(args.program_facts),
            },
        )
        raw_registry = json.loads(args.registry.read_text())
        raw_heuristic_rules = [
            dict(row)
            for row in list(raw_registry.get("heuristic_sink_rules", []) or [])
            if isinstance(row, dict)
        ]
        default_methods = {
            str(row.get("id", ""))
            for row in raw_heuristic_rules
            if row.get("enabled", False) is True
        }
        if args.audit_heuristics:
            enabled_methods = {
                str(row.get("id", ""))
                for row in raw_heuristic_rules
                if row.get("audit_enabled", row.get("enabled", False)) is True
            }
        else:
            enabled_methods = set(default_methods)
        enabled_methods.discard("")
        requested_methods = {
            str(value).strip()
            for value in list(args.heuristic_method or [])
            if str(value).strip()
        }
        if requested_methods:
            known_methods = {
                str(row.get("id", ""))
                for row in raw_heuristic_rules
                if str(row.get("id", ""))
            }
            unknown_methods = requested_methods - known_methods
            if unknown_methods:
                parser.error(
                    "unknown --heuristic-method value(s): "
                    + ", ".join(sorted(unknown_methods))
                )
            enabled_methods = default_methods | requested_methods
        if args.disable_body_derived_sink_heuristics:
            enabled_methods = set()
        source_evidence = read_json(args.sources_json) if args.sources_json else {}
        channel_graph = read_json(args.channel_graph) if args.channel_graph else {}
        register_evidence = (
            read_json(args.hardware_metadata) if args.hardware_metadata else {}
        )
        heuristic_artifact = (
            analyze_body_sinks(
                program_facts,
                source_evidence=source_evidence,
                register_evidence=register_evidence,
                source_associations=list(
                    channel_graph.get("source_associations", []) or []
                ),
                enabled_methods=enabled_methods,
                method_specs={
                    str(row.get("id", "")): row
                    for row in raw_heuristic_rules
                    if str(row.get("id", ""))
                },
            )
            if enabled_methods
            else {
                "heuristic_sink_calls": [],
                "candidates": [],
                "blockers": [],
                "stats": {"functions_analyzed": 0},
            }
        )
        heuristic_implementations = [
            dict(row)
            for row in list(
                heuristic_artifact.get(
                    "heuristic_sink_implementations",
                    heuristic_artifact.get("heuristic_sink_calls", []),
                )
                or []
            )
        ]
        (
            heuristic_implementations,
            heuristic_audit_candidates,
            audit_only_methods,
        ) = partition_audit_only_heuristics(
            heuristic_implementations,
            raw_heuristic_rules,
        )
        # A parser read is already anchored at the concrete LOAD/range-read
        # instruction.  Re-materializing it at every caller does not add a new
        # memory effect and multiplies BFS startpoints.  Wrapper boundaries are
        # still materialized for body-derived write/copy effects whose effect
        # is intentionally represented at the outer call boundary.
        direct_effect_heuristics = [
            row
            for row in heuristic_implementations
            if str(row.get("label", "")) == "PARSER_OOB_READ_SINK"
        ]
        boundary_heuristics = [
            row
            for row in heuristic_implementations
            if str(row.get("label", "")) != "PARSER_OOB_READ_SINK"
        ]
        materialized_heuristics = materialize_body_sink_calls(
            program_facts,
            boundary_heuristics,
            excluded_function_names=set(PRIMITIVE_SINK_SPECS),
        )
        heuristic_artifact["heuristic_sink_implementations"] = (
            heuristic_implementations
        )
        heuristic_artifact["heuristic_audit_candidates"] = (
            heuristic_audit_candidates
        )
        heuristic_artifact["heuristic_sink_calls"] = [
            *direct_effect_heuristics,
            *list(materialized_heuristics.get("heuristic_sink_calls", []) or []),
        ]
        heuristic_artifact["blockers"] = [
            *list(heuristic_artifact.get("blockers", []) or []),
            *list(materialized_heuristics.get("blockers", []) or []),
        ]
        heuristic_artifact["materialization"] = {
            key: int(materialized_heuristics.get(key, 0) or 0)
            for key in (
                "implementation_groups",
                "body_effect_fallbacks",
                "recursive_summaries",
                "canonical_wrapper_callsites",
            )
        }

        deterministic_rows = [
            dict(row)
            for row in list(artifact.get("deterministic_sink_calls", []) or [])
        ]
        heuristic_rows = dedupe_rows(
            [
                dict(row)
                for row in list(
                    heuristic_artifact.get("heuristic_sink_calls", []) or []
                )
            ],
            "function_id",
            "site_id",
            "recognition_method",
        )
        all_sinks = dedupe_rows(
            [*deterministic_rows, *heuristic_rows],
            "function_id",
            "site_id",
            "effect_site_id",
            "recognition_method",
        )
        artifact["scope"] = "sink_backward_dfa_inputs"
        artifact["decision_policy"] = (
            "deterministic_registry_and_wrapper_only_ablation"
            if args.disable_body_derived_sink_heuristics
            else "deterministic_registry_and_wrapper_plus_audited_body_heuristics"
        )
        artifact["heuristic_mode"] = (
            "independent_audit" if args.audit_heuristics else "enabled_rules_only"
        )
        artifact["enabled_heuristic_methods"] = sorted(enabled_methods)
        artifact["audit_only_heuristic_methods"] = sorted(audit_only_methods)
        artifact["heuristic_sink_implementations"] = heuristic_implementations
        artifact["heuristic_audit_candidates"] = heuristic_audit_candidates
        artifact["heuristic_sink_calls"] = heuristic_rows
        artifact["confirmed_sink_calls"] = all_sinks
        artifact["sinks"] = all_sinks
        artifact["sink_startpoints"] = all_sinks
        artifact["body_heuristic_candidates"] = list(
            heuristic_artifact.get("candidates", []) or []
        )
        artifact["body_heuristic_blockers"] = list(
            heuristic_artifact.get("blockers", []) or []
        )
        artifact["body_heuristic_materialization"] = dict(
            heuristic_artifact.get("materialization", {}) or {}
        )
        counts = dict(artifact.get("counts", {}) or {})
        counts["deterministic_sink_calls"] = len(deterministic_rows)
        counts["heuristic_sink_calls"] = len(heuristic_rows)
        counts["heuristic_sink_implementations"] = len(
            heuristic_implementations
        )
        counts["heuristic_audit_candidates"] = len(
            heuristic_audit_candidates
        )
        counts["heuristic_sink_startpoints"] = len(heuristic_rows)
        counts["sink_startpoints"] = len(all_sinks)
        counts["body_heuristic_candidates"] = len(
            artifact["body_heuristic_candidates"]
        )
        counts["body_heuristic_blockers"] = len(
            artifact["body_heuristic_blockers"]
        )
        for key, value in artifact["body_heuristic_materialization"].items():
            counts[f"body_heuristic_{key}"] = int(value or 0)
        counts["body_heuristic_functions_analyzed"] = int(
            dict(heuristic_artifact.get("stats", {}) or {}).get(
                "functions_analyzed", 0
            )
        )
        artifact["counts"] = counts
        artifact.setdefault("registry", {})["enabled_heuristic_methods"] = sorted(
            enabled_methods
        )
        artifact["registry"]["heuristic_audit_override"] = bool(
            args.audit_heuristics
        )
        artifact["disabled_capabilities"] = (
            ["body-derived-sink-heuristics"]
            if args.disable_body_derived_sink_heuristics
            else []
        )
        args.sinks_json.parent.mkdir(parents=True, exist_ok=True)
        args.sink_unconfirmed_json.parent.mkdir(parents=True, exist_ok=True)
        args.sinks_json.write_text(json.dumps(artifact, indent=2, sort_keys=False) + "\n")
        args.sink_unconfirmed_json.write_text(
            json.dumps(unconfirmed_artifact, indent=2, sort_keys=False) + "\n"
        )
        print(json.dumps(artifact["counts"], indent=2, sort_keys=True))
        return 0

    if not program_facts and not args.allow_legacy_pseudoc_heuristics:
        parser.error(
            "strict deterministic Sink mining requires --program-facts; "
            "use --allow-legacy-pseudoc-heuristics only for diagnostics"
        )

    primitive_calls: list[Callsite] = []
    primitive_names = set(PRIMITIVE_SINK_SPECS)
    for func in functions:
        primitive_calls.extend(find_calls_in_function(func, primitive_names))

    wrappers = discover_wrappers(functions, primitive_calls)
    wrapper_by_name = {w.function: w for w in wrappers}

    known_framework_names = set(FRAMEWORK_SINK_SPECS)
    wrapper_names = set(wrapper_by_name) | known_framework_names
    wrapper_calls: list[Callsite] = []
    for func in functions:
        wrapper_calls.extend(find_calls_in_function(func, wrapper_names))

    dispatches = detect_dispatches(functions)

    annotations: dict[int, list[str]] = {}
    confirmed_sink_calls: list[dict[str, Any]] = []
    filtered_literal_format_calls: list[dict[str, Any]] = []
    next_sink = 1

    for call in sorted(primitive_calls, key=lambda c: (c.line, c.callee, c.expr)):
        spec = PRIMITIVE_SINK_SPECS[call.callee]
        effective_label = str(spec["label"])
        vulnerable_roles: list[str] | None = None
        extra: dict[str, Any] | None = None
        if is_literal_format_call(call, spec):
            roles, vulnerable_roles = literal_format_output_roles(call, spec)
            if vulnerable_roles:
                effective_label = "COPY_SINK"
                extra = {
                    "semantic_subtype": "literal_format_buffer_write",
                    "format_literal": str(roles.get("fmt", "")),
                }
            else:
                filtered_literal_format_calls.append(
                    {
                        "callee": call.callee,
                        "function": call.function,
                        "plain_line": call.line,
                        "expr": call.expr,
                        "reason": "literal_format_without_dynamic_output_argument",
                    }
                )
                continue
        else:
            roles = roles_for_call(call, spec)
        sink_id = f"S{next_sink:04d}"
        next_sink += 1
        confirmed_sink_calls.append(
            confirmed_sink_row(
                sink_id=sink_id,
                detection_kind="primitive_callsite",
                confirmation_source=confirmation_source_for_primitive(call.callee, spec),
                label=effective_label,
                sink_kind=str(spec["kind"]),
                callee=call.callee,
                function=call.function,
                plain_line=call.line,
                args=call.args,
                roles=roles,
                expr=call.expr,
                spec=spec,
                vulnerable_roles=vulnerable_roles,
                extra=extra,
            )
        )
        annotations.setdefault(call.line, []).append(
            f"CT-SINK {sink_id} primitive={call.callee} {comment_for_roles(roles)}".strip()
        )

    for wrapper in wrappers:
        inner_line = int(wrapper.inner_sink["line"])
        annotations.setdefault(inner_line, []).append(
            f"CT-WRAPPER {wrapper.id} {wrapper.function} inner={wrapper.inner_sink['callee']} {comment_for_roles(wrapper.roles)}".strip()
        )

    for call in sorted(wrapper_calls, key=lambda c: (c.line, c.callee, c.expr)):
        if call.function == call.callee:
            continue
        wrapper = wrapper_by_name.get(call.callee)
        spec = FRAMEWORK_SINK_SPECS.get(call.callee)
        if wrapper:
            roles: dict[str, str] = {}
            for role, mapped in wrapper.roles.items():
                instantiated = mapped
                for idx, arg in enumerate(call.args):
                    instantiated = re.sub(
                        rf"\barg{idx}\b", lambda _match, replacement=arg: replacement, instantiated
                    )
                roles[role] = instantiated
            wrapper_id = wrapper.id
            kind = "wrapper_callsite"
            label = str(wrapper.inner_sink.get("label", "COPY_SINK"))
            sink_kind = str(wrapper.inner_sink.get("kind", "body_derived_wrapper_sink"))
            confirmation_source = "body_derived_wrapper"
        elif spec:
            roles = roles_for_call(call, spec)
            wrapper_id = ""
            kind = "framework_callsite"
            label = spec["label"]
            sink_kind = spec["kind"]
            confirmation_source = "curated_framework_summary"
        else:
            continue
        sink_id = f"S{next_sink:04d}"
        next_sink += 1
        extra = {"wrapper": wrapper_id} if wrapper_id else {
            "decision": "ACCEPT_HEURISTIC",
            "evidence_level": "HEURISTIC_CURATED_FRAMEWORK_SUMMARY",
            "rule_id": "SINK_CURATED_FRAMEWORK_SUMMARY",
        }
        confirmed_sink_calls.append(
            confirmed_sink_row(
                sink_id=sink_id,
                detection_kind=kind,
                confirmation_source=confirmation_source,
                label=str(label),
                sink_kind=str(sink_kind),
                callee=call.callee,
                function=call.function,
                plain_line=call.line,
                args=call.args,
                roles=roles,
                expr=call.expr,
                spec=spec if spec else None,
                extra=extra,
            )
        )
        wrapper_part = f" wrapper={wrapper_id}" if wrapper_id else ""
        annotations.setdefault(call.line, []).append(
            f"CT-SINK {sink_id}{wrapper_part} callee={call.callee} {comment_for_roles(roles)}".strip()
        )

    field_update_sinks, field_update_annotations, next_sink = detect_field_update_store_sinks(
        functions,
        start_sink_index=next_sink,
    )
    confirmed_sink_calls.extend(field_update_sinks)
    confirmed_before_withdraw = len(confirmed_sink_calls)
    confirmed_sink_calls, withdrawn_sink_rows, withdrawn_reason_counts = filter_confirmed_sink_startpoints(
        confirmed_sink_calls
    )
    confirmed_withdrawn_count = confirmed_before_withdraw - len(confirmed_sink_calls)
    rows_before_dedupe = len(confirmed_sink_calls)
    confirmed_sink_calls = dedupe_sink_rows(confirmed_sink_calls)
    confirmed_deduped_count = rows_before_dedupe - len(confirmed_sink_calls)
    for line_no, comments in field_update_annotations.items():
        annotations.setdefault(line_no, []).extend(comments)

    for idx, dispatch in enumerate(sorted(dispatches, key=lambda d: (d["plain_line"], d["function"])), start=1):
        dispatch["id"] = f"D{idx:04d}"
        annotations.setdefault(int(dispatch["plain_line"]), []).append(
            f"CT-DISPATCH {dispatch['id']} unresolved {dispatch['pattern']}"
        )

    if args.annotated_output:
        annotated_lines = annotate_lines(lines, annotations)
        args.annotated_output.parent.mkdir(parents=True, exist_ok=True)
        args.annotated_output.write_text("".join(annotated_lines))

    args.sinks_json.parent.mkdir(parents=True, exist_ok=True)
    args.sink_unconfirmed_json.parent.mkdir(parents=True, exist_ok=True)

    confirmed_keys = {
        (str(row["function"]), int(row["plain_line"]), str(row["callee"]), str(row["expr"]))
        for row in confirmed_sink_calls
    }
    semantic_candidates = detect_semantic_candidates(
        functions,
        functions_by_name,
        known_confirmed_names=primitive_names | wrapper_names,
        confirmed_call_keys=confirmed_keys,
        start_index=1,
    )
    next_candidate = len(semantic_candidates) + 1
    loop_candidates = detect_loop_write_candidates(
        functions,
        functions_by_name,
        start_index=next_candidate,
    )
    semantic_candidates.extend(loop_candidates)
    next_candidate = len(semantic_candidates) + 1
    parser_store_candidates = detect_parser_store_candidates(
        functions,
        functions_by_name,
        start_index=next_candidate,
    )
    semantic_candidates.extend(parser_store_candidates)
    next_candidate = len(semantic_candidates) + 1
    unbounded_walk_candidates = detect_unbounded_walk_candidates(
        functions,
        functions_by_name,
        start_index=next_candidate,
    )
    semantic_candidates.extend(unbounded_walk_candidates)
    candidates_before_dedupe = len(semantic_candidates)
    semantic_candidates = dedupe_candidates(semantic_candidates)
    candidates_deduped_count = candidates_before_dedupe - len(semantic_candidates)

    next_sink_number = next_sink
    heuristic_sink_calls: list[dict[str, Any]] = []
    dropped_candidates: list[dict[str, Any]] = list(withdrawn_sink_rows)
    for candidate in semantic_candidates:
        row = heuristic_sink_row(candidate, f"S{next_sink_number:04d}")
        if row is None:
            dropped = dict(candidate)
            dropped["decision"] = "DROP_LOCAL_HEURISTIC"
            dropped["drop_reason"] = (
                "peripheral_producer_not_sink"
                if str(candidate.get("semantic_hint_label", "")) == "peripheral_buffer_fill"
                else "insufficient_generalized_structural_sink_evidence"
            )
            dropped_candidates.append(dropped)
            continue
        heuristic_sink_calls.append(row)
        next_sink_number += 1

    bind_sink_rows_to_program_facts(confirmed_sink_calls, program_facts)
    bind_sink_rows_to_program_facts(heuristic_sink_calls, program_facts)
    callsite_kinds = {"primitive_callsite", "wrapper_callsite", "framework_callsite"}
    for row in confirmed_sink_calls:
        if (
            str(row.get("detection_kind", "")) in callsite_kinds
            and str(row.get("binding_status", "")) != "verified_high_pcode_callsite"
        ):
            row["decision"] = "ACCEPT_HEURISTIC"
            row["evidence_level"] = "HEURISTIC_PSEUDOC_CALLSITE_UNBOUND"
            row["rule_id"] = "SINK_PSEUDOC_CALLSITE_UNBOUND"
    deterministic_sink_calls = [
        row for row in confirmed_sink_calls if row.get("decision") == "ACCEPT_DETERMINISTIC"
    ]
    heuristic_sink_calls = dedupe_sink_rows(
        [row for row in confirmed_sink_calls if row.get("decision") == "ACCEPT_HEURISTIC"]
        + heuristic_sink_calls
    )
    confirmed_sink_calls = deterministic_sink_calls
    sink_startpoints = dedupe_sink_rows(confirmed_sink_calls + heuristic_sink_calls)

    artifact = {
        "schema_version": "ct-mini-sinks-v3",
        "scope": "sink_backward_dfa_startpoints",
        "input": {
            "decompiled_c": str(args.input),
            "elf": args.elf,
            "program_facts": str(args.program_facts) if args.program_facts else "",
        },
        "registry": {
            "schema_version": registry["schema_version"],
            "name": registry["name"],
            "path": registry["path"],
            "primitive_sink_names": sorted(PRIMITIVE_SINK_SPECS),
            "framework_sink_names": sorted(FRAMEWORK_SINK_SPECS),
            "sink_labels": [
                str(entry.get("label", ""))
                for entry in registry.get("sink_labels", [])
                if str(entry.get("label", ""))
            ],
            "pattern_sink_names": [
                str(entry.get("name", ""))
                for entry in registry.get("pattern_sinks", [])
                if str(entry.get("name", ""))
            ],
            "dispatch_pattern_names": [
                str(entry.get("name", ""))
                for entry in registry.get("dispatch_patterns", [])
                if str(entry.get("name", ""))
            ],
        },
        "decision_policy": "deterministic_and_generalized_local_heuristics_no_front_llm",
        "next_stage_ready": True,
        "counts": {
            "functions": len(functions),
            "primitive_calls": len(primitive_calls),
            "filtered_literal_format_calls": len(filtered_literal_format_calls),
            "wrappers": len(wrappers),
            "wrapper_or_framework_calls": len([
                s for s in sink_startpoints
                if s["detection_kind"] in {"wrapper_callsite", "framework_callsite"}
            ]),
            "confirmed_sink_calls": len(confirmed_sink_calls),
            "deterministic_sink_startpoints": len(confirmed_sink_calls),
            "heuristic_sink_startpoints": len(heuristic_sink_calls),
            "sink_startpoints": len(sink_startpoints),
            "locally_dropped_candidates": len(dropped_candidates),
            "confirmed_sink_calls_withdrawn": confirmed_withdrawn_count,
            "confirmed_sink_calls_withdrawn_by_reason": withdrawn_reason_counts,
            "confirmed_sink_calls_deduped": confirmed_deduped_count,
            "unconfirmed_candidates": len(semantic_candidates),
            "unconfirmed_candidates_deduped": candidates_deduped_count,
            "unconfirmed_semantic_api_candidates": len([
                c for c in semantic_candidates
                if c.get("reason") == "semantic_candidate_trigger"
            ]),
            "unconfirmed_loop_write_candidates": len(loop_candidates),
            "unconfirmed_parser_store_candidates": len(parser_store_candidates),
            "unconfirmed_unbounded_walk_candidates": len(unbounded_walk_candidates),
            "field_update_store_sinks": len(field_update_sinks),
            "dispatches": len(dispatches),
        },
        "confirmed_sink_calls": confirmed_sink_calls,
        "heuristic_sink_calls": heuristic_sink_calls,
        "sink_startpoints": sink_startpoints,
        "dropped_candidates": dropped_candidates,
    }
    unconfirmed_artifact = {
        "schema_version": "ct-mini-sink-unconfirmed-v2",
        "scope": "deprecated_compatibility_artifact_no_front_llm",
        "input": {
            "decompiled_c": str(args.input),
            "elf": args.elf,
        },
        "registry": {
            "schema_version": registry["schema_version"],
            "name": registry["name"],
            "path": registry["path"],
        },
        "counts": {
            "functions": len(functions),
            "candidates": 0,
        },
        "candidates": [],
        "note": "All generalized structural decisions are recorded in sinks.json.",
    }
    args.sinks_json.write_text(json.dumps(artifact, indent=2, sort_keys=False) + "\n")
    args.sink_unconfirmed_json.write_text(json.dumps(unconfirmed_artifact, indent=2, sort_keys=False) + "\n")
    print(json.dumps(artifact["counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
