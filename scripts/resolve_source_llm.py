#!/usr/bin/env python3
"""Fail-closed merge of source adjudication decisions into source artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SOURCE_LABELS = {
    "MMIO_READ",
    "ISR_MMIO_READ",
    "ISR_FILLED_BUFFER",
    "DMA_BACKED_BUFFER",
    "BYTE_STREAM_INGRESS",
    "CONTROL_STATE",
    "SENSOR_INPUT",
    "UNKNOWN_SOURCE",
}
CONFIRMED_SOURCE_LABELS = SOURCE_LABELS - {"UNKNOWN_SOURCE"}
ADJUDICATION_SCHEMA_VERSION = "ct-mini-source-adjudication-v2"
FINAL_DECISION_VALUES = {"confirmed", "rejected", "analysis_unresolved"}
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
RESOLUTION_ANNOTATION_FIELDS = frozenset(
    {
        "analysis_status",
        "decision",
        "drop_kind",
        "failure_kind",
        "output",
    }
)
FINAL_DECISION_FIELDS = {
    "candidate_id",
    "candidate_hash",
    "packet_hash",
    "decision",
    "source_label",
    "source_kind",
    "source_output",
    "evidence_refs",
    "notes",
    "failure_kind",
}
PROVENANCE_FIELDS = {"model", "prompt", "input", "parameters", "attempts"}


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stable_json_hash(value: Any) -> str:
    return sha256_text(canonical_json(value))


def candidate_hash_payload(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in candidate.items()
        if key not in RESOLUTION_ANNOTATION_FIELDS
    }


def candidate_hash(candidate: dict[str, Any]) -> str:
    return stable_json_hash(candidate_hash_payload(candidate))


def clean_expr(expr: Any) -> str:
    return re.sub(r"\s+", " ", str(expr or "").strip())


def candidate_output_bindings(candidate: dict[str, Any]) -> list[dict[str, str]]:
    bindings: list[dict[str, str]] = []
    seen: set[str] = set()
    for field in (
        "candidate_source_buffer",
        "candidate_source_value",
        "candidate_source_expression",
    ):
        expression = clean_expr(candidate.get(field))
        if expression and expression not in seen:
            kind = "memory_object" if field == "candidate_source_buffer" else "scalar_value"
            bindings.append({
                "binding_id": field,
                "expression": expression,
                "kind": kind,
                "object_id": str(candidate.get("candidate_source_object_id", "")) if kind == "memory_object" else "",
                "value_id": str(candidate.get("candidate_source_value_id", "")) if kind == "scalar_value" else "",
                "binding_status": str((candidate.get("static_bindings", {}) or {}).get("site_binding_status", "")),
            })
            seen.add(expression)

    raw_nodes = candidate.get("candidate_source_nodes", [])
    if isinstance(raw_nodes, list):
        for index, raw_node in enumerate(raw_nodes):
            if isinstance(raw_node, dict):
                expression = clean_expr(
                    raw_node.get("expression") or raw_node.get("node")
                )
                binding_id = str(raw_node.get("id") or f"candidate_source_nodes[{index}]")
            else:
                expression = clean_expr(raw_node)
                binding_id = f"candidate_source_nodes[{index}]"
            if expression and expression not in seen:
                bindings.append({
                    "binding_id": binding_id,
                    "expression": expression,
                    "kind": str(raw_node.get("kind", "memory_object")) if isinstance(raw_node, dict) else "memory_object",
                    "object_id": str(raw_node.get("object_id", "")) if isinstance(raw_node, dict) else "",
                    "value_id": str(raw_node.get("value_id", "")) if isinstance(raw_node, dict) else "",
                    "binding_status": str(raw_node.get("binding_status", "")) if isinstance(raw_node, dict) else "",
                })
                seen.add(expression)
    return bindings


def candidate_packet_payload(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": candidate.get("id", ""),
        "candidate_kind": candidate.get("candidate_kind", ""),
        "function": candidate.get("function", ""),
        "plain_line": candidate.get("plain_line", 0),
        "callee": candidate.get("callee", ""),
        "source_site": candidate.get("source_site", ""),
        "site_id": candidate.get("site_id", ""),
        "actual_args": candidate.get("actual_args", []),
        "label_hint": candidate.get("label_hint", ""),
        "allowed_source_labels": candidate.get("allowed_source_labels", []),
        "source_kind_hint": candidate.get("source_kind_hint", ""),
        "known_facts": candidate.get("known_facts", []),
        "unresolved": candidate.get("unresolved", []),
        "source_output_bindings": candidate_output_bindings(candidate),
        "static_bindings": candidate.get("static_bindings", {}),
        "function_id": candidate.get("function_id", ""),
        "callee_function_id": candidate.get("callee_function_id", ""),
        "callee_definition": str(candidate.get("callee_definition", "")),
        "callee_peripheral_evidence": candidate.get("callee_peripheral_evidence", []),
        "caller_context": candidate.get("caller_context", []),
        "unresolved_indirect_calls": candidate.get("unresolved_indirect_calls", []),
        "binding_required": bool(candidate.get("binding_required", False)),
        "function_slice": str(candidate.get("function_slice", "")),
        "semantic_slice": candidate.get("semantic_slice", {}),
    }


def static_node_binding_error(
    candidate: dict[str, Any], binding: dict[str, str]
) -> str:
    site = str(candidate.get("site_id", ""))
    if not site.startswith("site:"):
        return "confirmed decision lacks miner-provided SiteId binding"
    kind = str(binding.get("kind", "memory_object"))
    object_id = str(binding.get("object_id", ""))
    value_id = str(binding.get("value_id", ""))
    if kind == "memory_object" and (not object_id or object_id.startswith("textobj:")):
        return "confirmed memory Source lacks miner-provided ObjectId binding"
    if kind == "scalar_value" and not value_id:
        return "confirmed scalar Source lacks miner-provided ValueId binding"
    if kind not in {"memory_object", "scalar_value", "event"}:
        return "confirmed Source has an unsupported output kind"
    function_id = str(candidate.get("function_id", ""))
    if function_id.startswith("fn:"):
        expected_entry = function_id.removeprefix("fn:").lower().lstrip("0") or "0"
        site_parts = site.split(":")
        observed_entry = site_parts[1].lower().lstrip("0") if len(site_parts) > 1 else ""
        if observed_entry != expected_entry:
            return "SiteId does not belong to the candidate FunctionId"
    static_bindings = dict(candidate.get("static_bindings", {}) or {})
    site_status = str(static_bindings.get("site_binding_status", ""))
    if site_status not in {
        "verified_direct_call_site",
        "verified_high_pcode_def_use_site",
        "verified_event_site",
    }:
        return "SiteId is not verified against an exported High P-code operation"
    bound_site = str(
        static_bindings.get("call_site_id")
        or static_bindings.get("mmio_load_site_id")
        or ""
    )
    if not bound_site:
        return "verified site status has no bound High P-code operation"
    if bound_site != site:
        return "SiteId does not match the statically bound High P-code operation"
    bound_object = str(
        static_bindings.get("source_actual_object_id")
        or static_bindings.get("destination_object_id")
        or ""
    )
    if bound_object and bound_object != object_id:
        return "selected ObjectId does not match the statically bound actual argument"
    bound_value = str(
        static_bindings.get("source_actual_value_id")
        or static_bindings.get("source_value_id")
        or ""
    )
    if kind == "scalar_value" and bound_value and bound_value != value_id:
        return "selected ValueId does not match the statically bound value"
    return ""


def packet_hash(candidate: dict[str, Any]) -> str:
    return stable_json_hash(candidate_packet_payload(candidate))


def _require_exact_keys(data: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(data)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{context} keys differ: missing={missing}, extra={extra}")


def _require_sha256(value: Any, context: str) -> None:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        raise ValueError(f"{context} must be a lowercase SHA-256 hash")


def validate_provenance_shape(provenance: Any) -> dict[str, Any]:
    if not isinstance(provenance, dict):
        raise ValueError("provenance must be an object")
    _require_exact_keys(provenance, PROVENANCE_FIELDS, "provenance")

    model = provenance["model"]
    if not isinstance(model, dict):
        raise ValueError("provenance.model must be an object")
    _require_exact_keys(model, {"requested", "resolved"}, "provenance.model")
    if not isinstance(model["requested"], str):
        raise ValueError("provenance.model.requested must be a string")
    if not isinstance(model["resolved"], list) or any(
        not isinstance(value, str) for value in model["resolved"]
    ):
        raise ValueError("provenance.model.resolved must be a string list")

    prompt = provenance["prompt"]
    if not isinstance(prompt, dict):
        raise ValueError("provenance.prompt must be an object")
    _require_exact_keys(
        prompt,
        {"system_sha256", "contract_sha256", "attempt_sha256"},
        "provenance.prompt",
    )
    _require_sha256(prompt["system_sha256"], "provenance.prompt.system_sha256")
    _require_sha256(prompt["contract_sha256"], "provenance.prompt.contract_sha256")
    if not isinstance(prompt["attempt_sha256"], list):
        raise ValueError("provenance.prompt.attempt_sha256 must be a list")
    for index, value in enumerate(prompt["attempt_sha256"]):
        _require_sha256(value, f"provenance.prompt.attempt_sha256[{index}]")

    input_provenance = provenance["input"]
    if not isinstance(input_provenance, dict):
        raise ValueError("provenance.input must be an object")
    _require_exact_keys(
        input_provenance,
        {
            "source_unconfirmed_json",
            "source_unconfirmed_sha256",
            "selected_candidate_ids",
            "selected_candidates_sha256",
            "candidate_hashes",
            "packet_hashes",
        },
        "provenance.input",
    )
    if not isinstance(input_provenance["source_unconfirmed_json"], str):
        raise ValueError("provenance.input.source_unconfirmed_json must be a string")
    _require_sha256(
        input_provenance["source_unconfirmed_sha256"],
        "provenance.input.source_unconfirmed_sha256",
    )
    _require_sha256(
        input_provenance["selected_candidates_sha256"],
        "provenance.input.selected_candidates_sha256",
    )
    selected_ids = input_provenance["selected_candidate_ids"]
    if not isinstance(selected_ids, list) or any(not isinstance(cid, str) for cid in selected_ids):
        raise ValueError("provenance.input.selected_candidate_ids must be a string list")
    if len(selected_ids) != len(set(selected_ids)):
        raise ValueError("provenance.input.selected_candidate_ids contains duplicates")
    for map_name in ("candidate_hashes", "packet_hashes"):
        hash_map = input_provenance[map_name]
        if not isinstance(hash_map, dict) or any(
            not isinstance(cid, str) for cid in hash_map
        ):
            raise ValueError(f"provenance.input.{map_name} must be an object")
        if set(hash_map) != set(selected_ids):
            raise ValueError(f"provenance.input.{map_name} keys do not match selected ids")
        for cid, value in hash_map.items():
            _require_sha256(value, f"provenance.input.{map_name}.{cid}")

    parameters = provenance["parameters"]
    if not isinstance(parameters, dict):
        raise ValueError("provenance.parameters must be an object")
    _require_exact_keys(
        parameters,
        {"max_code_chars", "request_timeout_sec", "batch_size"},
        "provenance.parameters",
    )
    if (
        not isinstance(parameters["max_code_chars"], int)
        or isinstance(parameters["max_code_chars"], bool)
        or parameters["max_code_chars"] < 0
    ):
        raise ValueError("provenance.parameters.max_code_chars must be non-negative")
    if not isinstance(parameters["request_timeout_sec"], (int, float)) or isinstance(
        parameters["request_timeout_sec"], bool
    ):
        raise ValueError("provenance.parameters.request_timeout_sec must be numeric")
    if (
        not isinstance(parameters["batch_size"], int)
        or isinstance(parameters["batch_size"], bool)
        or parameters["batch_size"] < 1
    ):
        raise ValueError("provenance.parameters.batch_size must be positive")
    if not isinstance(provenance["attempts"], list):
        raise ValueError("provenance.attempts must be a list")
    return provenance


def validate_final_decision_shape(decision: Any, index: int) -> dict[str, Any]:
    if not isinstance(decision, dict):
        raise ValueError(f"decision {index} must be an object")
    _require_exact_keys(decision, FINAL_DECISION_FIELDS, f"decision {index}")
    for field in (
        "candidate_id",
        "candidate_hash",
        "packet_hash",
        "decision",
        "source_label",
        "source_kind",
        "notes",
    ):
        if not isinstance(decision[field], str):
            raise ValueError(f"decision {index} field {field} must be a string")
    _require_sha256(decision["candidate_hash"], f"decision {index}.candidate_hash")
    _require_sha256(decision["packet_hash"], f"decision {index}.packet_hash")
    if decision["decision"] not in FINAL_DECISION_VALUES:
        raise ValueError(f"decision {index} has invalid decision value")
    if decision["source_label"] not in SOURCE_LABELS:
        raise ValueError(f"decision {index} has invalid source_label")
    refs = decision["evidence_refs"]
    if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
        raise ValueError(f"decision {index}.evidence_refs must be a string list")
    source_output = decision["source_output"]
    if source_output is not None:
        if not isinstance(source_output, dict):
            raise ValueError(f"decision {index}.source_output must be an object or null")
        _require_exact_keys(
            source_output, {"binding_id", "expression"}, f"decision {index}.source_output"
        )
        if not isinstance(source_output["binding_id"], str) or not isinstance(
            source_output["expression"], str
        ):
            raise ValueError(f"decision {index}.source_output fields must be strings")
    failure_kind = decision["failure_kind"]
    if failure_kind is not None and not isinstance(failure_kind, str):
        raise ValueError(f"decision {index}.failure_kind must be a string or null")
    if decision["decision"] in {"confirmed", "rejected"} and failure_kind is not None:
        raise ValueError(f"decision {index} semantic outcome cannot have failure_kind")
    if decision["decision"] != "confirmed" and source_output is not None:
        raise ValueError(f"decision {index} non-confirmed outcome cannot have source_output")
    if decision["decision"] == "analysis_unresolved" and not failure_kind:
        raise ValueError(f"decision {index} analysis_unresolved requires failure_kind")
    return decision


def load_response(
    path: Path,
) -> tuple[dict[str, dict[str, Any]], dict[str, Any], dict[str, str] | None]:
    try:
        raw_text = path.read_text(errors="replace")
    except OSError as exc:
        return {}, {}, {"kind": "missing_response", "message": str(exc)}
    try:
        data = json.loads(raw_text)
        if not isinstance(data, dict):
            raise ValueError("adjudication response must be an object")
        _require_exact_keys(
            data, {"schema_version", "provenance", "decisions"}, "response"
        )
        if data["schema_version"] != ADJUDICATION_SCHEMA_VERSION:
            raise ValueError("unexpected adjudication response schema_version")
        provenance = validate_provenance_shape(data["provenance"])
        if not isinstance(data["decisions"], list):
            raise ValueError("response decisions must be a list")
        decisions: dict[str, dict[str, Any]] = {}
        for index, raw_decision in enumerate(data["decisions"]):
            decision = validate_final_decision_shape(raw_decision, index)
            cid = decision["candidate_id"]
            if cid in decisions:
                raise ValueError(f"duplicate decision for candidate {cid}")
            decisions[cid] = decision
        return decisions, provenance, None
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        return {}, {}, {"kind": "response_parse_or_schema_error", "message": str(exc)}


def parse_response(path: Path) -> dict[str, dict[str, Any]]:
    """Compatibility wrapper returning only strict, valid decisions."""
    decisions, _, _ = load_response(path)
    return decisions


def validate_provenance_bindings(
    provenance: dict[str, Any],
    candidates: list[dict[str, Any]],
    *,
    source_unconfirmed_path: Path,
    source_unconfirmed_text: str,
) -> dict[str, str] | None:
    input_provenance = provenance["input"]
    recorded_path = Path(input_provenance["source_unconfirmed_json"])
    if recorded_path.resolve() != source_unconfirmed_path.resolve():
        return {
            "kind": "input_provenance_mismatch",
            "message": "source_unconfirmed path does not match response provenance",
        }
    if sha256_text(source_unconfirmed_text) != input_provenance["source_unconfirmed_sha256"]:
        return {
            "kind": "input_provenance_mismatch",
            "message": "source_unconfirmed file hash does not match response provenance",
        }
    selected_ids = input_provenance["selected_candidate_ids"]
    candidates_by_id = {str(candidate.get("id", "")): candidate for candidate in candidates}
    if set(selected_ids) != set(candidates_by_id):
        return {
            "kind": "partial_response_not_allowed",
            "message": "adjudication response does not cover the complete current candidate pool",
        }
    try:
        selected_candidates = [candidates_by_id[cid] for cid in selected_ids]
    except KeyError as exc:
        return {
            "kind": "input_provenance_mismatch",
            "message": f"response provenance references unknown candidate {exc.args[0]}",
        }
    if stable_json_hash(
        [candidate_hash_payload(candidate) for candidate in selected_candidates]
    ) != input_provenance["selected_candidates_sha256"]:
        return {
            "kind": "input_provenance_mismatch",
            "message": "selected candidate input hash does not match current candidates",
        }
    for candidate in selected_candidates:
        cid = str(candidate.get("id", ""))
        if input_provenance["candidate_hashes"].get(cid) != candidate_hash(candidate):
            return {
                "kind": "input_provenance_mismatch",
                "message": f"candidate provenance hash mismatch for {cid}",
            }
        if input_provenance["packet_hashes"].get(cid) != packet_hash(candidate):
            return {
                "kind": "input_provenance_mismatch",
                "message": f"packet provenance hash mismatch for {cid}",
            }
    return None


def validate_decision_binding(
    decision: dict[str, Any],
    candidate: dict[str, Any],
    provenance: dict[str, Any],
) -> dict[str, str] | None:
    cid = str(candidate.get("id", ""))
    if decision["candidate_id"] != cid:
        return {"kind": "candidate_id_mismatch", "message": "candidate id mismatch"}
    expected_candidate_hash = candidate_hash(candidate)
    expected_packet_hash = packet_hash(candidate)
    if decision["candidate_hash"] != expected_candidate_hash:
        return {"kind": "candidate_hash_mismatch", "message": "candidate hash mismatch"}
    if decision["packet_hash"] != expected_packet_hash:
        return {"kind": "packet_hash_mismatch", "message": "packet hash mismatch"}
    input_provenance = provenance["input"]
    if input_provenance["candidate_hashes"].get(cid) != expected_candidate_hash:
        return {
            "kind": "candidate_hash_mismatch",
            "message": "candidate hash is not bound in input provenance",
        }
    if input_provenance["packet_hashes"].get(cid) != expected_packet_hash:
        return {
            "kind": "packet_hash_mismatch",
            "message": "packet hash is not bound in input provenance",
        }

    if decision["decision"] == "confirmed":
        if decision["source_label"] not in CONFIRMED_SOURCE_LABELS:
            return {
                "kind": "invalid_confirmed_label",
                "message": "confirmed source label is not concrete",
            }
        allowed_labels = {
            str(label) for label in list(candidate.get("allowed_source_labels", []) or [])
            if str(label)
        }
        if not allowed_labels or decision["source_label"] not in allowed_labels:
            return {
                "kind": "invalid_confirmed_label",
                "message": "confirmed source label is outside candidate allowed labels",
            }
        output = decision["source_output"]
        if output is None:
            return {
                "kind": "invalid_source_output",
                "message": "confirmed decision has no source output",
            }
        bindings = {
            binding["binding_id"]: binding
            for binding in candidate_output_bindings(candidate)
        }
        binding_id = output["binding_id"]
        if binding_id not in bindings or not bindings[binding_id]["expression"]:
            return {
                "kind": "invalid_source_output",
                "message": "source output binding was not offered by the candidate",
            }
        if output["expression"] != bindings[binding_id]["expression"]:
            return {
                "kind": "invalid_source_output",
                "message": "source output expression does not match the candidate binding",
            }
        node_error = static_node_binding_error(candidate, bindings[binding_id])
        if node_error:
            return {
                "kind": "missing_static_node_binding",
                "message": node_error,
            }
    return None


def next_source_id(confirmed: list[dict[str, Any]]) -> int:
    highest = 0
    for row in confirmed:
        match = re.match(r"^SO(\d+)$", str(row.get("id", "")))
        if match:
            highest = max(highest, int(match.group(1)))
    return highest + 1


def decision_provenance(
    decision: dict[str, Any], provenance: dict[str, Any]
) -> dict[str, Any]:
    return {
        "model": provenance["model"],
        "system_prompt_sha256": provenance["prompt"]["system_sha256"],
        "prompt_contract_sha256": provenance["prompt"]["contract_sha256"],
        "candidate_hash": decision["candidate_hash"],
        "packet_hash": decision["packet_hash"],
    }


def confirmed_row_from_candidate(
    *,
    source_id: str,
    candidate: dict[str, Any],
    decision: dict[str, Any],
    response_path: Path,
    provenance: dict[str, Any],
) -> dict[str, Any]:
    validation_error = validate_decision_binding(decision, candidate, provenance)
    if validation_error or decision["decision"] != "confirmed":
        message = validation_error["message"] if validation_error else "not confirmed"
        raise ValueError(f"cannot build confirmed source: {message}")
    source_output = decision["source_output"]
    assert source_output is not None
    source_expression = source_output["expression"]
    selected_binding = next(
        binding for binding in candidate_output_bindings(candidate)
        if binding["binding_id"] == source_output["binding_id"]
    )
    output_kind = str(selected_binding.get("kind", "memory_object"))
    object_id = str(selected_binding.get("object_id", ""))
    value_id = str(selected_binding.get("value_id", ""))
    binding_status = str(
        selected_binding.get("binding_status")
        or (candidate.get("static_bindings", {}) or {}).get("site_binding_status", "")
    )
    return {
        "id": source_id,
        "detection_kind": "semantic_candidate",
        "confirmation_source": "llm_review",
        "label": decision["source_label"],
        "source_kind": clean_expr(
            decision.get("source_kind") or candidate.get("source_kind_hint")
        ),
        "function": str(candidate.get("function", "")),
        "plain_line": int(candidate.get("plain_line") or 0),
        "callee": str(candidate.get("callee", "")),
        "args": list(candidate.get("actual_args", []) or []),
        "source_site": clean_expr(candidate.get("source_site", "")),
        "source_buffer": source_expression if output_kind == "memory_object" else "",
        "length_expr": "",
        # Retain the legacy expression field for CopperTrace compatibility;
        # source_output_kind is the authoritative typed interpretation.
        "value_expr": source_expression,
        "source_output_binding": source_output["binding_id"],
        "site_id": str(candidate.get("site_id", "")),
        "source_object_id": object_id,
        "source_value_id": value_id,
        "source_output_kind": output_kind,
        "output_binding_status": binding_status,
        "source_output": {
            "kind": output_kind,
            "expression": source_expression,
            "object_id": object_id,
            "value_id": value_id,
            "binding_status": binding_status,
        },
        "chain_ready": bool(
            object_id if output_kind == "memory_object"
            else value_id if output_kind == "scalar_value"
            else str(candidate.get("site_id", "")).startswith("site:")
        ),
        "static_bindings": dict(candidate.get("static_bindings", {}) or {}),
        "taint_status": "source_semantics_confirmed",
        "vulnerability_status": "not_evaluated",
        "source_candidate_id": str(candidate.get("id", "")),
        "llm_response_file": str(response_path),
        "llm_evidence_refs": list(decision.get("evidence_refs", []) or []),
        "llm_notes": str(decision.get("notes", "")),
        "llm_provenance": decision_provenance(decision, provenance),
    }


def dropped_row_from_candidate(
    *,
    drop_id: str,
    candidate: dict[str, Any],
    decision: dict[str, Any],
    response_path: Path,
    provenance: dict[str, Any],
    drop_kind: str,
) -> dict[str, Any]:
    return {
        "id": drop_id,
        "source_candidate_id": str(candidate.get("id", "")),
        "drop_kind": drop_kind,
        "decision": "rejected",
        "label_hint": str(candidate.get("label_hint", "")),
        "source_kind_hint": str(candidate.get("source_kind_hint", "")),
        "function": str(candidate.get("function", "")),
        "plain_line": int(candidate.get("plain_line") or 0),
        "callee": str(candidate.get("callee", "")),
        "args": list(candidate.get("actual_args", []) or []),
        "source_site": clean_expr(candidate.get("source_site", "")),
        "candidate_source_buffer": clean_expr(candidate.get("candidate_source_buffer", "")),
        "llm_response_file": str(response_path),
        "llm_source_label": decision["source_label"],
        "llm_source_kind": clean_expr(decision.get("source_kind")),
        "llm_source_output": decision["source_output"],
        "llm_evidence_refs": list(decision.get("evidence_refs", []) or []),
        "llm_notes": str(decision.get("notes", "")),
        "llm_provenance": decision_provenance(decision, provenance),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources-json", required=True, type=Path)
    parser.add_argument("--source-unconfirmed-json", required=True, type=Path)
    parser.add_argument("--response", required=True, type=Path)
    parser.add_argument("--output-sources-json", default=None, type=Path)
    parser.add_argument("--source-dropped-json", default=None, type=Path)
    parser.add_argument(
        "--drop-unresolved",
        action="store_true",
        help="Deprecated compatibility option; unresolved candidates always remain blockers.",
    )
    args = parser.parse_args()

    sources = json.loads(args.sources_json.read_text(errors="replace"))
    source_unconfirmed_text = args.source_unconfirmed_json.read_text(errors="replace")
    unconfirmed = json.loads(source_unconfirmed_text)
    candidates = list(unconfirmed.get("candidates", []) or [])
    decisions, provenance, response_error = load_response(args.response)
    if response_error is None:
        response_error = validate_provenance_bindings(
            provenance,
            candidates,
            source_unconfirmed_path=args.source_unconfirmed_json,
            source_unconfirmed_text=source_unconfirmed_text,
        )
    if response_error is None:
        selected_ids = set(provenance["input"]["selected_candidate_ids"])
        unexpected_decision_ids = sorted(set(decisions) - selected_ids)
        if unexpected_decision_ids:
            response_error = {
                "kind": "response_decision_set_mismatch",
                "message": (
                    "response contains decisions outside its selected input: "
                    + ", ".join(unexpected_decision_ids)
                ),
            }

    # Re-resolving must not retain a stale LLM confirmation for a now-blocked candidate.
    confirmed = [
        row for row in list(sources.get("confirmed_sources", []) or [])
        if str(row.get("confirmation_source", "")) != "llm_review"
    ]
    next_id = next_source_id(confirmed)

    confirmed_count = 0
    rejected_count = 0
    unresolved_count = 0
    confirmed_candidate_ids: list[str] = []
    rejected_candidate_ids: list[str] = []
    unresolved_candidate_ids: list[str] = []
    dropped_rows: list[dict[str, Any]] = []
    candidate_resolution: dict[str, dict[str, Any]] = {}
    next_drop_id = 1

    for candidate in candidates:
        cid = str(candidate.get("id", ""))
        decision = decisions.get(cid) if response_error is None else None
        if decision is None:
            failure = response_error or {
                "kind": "missing_decision",
                "message": "adjudication response omitted this candidate",
            }
            unresolved_count += 1
            if cid:
                unresolved_candidate_ids.append(cid)
                candidate_resolution[cid] = {
                    "decision": "analysis_unresolved",
                    "analysis_status": "blocker",
                    "failure_kind": failure["kind"],
                    "output": "source_unconfirmed.json",
                }
            continue

        validation_error = validate_decision_binding(decision, candidate, provenance)
        if validation_error is not None:
            unresolved_count += 1
            if cid:
                unresolved_candidate_ids.append(cid)
                candidate_resolution[cid] = {
                    "decision": "analysis_unresolved",
                    "analysis_status": "blocker",
                    "failure_kind": validation_error["kind"],
                    "output": "source_unconfirmed.json",
                }
            continue

        outcome = decision["decision"]
        if outcome == "confirmed":
            source_id = f"SO{next_id:04d}"
            next_id += 1
            confirmed.append(
                confirmed_row_from_candidate(
                    source_id=source_id,
                    candidate=candidate,
                    decision=decision,
                    response_path=args.response,
                    provenance=provenance,
                )
            )
            confirmed_count += 1
            if cid:
                confirmed_candidate_ids.append(cid)
                candidate_resolution[cid] = {
                    "decision": "confirmed",
                    "output": "sources.json",
                }
        elif outcome == "rejected":
            rejected_count += 1
            if cid:
                rejected_candidate_ids.append(cid)
                candidate_resolution[cid] = {
                    "decision": "rejected",
                    "output": "source_dropped.json",
                    "drop_kind": "llm_semantic_rejected",
                }
            dropped_rows.append(
                dropped_row_from_candidate(
                    drop_id=f"SD{next_drop_id:04d}",
                    candidate=candidate,
                    decision=decision,
                    response_path=args.response,
                    provenance=provenance,
                    drop_kind="llm_semantic_rejected",
                )
            )
            next_drop_id += 1
        else:
            unresolved_count += 1
            if cid:
                unresolved_candidate_ids.append(cid)
                candidate_resolution[cid] = {
                    "decision": "analysis_unresolved",
                    "analysis_status": "blocker",
                    "failure_kind": decision["failure_kind"],
                    "output": "source_unconfirmed.json",
                }

    direct_confirmed = [
        row
        for row in confirmed
        if str(row.get("confirmation_source", "")) != "llm_review"
    ]
    llm_confirmed = [
        row
        for row in confirmed
        if str(row.get("confirmation_source", "")) == "llm_review"
    ]
    output = args.output_sources_json or args.sources_json
    dropped_output = args.source_dropped_json or output.with_name("source_dropped.json")

    sources["confirmed_sources"] = confirmed
    sources["resolution"] = {
        "unconfirmed_total": len(candidates),
        "llm_confirmed_total": confirmed_count,
        "rejected_total": rejected_count,
        "dropped_after_unresolved_total": 0,
        "analysis_unresolved_blockers": unresolved_count,
        "unresolved_blockers": unresolved_count,
        "response_file": str(args.response),
        "response_error": response_error,
        "source_dropped_file": str(dropped_output),
        "confirmed_candidate_ids": confirmed_candidate_ids,
        "rejected_candidate_ids": rejected_candidate_ids,
        "analysis_unresolved_candidate_ids": unresolved_candidate_ids,
        "unresolved_candidate_ids": unresolved_candidate_ids,
        "adjudication_provenance": provenance,
    }
    sources["next_stage_ready"] = unresolved_count == 0
    sources.setdefault("counts", {})["confirmed_sources"] = len(confirmed)
    sources.setdefault("counts", {})["direct_confirmed_sources"] = len(direct_confirmed)
    sources.setdefault("counts", {})["llm_confirmed_sources"] = len(llm_confirmed)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(sources, indent=2, sort_keys=False) + "\n")
    dropped_output.parent.mkdir(parents=True, exist_ok=True)
    dropped_output.write_text(
        json.dumps(
            {
                "schema_version": "ct-mini-source-dropped-v2",
                "source_unconfirmed_json": str(args.source_unconfirmed_json),
                "response_file": str(args.response),
                "adjudication_provenance": provenance,
                "counts": {
                    "dropped_sources": len(dropped_rows),
                    "dropped_after_unresolved": 0,
                },
                "dropped_sources": dropped_rows,
            },
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )

    resolved_candidates: list[dict[str, Any]] = []
    for candidate in candidates:
        row = candidate_hash_payload(candidate)
        cid = str(row.get("id", ""))
        row.update(
            candidate_resolution.get(
                cid,
                {
                    "decision": "analysis_unresolved",
                    "analysis_status": "blocker",
                    "failure_kind": "missing_resolution",
                    "output": "source_unconfirmed.json",
                },
            )
        )
        resolved_candidates.append(row)
    unconfirmed["candidates"] = resolved_candidates
    unconfirmed["resolution"] = {
        "status": "fully_resolved" if unresolved_count == 0 else "analysis_unresolved",
        "confirmed_candidate_ids": confirmed_candidate_ids,
        "rejected_candidate_ids": rejected_candidate_ids,
        "analysis_unresolved_candidate_ids": unresolved_candidate_ids,
        "remaining_need_confirmation_candidate_ids": unresolved_candidate_ids,
        "sources_json": str(output),
        "source_dropped_json": str(dropped_output),
        "response_file": str(args.response),
        "response_error": response_error,
        "adjudication_provenance": provenance,
    }
    unconfirmed.setdefault("counts", {})[
        "remaining_need_confirmation_candidates"
    ] = unresolved_count
    unconfirmed.setdefault("counts", {})["analysis_unresolved_candidates"] = unresolved_count
    args.source_unconfirmed_json.write_text(
        json.dumps(unconfirmed, indent=2, sort_keys=False) + "\n"
    )
    print(json.dumps(sources["resolution"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
