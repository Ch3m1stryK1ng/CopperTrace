#!/usr/bin/env python3
"""Run fail-closed LLM adjudication for MINI semantic source candidates."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


SOURCE_LABELS = [
    "MMIO_READ",
    "ISR_MMIO_READ",
    "ISR_FILLED_BUFFER",
    "DMA_BACKED_BUFFER",
    "BYTE_STREAM_INGRESS",
    "CONTROL_STATE",
    "SENSOR_INPUT",
    "UNKNOWN_SOURCE",
]
CONFIRMED_SOURCE_LABELS = frozenset(SOURCE_LABELS) - {"UNKNOWN_SOURCE"}
MODEL_RESPONSE_SCHEMA_VERSION = "ct-mini-source-llm-model-response-v2"
ADJUDICATION_SCHEMA_VERSION = "ct-mini-source-adjudication-v2"
FINAL_DECISION_VALUES = frozenset({"confirmed", "rejected", "analysis_unresolved"})
MODEL_DECISION_VALUES = frozenset({"confirmed", "rejected", "unresolved"})
HASH_RE = re.compile(r"^[0-9a-f]{64}$")

# Resolution annotations are deliberately excluded so rerunning the resolver does
# not change the identity of the originally mined candidate.
RESOLUTION_ANNOTATION_FIELDS = frozenset(
    {
        "analysis_status",
        "decision",
        "drop_kind",
        "failure_kind",
        "output",
    }
)

SYSTEM_PROMPT = """You are a firmware static-analysis reviewer.
Respond with ONLY one valid JSON object matching the supplied strict schema. Do not use markdown.
Decide whether each pre-mined code slice has Source semantics.
A Source means external/peripheral/environment-controlled data or control state enters firmware and is bound to an offered source output.
Do not decide whether a vulnerability is confirmed or exploitable.
Use only evidence present in the packet. Never invent or rewrite a source expression.
A receive/read-like name alone is never sufficient. Confirm only when the supplied body or call context shows external/MMIO/environment data being written into the offered output.
For unknown MMIO, use semantic_slice to distinguish payload/data flow from status or control use. High P-code proves value flow, not the hardware register's semantic role. Treat register names and function names as hints unless trusted_register_metadata is available.
For example, read_config(out) { memcpy(out, internal_state, n); } is NOT a Source, and parser_input(packet) consuming an already populated packet is NOT a new Source.
"""

MODEL_DECISION_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "candidate_id",
        "candidate_hash",
        "packet_hash",
        "decision",
        "source_label",
        "source_kind",
        "source_output_binding",
        "evidence_refs",
        "notes",
    ],
    "properties": {
        "candidate_id": {"type": "string"},
        "candidate_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "packet_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "decision": {"enum": sorted(MODEL_DECISION_VALUES)},
        "source_label": {"enum": SOURCE_LABELS},
        "source_kind": {"type": "string"},
        "source_output_binding": {"type": ["string", "null"]},
        "evidence_refs": {"type": "array", "items": {"type": "string"}},
        "notes": {"type": "string"},
    },
}
MODEL_RESPONSE_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "decisions"],
    "properties": {
        "schema_version": {"const": MODEL_RESPONSE_SCHEMA_VERSION},
        "decisions": {"type": "array", "items": MODEL_DECISION_JSON_SCHEMA},
    },
}

DECISION_POLICY = [
    "Review each candidate independently.",
    "Use confirmed only for external/peripheral/environment input or externally influenced control state.",
    "Reject internal-state/database/attribute reads that merely copy firmware-owned data into an output buffer.",
    "Do not treat downstream parser/input functions as new Sources when they consume an already-populated packet.",
    "Use rejected only when the evidence positively shows no Source semantics.",
    "Use unresolved whenever evidence is insufficient or no offered source output is correct.",
    "A confirmed source is not a confirmed vulnerability.",
    "Confirmed requires a non-UNKNOWN source_label and source_output_binding equal to one offered binding_id.",
    "For confirmed, source_label must be one of that packet's allowed_source_labels; never infer ISR/DMA context outside the offered set.",
    "When binding_required is true, select only an offered output with a statically verified identity: ObjectId for memory_object, ValueId for scalar_value, or a verified SiteId for event.",
    "For unknown MMIO candidates, decide only the register role and Source semantics; do not alter the High P-code LOAD/STORE binding.",
    "Rejected and unresolved require source_output_binding to be null.",
    "Echo candidate_id, candidate_hash, and packet_hash exactly from each packet.",
]

RETRYABLE_FAILURE_KINDS = frozenset(
    {
        "hash_mismatch",
        "invalid_confirmed_label",
        "invalid_source_binding",
        "llm_error",
        "missing_decision",
        "parse_error",
        "request_error",
        "response_schema_error",
        "timeout",
    }
)


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


def clean_expression(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip())


def candidate_output_bindings(candidate: dict[str, Any]) -> list[dict[str, str]]:
    """Return only expressions explicitly designated as outputs by the miner."""
    bindings: list[dict[str, str]] = []
    seen: set[str] = set()
    for field in (
        "candidate_source_buffer",
        "candidate_source_value",
        "candidate_source_expression",
    ):
        expression = clean_expression(candidate.get(field))
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
                expression = clean_expression(
                    raw_node.get("expression") or raw_node.get("node")
                )
                binding_id = str(raw_node.get("id") or f"candidate_source_nodes[{index}]")
            else:
                expression = clean_expression(raw_node)
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


def load_sourceagent(sourceagent_root: Path) -> None:
    sourceagent_root = sourceagent_root.resolve()
    env_path = sourceagent_root / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv

            load_dotenv(env_path)
        except ImportError:
            pass
    root_text = str(sourceagent_root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)


def compact_code(code: str, *, max_chars: int) -> str:
    code = str(code or "").strip()
    if len(code) <= max_chars:
        return code
    head = max_chars // 2
    tail = max_chars - head
    return code[:head].rstrip() + "\n/* ... truncated ... */\n" + code[-tail:].lstrip()


def compact_candidate(candidate: dict[str, Any], *, max_code_chars: int) -> dict[str, Any]:
    packet = candidate_packet_payload(candidate)
    packet["function_slice"] = compact_code(
        packet["function_slice"], max_chars=max_code_chars
    )
    packet["callee_definition"] = compact_code(
        packet["callee_definition"], max_chars=max_code_chars
    )
    packet["candidate_hash"] = candidate_hash(candidate)
    packet["packet_hash"] = packet_hash(candidate)
    return packet


def prompt_contract() -> dict[str, Any]:
    return {
        "decision_policy": DECISION_POLICY,
        "response_json_schema": MODEL_RESPONSE_JSON_SCHEMA,
    }


def build_prompt(candidate: dict[str, Any], *, max_code_chars: int) -> str:
    return build_batch_prompt([candidate], max_code_chars=max_code_chars)


def build_batch_prompt(candidates: list[dict[str, Any]], *, max_code_chars: int) -> str:
    per_candidate_chars = max(900, min(max_code_chars, 1800))
    packets = [
        compact_candidate(candidate, max_code_chars=per_candidate_chars)
        for candidate in candidates
    ]
    return (
        "Review this batch of MINI semantic source candidates.\n\n"
        "Decision policy and strict response schema:\n"
        + json.dumps(prompt_contract(), indent=2, sort_keys=True)
        + "\n\nCandidate packets:\n"
        + json.dumps(packets, indent=2, sort_keys=True)
    )


def extract_json_object(text: str) -> dict[str, Any]:
    """Parse exactly one JSON object; markdown and surrounding text are invalid."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("LLM response is not a JSON object")
    return data


def _require_exact_keys(data: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(data)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{context} keys differ: missing={missing}, extra={extra}")


def validate_model_response_shape(data: dict[str, Any]) -> list[dict[str, Any]]:
    _require_exact_keys(data, {"schema_version", "decisions"}, "response")
    if data["schema_version"] != MODEL_RESPONSE_SCHEMA_VERSION:
        raise ValueError("unexpected model response schema_version")
    raw_decisions = data["decisions"]
    if not isinstance(raw_decisions, list):
        raise ValueError("response decisions must be a list")

    required = set(MODEL_DECISION_JSON_SCHEMA["required"])
    for index, raw in enumerate(raw_decisions):
        if not isinstance(raw, dict):
            raise ValueError(f"decision {index} is not an object")
        _require_exact_keys(raw, required, f"decision {index}")
        for field in (
            "candidate_id",
            "candidate_hash",
            "packet_hash",
            "decision",
            "source_label",
            "source_kind",
            "notes",
        ):
            if not isinstance(raw[field], str):
                raise ValueError(f"decision {index} field {field} must be a string")
        if not HASH_RE.fullmatch(raw["candidate_hash"]):
            raise ValueError(f"decision {index} candidate_hash is not SHA-256")
        if not HASH_RE.fullmatch(raw["packet_hash"]):
            raise ValueError(f"decision {index} packet_hash is not SHA-256")
        if raw["decision"] not in MODEL_DECISION_VALUES:
            raise ValueError(f"decision {index} has invalid decision value")
        if raw["source_label"] not in SOURCE_LABELS:
            raise ValueError(f"decision {index} has invalid source_label")
        if raw["source_output_binding"] is not None and not isinstance(
            raw["source_output_binding"], str
        ):
            raise ValueError(
                f"decision {index} source_output_binding must be a string or null"
            )
        refs = raw["evidence_refs"]
        if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
            raise ValueError(f"decision {index} evidence_refs must be strings")
    return raw_decisions


def unresolved_decision(
    candidate: dict[str, Any],
    *,
    notes: str,
    failure_kind: str,
    final: bool = False,
) -> dict[str, Any]:
    return {
        "candidate_id": str(candidate.get("id", "")),
        "candidate_hash": candidate_hash(candidate),
        "packet_hash": packet_hash(candidate),
        "decision": "analysis_unresolved" if final else "unresolved",
        "source_label": "UNKNOWN_SOURCE",
        "source_kind": "",
        "source_output": None,
        "evidence_refs": [],
        "notes": str(notes)[:900],
        "failure_kind": failure_kind,
    }


def normalize_decision(data: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Bind a schema-valid model decision to one exact mined candidate."""
    expected_candidate_hash = candidate_hash(candidate)
    expected_packet_hash = packet_hash(candidate)
    if data["candidate_id"] != str(candidate.get("id", "")):
        return unresolved_decision(
            candidate,
            notes="model decision candidate_id did not match the candidate",
            failure_kind="hash_mismatch",
        )
    if (
        data["candidate_hash"] != expected_candidate_hash
        or data["packet_hash"] != expected_packet_hash
    ):
        return unresolved_decision(
            candidate,
            notes="model decision candidate/packet hash did not match the input",
            failure_kind="hash_mismatch",
        )

    decision = data["decision"]
    binding_id = data["source_output_binding"]
    bindings = {
        binding["binding_id"]: binding["expression"]
        for binding in candidate_output_bindings(candidate)
    }
    if decision == "confirmed":
        if data["source_label"] not in CONFIRMED_SOURCE_LABELS:
            return unresolved_decision(
                candidate,
                notes="confirmed decision did not provide a concrete source label",
                failure_kind="invalid_confirmed_label",
            )
        allowed_labels = {
            str(label) for label in list(candidate.get("allowed_source_labels", []) or [])
            if str(label)
        }
        if not allowed_labels or data["source_label"] not in allowed_labels:
            return unresolved_decision(
                candidate,
                notes="confirmed decision selected a source label outside the candidate's allowed labels",
                failure_kind="invalid_confirmed_label",
            )
        if not binding_id or binding_id not in bindings:
            return unresolved_decision(
                candidate,
                notes="confirmed decision did not select an offered source output binding",
                failure_kind="invalid_source_binding",
            )
        offered = next(
            binding for binding in candidate_output_bindings(candidate)
            if binding["binding_id"] == binding_id
        )
        node_error = static_node_binding_error(candidate, offered)
        if node_error:
            return unresolved_decision(
                candidate,
                notes=node_error,
                failure_kind="invalid_source_binding",
            )
        source_output: dict[str, str] | None = {
            "binding_id": binding_id,
            "expression": bindings[binding_id],
        }
    else:
        if binding_id is not None:
            return unresolved_decision(
                candidate,
                notes=f"{decision} decision supplied a source output binding",
                failure_kind="response_schema_error",
            )
        source_output = None

    return {
        "candidate_id": data["candidate_id"],
        "candidate_hash": expected_candidate_hash,
        "packet_hash": expected_packet_hash,
        "decision": decision,
        "source_label": data["source_label"],
        "source_kind": data["source_kind"].strip(),
        "source_output": source_output,
        "evidence_refs": [ref.strip() for ref in data["evidence_refs"] if ref.strip()],
        "notes": data["notes"].strip(),
        "failure_kind": "model_unresolved" if decision == "unresolved" else None,
    }


def analysis_unresolved_decision(
    candidate: dict[str, Any],
    *,
    first_decision: dict[str, Any],
    retry_decision: dict[str, Any] | None = None,
) -> dict[str, Any]:
    decisions = [first_decision]
    if retry_decision is not None:
        decisions.append(retry_decision)
    notes = "; ".join(
        str(decision.get("notes") or decision.get("failure_kind") or "unresolved")
        for decision in decisions
    )
    failure_kind = str(
        (retry_decision or first_decision).get("failure_kind") or "model_unresolved"
    )
    result = unresolved_decision(
        candidate,
        notes=f"analysis unresolved after adjudication: {notes}",
        failure_kind=failure_kind,
        final=True,
    )
    refs: list[str] = []
    for decision in decisions:
        refs.extend(str(ref) for ref in decision.get("evidence_refs", []) if str(ref))
    result["evidence_refs"] = refs
    return result


# Retain these names for callers that imported the old helpers. They now fail closed.
def dropped_after_retry_decision(
    candidate: dict[str, Any],
    *,
    first_decision: dict[str, Any],
    retry_decision: dict[str, Any],
) -> dict[str, Any]:
    return analysis_unresolved_decision(
        candidate,
        first_decision=first_decision,
        retry_decision=retry_decision,
    )


def dropped_without_retry_decision(
    candidate: dict[str, Any],
    *,
    unresolved_decision: dict[str, Any],
) -> dict[str, Any]:
    return analysis_unresolved_decision(
        candidate,
        first_decision=unresolved_decision,
    )


def is_retryable_adjudication_error(decision: dict[str, Any]) -> bool:
    return str(decision.get("failure_kind", "")) in RETRYABLE_FAILURE_KINDS


def format_response(
    decisions: list[dict[str, Any]],
    provenance: dict[str, Any] | None = None,
) -> str:
    response = {
        "schema_version": ADJUDICATION_SCHEMA_VERSION,
        "provenance": provenance or {},
        "decisions": decisions,
    }
    return json.dumps(response, indent=2, sort_keys=True) + "\n"


async def call_llm_for_candidates(
    *,
    candidates: list[dict[str, Any]],
    sourceagent_root: Path,
    model: str | None,
    max_code_chars: int,
    request_timeout_sec: float,
    attempt_provenance: list[dict[str, Any]] | None = None,
    attempt_kind: str = "initial",
) -> list[dict[str, Any]]:
    load_sourceagent(sourceagent_root)
    from sourceagent.llm.llm import LLM

    llm = LLM(model=model)
    try:
        llm.update_config(temperature=0.0)
    except Exception:
        pass

    by_id = {str(candidate.get("id", "")): candidate for candidate in candidates}
    packets = [
        compact_candidate(candidate, max_code_chars=max(900, min(max_code_chars, 1800)))
        for candidate in candidates
    ]
    prompt = build_batch_prompt(candidates, max_code_chars=max_code_chars)
    attempt = {
        "attempt_kind": attempt_kind,
        "candidate_ids": [str(candidate.get("id", "")) for candidate in candidates],
        "candidate_hashes": {
            str(candidate.get("id", "")): candidate_hash(candidate)
            for candidate in candidates
        },
        "packet_hashes": {
            str(candidate.get("id", "")): packet_hash(candidate)
            for candidate in candidates
        },
        "input_sha256": stable_json_hash(packets),
        "system_prompt_sha256": sha256_text(SYSTEM_PROMPT),
        "prompt_sha256": sha256_text(prompt),
        "model_requested": model or "",
        "model_resolved": str(getattr(llm, "model", "")),
        "finish_reason": "",
        "status": "started",
    }

    def finish_attempt(status: str, *, response: Any = None) -> None:
        attempt["status"] = status
        if response is not None:
            attempt["model_resolved"] = str(
                getattr(response, "model", "") or attempt["model_resolved"]
            )
            attempt["finish_reason"] = str(getattr(response, "finish_reason", ""))
        if attempt_provenance is not None:
            attempt_provenance.append(attempt)

    try:
        response = await asyncio.wait_for(
            llm.generate(
                system_prompt=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": prompt}],
                tools=None,
                metadata={
                    "component": "coppertrace-mini",
                    "task": "source_semantic_batch_adjudication",
                    "candidate_count": len(candidates),
                    "input_sha256": attempt["input_sha256"],
                    "prompt_sha256": attempt["prompt_sha256"],
                },
            ),
            timeout=request_timeout_sec,
        )
    except asyncio.TimeoutError:
        finish_attempt("timeout")
        return [
            unresolved_decision(
                candidate,
                notes=f"LLM batch request timed out after {request_timeout_sec:g}s",
                failure_kind="timeout",
            )
            for candidate in candidates
        ]
    except Exception as exc:  # noqa: BLE001 - failures become explicit blockers.
        finish_attempt("request_error")
        return [
            unresolved_decision(
                candidate,
                notes=f"LLM request error: {type(exc).__name__}: {exc}",
                failure_kind="request_error",
            )
            for candidate in candidates
        ]

    content = response.content or ""
    if response.finish_reason == "error" or content.startswith("LLM Error:"):
        finish_attempt("llm_error", response=response)
        return [
            unresolved_decision(
                candidate,
                notes=content[:300] or "LLM returned an error finish reason",
                failure_kind="llm_error",
            )
            for candidate in candidates
        ]

    try:
        data = extract_json_object(content)
    except Exception as exc:  # noqa: BLE001 - parse failures are retryable blockers.
        finish_attempt("parse_error", response=response)
        return [
            unresolved_decision(
                candidate,
                notes=f"failed to parse strict LLM JSON response: {exc}",
                failure_kind="parse_error",
            )
            for candidate in candidates
        ]

    try:
        raw_decisions = validate_model_response_shape(data)
    except (TypeError, ValueError) as exc:
        finish_attempt("response_schema_error", response=response)
        return [
            unresolved_decision(
                candidate,
                notes=f"LLM response schema validation failed: {exc}",
                failure_kind="response_schema_error",
            )
            for candidate in candidates
        ]

    raw_by_id: dict[str, dict[str, Any]] = {}
    duplicate_ids: set[str] = set()
    for raw in raw_decisions:
        cid = raw["candidate_id"]
        if cid in raw_by_id:
            duplicate_ids.add(cid)
        raw_by_id[cid] = raw

    unexpected_ids = sorted(set(raw_by_id) - set(by_id))
    if unexpected_ids:
        finish_attempt("response_schema_error", response=response)
        return [
            unresolved_decision(
                candidate,
                notes=(
                    "LLM response contained decisions for candidates outside the batch: "
                    + ", ".join(unexpected_ids)
                ),
                failure_kind="response_schema_error",
            )
            for candidate in candidates
        ]

    out: list[dict[str, Any]] = []
    for candidate in candidates:
        cid = str(candidate.get("id", ""))
        if cid in duplicate_ids:
            out.append(
                unresolved_decision(
                    candidate,
                    notes="LLM response contained duplicate decisions for this candidate",
                    failure_kind="response_schema_error",
                )
            )
        elif cid not in raw_by_id:
            out.append(
                unresolved_decision(
                    candidate,
                    notes="LLM batch response omitted this candidate",
                    failure_kind="missing_decision",
                )
            )
        else:
            out.append(normalize_decision(raw_by_id[cid], candidate))
    finish_attempt("validated", response=response)
    return out


async def adjudicate_with_batch_retry(
    *,
    candidates: list[dict[str, Any]],
    sourceagent_root: Path,
    model: str | None,
    max_code_chars: int,
    request_timeout_sec: float,
    batch_size: int,
    attempt_provenance: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    decisions: list[dict[str, Any]] = []
    adjudication_errors: list[dict[str, Any]] = []
    batch_size = max(1, batch_size)
    candidates_by_id = {str(candidate.get("id", "")): candidate for candidate in candidates}

    for start in range(0, len(candidates), batch_size):
        batch = candidates[start : start + batch_size]
        first_pass = await call_llm_for_candidates(
            candidates=batch,
            sourceagent_root=sourceagent_root,
            model=model,
            max_code_chars=max_code_chars,
            request_timeout_sec=request_timeout_sec,
            attempt_provenance=attempt_provenance,
            attempt_kind="initial",
        )
        retry_candidates: list[dict[str, Any]] = []
        first_retryable_by_id: dict[str, dict[str, Any]] = {}
        for first_decision in first_pass:
            cid = str(first_decision.get("candidate_id", ""))
            candidate = candidates_by_id.get(cid)
            if candidate is None:
                continue
            if str(first_decision.get("decision", "")) != "unresolved":
                decisions.append(first_decision)
            elif is_retryable_adjudication_error(first_decision):
                retry_candidates.append(candidate)
                first_retryable_by_id[cid] = first_decision
            else:
                decisions.append(
                    analysis_unresolved_decision(
                        candidate,
                        first_decision=first_decision,
                    )
                )

        if not retry_candidates:
            continue

        retry_pass = await call_llm_for_candidates(
            candidates=retry_candidates,
            sourceagent_root=sourceagent_root,
            model=model,
            max_code_chars=max_code_chars,
            request_timeout_sec=request_timeout_sec,
            attempt_provenance=attempt_provenance,
            attempt_kind="retry",
        )
        retry_by_id = {
            str(decision.get("candidate_id", "")): decision for decision in retry_pass
        }
        for candidate in retry_candidates:
            cid = str(candidate.get("id", ""))
            first_decision = first_retryable_by_id[cid]
            retry_decision = retry_by_id.get(
                cid,
                unresolved_decision(
                    candidate,
                    notes="LLM retry batch response omitted this candidate",
                    failure_kind="missing_decision",
                ),
            )
            adjudication_errors.append(
                {
                    "candidate_id": cid,
                    "first_failure_kind": first_decision.get("failure_kind"),
                    "first_pass_notes": first_decision.get("notes", ""),
                    "retry_decision": retry_decision.get("decision", ""),
                    "retry_failure_kind": retry_decision.get("failure_kind"),
                    "retry_notes": retry_decision.get("notes", ""),
                }
            )
            if str(retry_decision.get("decision", "")) == "unresolved":
                decisions.append(
                    analysis_unresolved_decision(
                        candidate,
                        first_decision=first_decision,
                        retry_decision=retry_decision,
                    )
                )
            else:
                decisions.append(retry_decision)
    await asyncio.sleep(1.0)
    return decisions, adjudication_errors


async def adjudicate_and_drain_transports(**kwargs: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    result = await adjudicate_with_batch_retry(**kwargs)
    # LiteLLM caches async HTTP clients globally. Explicitly close them before
    # asyncio.run() tears down the loop, otherwise a successful CLI run can emit
    # a misleading SSL "event loop is closed" traceback.
    try:
        import litellm

        await litellm.close_litellm_async_clients()
    except Exception:
        pass
    await asyncio.sleep(0)
    return result


def build_run_provenance(
    *,
    candidates: list[dict[str, Any]],
    source_unconfirmed_json: Path,
    source_unconfirmed_text: str,
    model: str | None,
    max_code_chars: int,
    request_timeout_sec: float,
    batch_size: int,
    attempts: list[dict[str, Any]],
) -> dict[str, Any]:
    candidate_hashes = {
        str(candidate.get("id", "")): candidate_hash(candidate) for candidate in candidates
    }
    packet_hashes = {
        str(candidate.get("id", "")): packet_hash(candidate) for candidate in candidates
    }
    return {
        "model": {
            "requested": model or "",
            "resolved": sorted(
                {
                    str(attempt.get("model_resolved", ""))
                    for attempt in attempts
                    if str(attempt.get("model_resolved", ""))
                }
            ),
        },
        "prompt": {
            "system_sha256": sha256_text(SYSTEM_PROMPT),
            "contract_sha256": stable_json_hash(prompt_contract()),
            "attempt_sha256": [str(attempt["prompt_sha256"]) for attempt in attempts],
        },
        "input": {
            "source_unconfirmed_json": str(source_unconfirmed_json),
            "source_unconfirmed_sha256": sha256_text(source_unconfirmed_text),
            "selected_candidate_ids": [
                str(candidate.get("id", "")) for candidate in candidates
            ],
            "selected_candidates_sha256": stable_json_hash(
                [candidate_hash_payload(candidate) for candidate in candidates]
            ),
            "candidate_hashes": candidate_hashes,
            "packet_hashes": packet_hashes,
        },
        "parameters": {
            "max_code_chars": max_code_chars,
            "request_timeout_sec": request_timeout_sec,
            "batch_size": max(1, batch_size),
        },
        "attempts": attempts,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sources-json", required=True, type=Path)
    parser.add_argument("--source-unconfirmed-json", required=True, type=Path)
    parser.add_argument("--response", required=True, type=Path)
    parser.add_argument("--sourceagent-root", default=ROOT, type=Path)
    parser.add_argument("--model", default=None)
    parser.add_argument("--max-code-chars", default=7000, type=int)
    parser.add_argument("--request-timeout-sec", default=60.0, type=float)
    parser.add_argument("--batch-size", default=8, type=int)
    parser.add_argument("--limit", default=0, type=int)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--source-dropped-json", default=None, type=Path)
    parser.add_argument("--adjudication-error-json", default=None, type=Path)
    args = parser.parse_args()

    source_unconfirmed_text = args.source_unconfirmed_json.read_text(errors="replace")
    unconfirmed = json.loads(source_unconfirmed_text)
    candidates = list(unconfirmed.get("candidates", []) or [])
    total_candidates = len(candidates)
    if args.limit and args.limit > 0:
        candidates = candidates[: args.limit]
    if args.apply and len(candidates) != total_candidates:
        raise SystemExit(
            "--apply requires adjudicating the complete candidate pool; "
            "--limit is inspection-only"
        )
    args.response.parent.mkdir(parents=True, exist_ok=True)
    error_path = args.adjudication_error_json or args.response.with_name(
        "adjudication_error.json"
    )
    error_path.parent.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []

    if not candidates:
        decisions: list[dict[str, Any]] = []
        adjudication_errors: list[dict[str, Any]] = []
    elif os.environ.get("CT_MINI_SOURCE_LLM_DRY_RUN") == "1":
        decisions = [
            unresolved_decision(
                candidate,
                notes="dry run",
                failure_kind="dry_run",
                final=True,
            )
            for candidate in candidates
        ]
        adjudication_errors = []
    else:
        decisions, adjudication_errors = asyncio.run(
            adjudicate_and_drain_transports(
                candidates=candidates,
                sourceagent_root=args.sourceagent_root,
                model=args.model,
                max_code_chars=args.max_code_chars,
                request_timeout_sec=args.request_timeout_sec,
                batch_size=args.batch_size,
                attempt_provenance=attempts,
            )
        )

    provenance = build_run_provenance(
        candidates=candidates,
        source_unconfirmed_json=args.source_unconfirmed_json,
        source_unconfirmed_text=source_unconfirmed_text,
        model=args.model,
        max_code_chars=args.max_code_chars,
        request_timeout_sec=args.request_timeout_sec,
        batch_size=args.batch_size,
        attempts=attempts,
    )
    args.response.write_text(format_response(decisions, provenance))
    error_path.write_text(
        json.dumps(
            {
                "schema_version": "ct-mini-source-adjudication-errors-v2",
                "candidate_count": len(candidates),
                "retry_attempts": len(adjudication_errors),
                "errors": adjudication_errors,
                "provenance": provenance,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print(
        json.dumps(
            {
                "candidates": len(candidates),
                "confirmed": sum(1 for d in decisions if d["decision"] == "confirmed"),
                "rejected": sum(1 for d in decisions if d["decision"] == "rejected"),
                "analysis_unresolved": sum(
                    1 for d in decisions if d["decision"] == "analysis_unresolved"
                ),
                "response": str(args.response),
                "adjudication_error_json": str(error_path),
            },
            indent=2,
        )
    )
    if args.apply:
        cmd = [
            sys.executable,
            str(Path(__file__).with_name("resolve_source_llm.py")),
            "--sources-json",
            str(args.sources_json),
            "--source-unconfirmed-json",
            str(args.source_unconfirmed_json),
            "--response",
            str(args.response),
        ]
        dropped_path = args.source_dropped_json or args.response.with_name(
            "source_dropped.json"
        )
        cmd.extend(["--source-dropped-json", str(dropped_path)])
        subprocess.run(cmd, check=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
