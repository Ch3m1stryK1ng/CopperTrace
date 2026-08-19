#!/usr/bin/env python3
"""Single-stage whole-Alert LLM review for A2 canonical Static Alerts."""

from __future__ import annotations

import asyncio
import copy
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from review_evidence_store import EvidenceTool, ReviewEvidenceStore


REVIEW_SCHEMA_VERSION = "ct-mini-whole-alert-review-v3"
REVIEWED_ALERTS_SCHEMA_VERSION = "ct-mini-reviewed-alerts-v4"
REVIEW_POLICY_VERSION = "whole-alert-single-review-v4.0-impact-aware"
MAX_BATCH_SIZE = 4

WHOLE_ALERT_SYSTEM_PROMPT = """You review a batch of unchanged CopperTrace Static Alerts from one firmware.
The analyzer has already fixed each Source, Sink, vulnerable parameters, and data-flow path. Never rewrite them and never use CVE knowledge.

For every Alert, decide exactly one:
- TRUPOC: supplied evidence positively supports an attacker-influenced violation of a concrete memory-range, object-state, or pointer-validity invariant at the reported Sink, with a plausible security-relevant consequence.
- REJECT: supplied evidence clearly shows that every dangerous condition listed for all reported vulnerable parameters cannot occur at this Sink.
- UNRESOLVED: a material relation is genuinely missing or conflicting, so neither TRUPOC nor REJECT is supportable.

Be decisive when the evidence supports a direction. Missing Check or object-capacity evidence alone is not positive vulnerability evidence: use UNRESOLVED when the invariant violation cannot be established. A heuristic Check may support REJECT when its structural relation is clear in Decompiled C. Do not reject because code merely looks careful, and do not select TRUPOC from function-name reputation.

Before selecting TRUPOC, establish from supplied evidence: (1) which Source-derived value controls the dangerous range or object state; (2) the concrete invariant that can be violated; (3) why collected Checks do not prevent that violation; and (4) a plausible security effect such as out-of-object read/write, invalid pointer dereference, corrupted buffer state, or externally observable disclosure/control impact. A Source-backed copy or parse operation is not by itself a vulnerability.

For reads, distinguish a true out-of-object access from a bounded read inside an allocated packet. A read followed by an effective late semantic drop is not automatically a vulnerability unless the read itself can cross the object boundary, fault, escape in output, or influence later memory/control behavior. Do not infer either safety or vulnerability from unknown extent alone.

For COPY_SINK, distinguish data provenance from address control. Source Association for the src role commonly means that external bytes are being copied; by itself it does not mean the src pointer is attacker-controlled and does not require a separate source-capacity proof. Source-range validity becomes a dangerous condition when the code or supplied path shows that an attacker-influenced address, index, offset, or extent can select the read range. In that case, a bound on only the destination endpoint is not enough to REJECT. Likewise, a destination-length bound is not enough when destination record selection or object validity remains attacker-influenced. Do not infer a valid object extent merely from pointer arithmetic, field offsets, or a plausible-looking struct layout. Explicit body evidence such as alloc(n) followed by copy(n), a successful tailroom reservation for the same n, or a clamp to both source-remaining and destination-remaining may prove a bounded supporting transformation. For BUFFER_STATE_SINK, an amount-versus-length Check is not enough when the reported buffer object or its type/state is also vulnerable. Calling an operation a bounded supporting transformation requires evidence for every applicable object and state invariant, not only one arithmetic identity.

A Check supports REJECT only when it governs every execution of the reported Sink and remains valid after relevant state mutation. An entry Check does not prove safety for a Sink inside a loop, repeated list traversal, callback recurrence, or later invocation when cursor, length, link, or object-state fields can change. If supplied control flow permits the Sink to revisit and mutate the same state until the original bound no longer holds, treat that path as plausibly dangerous rather than extending the initial Check as an unstated invariant.

Use only evidence inside each alert_namespace. Never cite evidence from another Alert in the batch. Relevant Decompiled C functions are included. If one exact relation is missing, issue all required read-only queries together when possible and include alert_id in every query. After the available query rounds, return decisions from the evidence obtained instead of requesting the same evidence again.

Return one bare JSON object with exactly one decision per input Alert and no markdown.
"""


class ReviewProtocolError(ValueError):
    pass


@dataclass
class StageInvocation:
    response: dict[str, Any] | None
    provenance: dict[str, Any]
    error: str = ""


BatchCallable = Callable[
    [list[dict[str, Any]], ReviewEvidenceStore], Awaitable[StageInvocation]
]


def _strict_json_object(text: str) -> dict[str, Any]:
    stripped = str(text or "").strip()
    if not stripped or stripped.startswith("```"):
        raise ReviewProtocolError("response is not a bare JSON object")
    try:
        result = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ReviewProtocolError(f"invalid JSON: {exc}") from exc
    if not isinstance(result, dict):
        raise ReviewProtocolError("response is not a JSON object")
    return result


def _require_exact_keys(
    value: dict[str, Any], *, required: set[str], allowed: set[str]
) -> None:
    missing = sorted(required - set(value))
    extra = sorted(set(value) - allowed)
    if missing:
        raise ReviewProtocolError("missing response fields: " + ", ".join(missing))
    if extra:
        raise ReviewProtocolError("unexpected response fields: " + ", ".join(extra))


def _reference_ids(value: Any, key: str = "") -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        for child_key, child in value.items():
            refs.update(_reference_ids(child, str(child_key)))
    elif isinstance(value, list):
        for child in value:
            refs.update(_reference_ids(child, key))
    elif isinstance(value, str) and (
        key.endswith("_id")
        or key.endswith("_ids")
        or key.endswith("_fingerprint")
        or key.endswith("_fingerprints")
        or key == "fingerprint"
        or key in {"check_id", "evidence_id"}
    ):
        if value:
            refs.add(value)
    return refs


def alert_id(enriched_alert: dict[str, Any]) -> str:
    return str(dict(enriched_alert.get("alert", {}) or {}).get("alert_id", "") or "")


def alert_namespaces(rows: list[dict[str, Any]]) -> dict[str, set[str]]:
    namespaces: dict[str, set[str]] = {}
    for row in rows:
        current_id = alert_id(row)
        if not current_id or current_id in namespaces:
            raise ReviewProtocolError("batch contains a missing or duplicate alert_id")
        namespaces[current_id] = _reference_ids(row)
    return namespaces


def _packet_reference_ids(
    enriched_alert: dict[str, Any], evidence_store: ReviewEvidenceStore
) -> set[str]:
    current_id = alert_id(enriched_alert)
    return _reference_ids(enriched_alert) | evidence_store.evidence_reference_ids(
        current_id
    )


def validate_batch_response(
    response: dict[str, Any],
    batch: list[dict[str, Any]],
    evidence_store: ReviewEvidenceStore,
) -> list[dict[str, Any]]:
    required_top = {"schema_version", "decisions"}
    _require_exact_keys(response, required=required_top, allowed=required_top)
    if response.get("schema_version") != REVIEW_SCHEMA_VERSION:
        raise ReviewProtocolError("unexpected review schema_version")
    decisions = response.get("decisions")
    if not isinstance(decisions, list):
        raise ReviewProtocolError("decisions must be an array")

    expected = {alert_id(row): row for row in batch}
    if len(decisions) != len(expected):
        raise ReviewProtocolError("review did not return exactly one decision per Alert")
    decision_keys = {
        "alert_id",
        "decision",
        "dangerous_condition",
        "blocking_relation",
        "evidence_refs",
        "missing_evidence",
        "reason",
    }
    normalized: dict[str, dict[str, Any]] = {}
    for raw in decisions:
        if not isinstance(raw, dict):
            raise ReviewProtocolError("review decision is not an object")
        _require_exact_keys(raw, required=decision_keys, allowed=decision_keys)
        current_id = str(raw.get("alert_id", "") or "")
        if current_id not in expected or current_id in normalized:
            raise ReviewProtocolError("review returned an unknown or duplicate alert_id")
        decision = str(raw.get("decision", "") or "")
        if decision not in {"TRUPOC", "REJECT", "UNRESOLVED"}:
            raise ReviewProtocolError("invalid whole-Alert decision")
        refs = raw.get("evidence_refs")
        missing = raw.get("missing_evidence")
        if not isinstance(refs, list) or not isinstance(missing, list):
            raise ReviewProtocolError("evidence_refs and missing_evidence must be arrays")
        refs = [str(value) for value in refs if str(value)]
        missing = [str(value) for value in missing if str(value)]
        unknown_refs = set(refs) - _packet_reference_ids(
            expected[current_id], evidence_store
        )
        if unknown_refs:
            raise ReviewProtocolError(
                f"{current_id} cited evidence outside its namespace: "
                + ", ".join(sorted(unknown_refs))
            )
        if decision in {"TRUPOC", "REJECT"} and not refs:
            raise ReviewProtocolError(f"{decision} must cite supplied evidence")
        if decision == "REJECT" and not str(raw.get("blocking_relation", "") or "").strip():
            raise ReviewProtocolError("REJECT must state the blocking relation")
        if decision == "UNRESOLVED" and not missing:
            raise ReviewProtocolError("UNRESOLVED must name missing evidence")
        normalized[current_id] = {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "alert_id": current_id,
            "decision": decision,
            "dangerous_condition": str(raw.get("dangerous_condition", "") or "").strip(),
            "blocking_relation": str(raw.get("blocking_relation", "") or "").strip(),
            "evidence_refs": refs,
            "missing_evidence": missing,
            "reason": str(raw.get("reason", "") or "").strip(),
        }
    if set(normalized) != set(expected):
        raise ReviewProtocolError("review Alert IDs do not equal the input batch")
    return [normalized[alert_id(row)] for row in batch]


def _batch_prompt(
    batch: list[dict[str, Any]], evidence_store: ReviewEvidenceStore
) -> str:
    packets = []
    for row in batch:
        packets.append(
            {
                "alert_namespace": alert_id(row),
                "unchanged_alert": row.get("alert", {}),
                "sink_review_question": row.get("sink_review_question", {}),
                "check_evidence": row.get("check_evidence", {}),
                "decompiled_context": evidence_store.initial_decompiled_context(row),
            }
        )
    packet = {
        "schema_version": "ct-mini-whole-alert-review-packet-v3",
        "firmware_id": evidence_store.neutral_firmware_id,
        "alerts": packets,
        "required_response": {
            "schema_version": REVIEW_SCHEMA_VERSION,
            "decisions": [
                {
                    "alert_id": "exact input alert_id",
                    "decision": "TRUPOC | REJECT | UNRESOLVED",
                    "dangerous_condition": "condition at the reported Sink",
                    "blocking_relation": "effective preventing relation, or empty",
                    "evidence_refs": ["IDs from this alert_namespace only"],
                    "missing_evidence": ["material missing relations for UNRESOLVED"],
                    "reason": "concise whole-Alert reason",
                }
            ],
        },
    }
    return json.dumps(packet, indent=2, sort_keys=True)


def _tool_call_parts(raw: Any) -> tuple[str, str, dict[str, Any]]:
    call_id = str(
        getattr(raw, "id", "")
        or (raw.get("id", "") if isinstance(raw, dict) else "")
    )
    function = getattr(raw, "function", None)
    if function is None and isinstance(raw, dict):
        function = raw.get("function", {})
    name = str(
        getattr(function, "name", "")
        or (function.get("name", "") if isinstance(function, dict) else "")
    )
    arguments = getattr(function, "arguments", "")
    if isinstance(function, dict):
        arguments = function.get("arguments", arguments)
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments or "{}")
        except json.JSONDecodeError as exc:
            raise ReviewProtocolError(f"invalid tool arguments for {name}: {exc}") from exc
    if not isinstance(arguments, dict):
        raise ReviewProtocolError(f"tool arguments for {name} are not an object")
    return call_id, name, arguments


def _llm_tool_call_dict(raw: Any) -> dict[str, Any]:
    call_id, name, arguments = _tool_call_parts(raw)
    return {
        "id": call_id,
        "type": "function",
        "function": {"name": name, "arguments": json.dumps(arguments, sort_keys=True)},
    }


def load_sourceagent(sourceagent_root: Path) -> None:
    sourceagent_root = sourceagent_root.resolve()
    env_path = sourceagent_root / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv

            load_dotenv(env_path, override=False)
        except ImportError:
            pass
    if str(sourceagent_root) not in sys.path:
        sys.path.insert(0, str(sourceagent_root))


class SourceAgentBatchRunner:
    """One fresh LLM/tool session per same-firmware Alert batch."""

    def __init__(
        self,
        *,
        sourceagent_root: Path,
        model: str,
        reasoning_effort: str = "high",
        request_timeout_sec: float = 180.0,
        max_tool_rounds: int = 2,
        max_attempts: int = 2,
    ):
        self.sourceagent_root = sourceagent_root
        self.model = model
        self.reasoning_effort = reasoning_effort
        self.request_timeout_sec = request_timeout_sec
        self.max_tool_rounds = max_tool_rounds
        self.max_attempts = max_attempts

    async def __call__(
        self,
        batch: list[dict[str, Any]],
        evidence_store: ReviewEvidenceStore,
    ) -> StageInvocation:
        if not 1 <= len(batch) <= MAX_BATCH_SIZE:
            return StageInvocation(None, {}, "batch size must be between 1 and 4")
        attempts: list[dict[str, Any]] = []
        last_error = ""
        # Large batches are an optimization. If one cannot complete promptly,
        # the corpus runner splits it; expensive retries are reserved for the
        # irreducible single-Alert review.
        attempt_limit = self.max_attempts if len(batch) == 1 else 1
        tool_round_limit = self.max_tool_rounds if len(batch) == 1 else 1
        for attempt_number in range(1, attempt_limit + 1):
            try:
                response, provenance = await self._run_once(
                    batch,
                    evidence_store,
                    max_tool_rounds=tool_round_limit,
                )
                attempts.append({"attempt": attempt_number, **provenance, "status": "OK"})
                return StageInvocation(
                    response=response,
                    provenance={"stage": "whole_alert", "attempts": attempts},
                )
            except Exception as exc:  # noqa: BLE001 - explicit unresolved output.
                last_error = f"{type(exc).__name__}: {exc}"
                attempts.append(
                    {
                        "attempt": attempt_number,
                        "status": "ERROR",
                        "error": last_error,
                        "model_requests": int(getattr(exc, "ct_model_requests", 1) or 1),
                    }
                )
        return StageInvocation(
            response=None,
            provenance={"stage": "whole_alert", "attempts": attempts},
            error=last_error or "whole-Alert review failed",
        )

    async def _run_once(
        self,
        batch: list[dict[str, Any]],
        evidence_store: ReviewEvidenceStore,
        *,
        max_tool_rounds: int,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        load_sourceagent(self.sourceagent_root)
        from sourceagent.llm.llm import LLM

        llm = LLM(model=self.model)
        try:
            llm.update_config(
                temperature=0.0,
                reasoning_effort=self.reasoning_effort,
            )
        except Exception:
            pass
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": _batch_prompt(batch, evidence_store)}
        ]
        tools = evidence_store.tools()
        tool_by_name = {tool.name: tool for tool in tools}
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        resolved_model = str(getattr(llm, "model", "") or "")
        finish_reason = ""
        model_requests = 0

        for _round in range(max_tool_rounds + 1):
            final_response_round = _round == max_tool_rounds
            if final_response_round and _round:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "No evidence-query rounds remain. Return the required bare "
                            "JSON decision object now, using only evidence already supplied."
                        ),
                    }
                )
            model_requests += 1
            try:
                response = await asyncio.wait_for(
                    llm.generate(
                        system_prompt=WHOLE_ALERT_SYSTEM_PROMPT,
                        messages=messages,
                        tools=[] if final_response_round else tools,
                        metadata={
                            "component": "coppertrace-mini",
                            "task": "whole_alert_review_v3",
                            "alert_ids": [alert_id(row) for row in batch],
                        },
                    ),
                    timeout=self.request_timeout_sec,
                )
            except Exception as exc:
                setattr(exc, "ct_model_requests", model_requests)
                raise
            resolved_model = str(getattr(response, "model", "") or resolved_model)
            finish_reason = str(getattr(response, "finish_reason", "") or "")
            for key in usage:
                usage[key] += int(dict(getattr(response, "usage", {}) or {}).get(key, 0) or 0)
            if finish_reason == "error" or str(response.content or "").startswith("LLM Error:"):
                raise RuntimeError(str(response.content or "LLM request failed"))
            raw_tool_calls = list(response.tool_calls or [])
            if not raw_tool_calls:
                try:
                    parsed = _strict_json_object(str(response.content or ""))
                    # Protocol-invalid output is retryable just like a timeout.
                    # Without this check an empty object bypasses the bounded
                    # retry policy and turns the whole batch into a false
                    # execution failure.
                    validate_batch_response(parsed, batch, evidence_store)
                except Exception as exc:
                    if isinstance(exc, ReviewProtocolError) and "parsed" in locals():
                        exc = ReviewProtocolError(
                            f"{exc}; response_keys={sorted(parsed)}"
                        )
                    setattr(exc, "ct_model_requests", model_requests)
                    raise exc
                return parsed, {
                    "model_requested": self.model,
                    "model_resolved": resolved_model,
                    "finish_reason": finish_reason,
                    "usage": usage,
                    "tool_queries": copy.deepcopy(evidence_store.query_log),
                    "model_requests": model_requests,
                }
            messages.append(
                {
                    "role": "assistant",
                    "content": str(response.content or ""),
                    "tool_calls": [_llm_tool_call_dict(call) for call in raw_tool_calls],
                }
            )
            for raw_call in raw_tool_calls:
                call_id, name, arguments = _tool_call_parts(raw_call)
                tool: EvidenceTool | None = tool_by_name.get(name)
                if not tool:
                    result = {"error": "TOOL_NOT_ALLOWED", "tool": name}
                else:
                    try:
                        result = tool.execute(arguments)
                    except Exception as exc:  # scoped query errors are evidence, not crashes.
                        result = {"error": "QUERY_REJECTED", "reason": str(exc)}
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "name": name,
                        "content": json.dumps(result, sort_keys=True),
                    }
                )
        error = RuntimeError("review tool-round budget exhausted")
        setattr(error, "ct_model_requests", model_requests)
        raise error


def _invocation_model_requests(invocation: StageInvocation | None) -> int:
    if invocation is None:
        return 0
    attempts = list(dict(invocation.provenance or {}).get("attempts", []) or [])
    if attempts:
        return sum(int(attempt.get("model_requests", 1) or 1) for attempt in attempts)
    return int(dict(invocation.provenance or {}).get("model_requests", 1) or 1)


def _review_provenance(invocation: StageInvocation) -> dict[str, Any]:
    return {
        "reviewer_stage_invocations": 1,
        "llm_calls": _invocation_model_requests(invocation),
        "whole_alert": copy.deepcopy(invocation.provenance),
        "errors": [invocation.error] if invocation.error else [],
    }


def _result_row(
    enriched_alert: dict[str, Any],
    decision: dict[str, Any],
    invocation: StageInvocation,
) -> dict[str, Any]:
    semantic = str(decision.get("decision", "") or "")
    if semantic == "TRUPOC":
        action, status = "RETAIN", "RESOLVED"
    elif semantic == "REJECT":
        action, status = "REJECT", "RESOLVED"
    else:
        action, status = "RETAIN", "UNRESOLVED"
    return {
        "alert": copy.deepcopy(enriched_alert.get("alert", {})),
        "sink_review_question": copy.deepcopy(
            enriched_alert.get("sink_review_question", {})
        ),
        "check_evidence": copy.deepcopy(enriched_alert.get("check_evidence", {})),
        "review_action": action,
        "review_status": status,
        "review_reason": str(decision.get("reason", "") or ""),
        "whole_review": copy.deepcopy(decision),
        "review_provenance": _review_provenance(invocation),
    }


def _failed_batch_rows(
    batch: list[dict[str, Any]], invocation: StageInvocation, reason: str
) -> list[dict[str, Any]]:
    rows = [
        _result_row(
            row,
            {
                "schema_version": REVIEW_SCHEMA_VERSION,
                "alert_id": alert_id(row),
                "decision": "UNRESOLVED",
                "dangerous_condition": "",
                "blocking_relation": "",
                "evidence_refs": [],
                "missing_evidence": ["REVIEW_EXECUTION_FAILED"],
                "reason": reason,
            },
            invocation,
        )
        for row in batch
    ]
    _share_batch_cost(rows)
    return rows


def _share_batch_cost(rows: list[dict[str, Any]]) -> None:
    batch_id = "batch:" + ":".join(
        str(dict(row.get("alert", {}) or {}).get("alert_id", "")) for row in rows
    )
    for index, row in enumerate(rows):
        provenance = dict(row.get("review_provenance", {}) or {})
        provenance["batch_id"] = batch_id
        provenance["batch_cost_owner"] = index == 0
        if index:
            provenance["llm_calls"] = 0
            provenance["reviewer_stage_invocations"] = 0
        row["review_provenance"] = provenance


async def review_enriched_batch(
    batch: list[dict[str, Any]],
    *,
    evidence_store: ReviewEvidenceStore,
    reviewer: BatchCallable,
) -> list[dict[str, Any]]:
    if not 1 <= len(batch) <= MAX_BATCH_SIZE:
        raise ReviewProtocolError("review batches must contain 1-4 Alerts")
    invocation = await reviewer(batch, evidence_store)
    if invocation.error or not invocation.response:
        return _failed_batch_rows(
            batch, invocation, "whole_alert_review_execution_failed"
        )
    try:
        decisions = validate_batch_response(
            invocation.response, batch, evidence_store
        )
    except ReviewProtocolError as exc:
        invocation.error = str(exc)
        return _failed_batch_rows(
            batch, invocation, "whole_alert_review_protocol_invalid"
        )
    rows = [
        _result_row(row, decision, invocation)
        for row, decision in zip(batch, decisions)
    ]
    _share_batch_cost(rows)
    return rows


def group_reviewed_alerts(rows: list[dict[str, Any]]) -> dict[str, Any]:
    trupocs: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    for row in rows:
        action = str(row.get("review_action", ""))
        status = str(row.get("review_status", ""))
        if action == "RETAIN" and status == "RESOLVED":
            trupocs.append(row)
        elif action == "REJECT" and status == "RESOLVED":
            rejected.append(row)
        elif action == "RETAIN" and status == "UNRESOLVED":
            unresolved.append(row)
        else:
            raise ReviewProtocolError(f"invalid final review state: {action} + {status}")
    return {
        "schema_version": REVIEWED_ALERTS_SCHEMA_VERSION,
        "counts": {
            "reviewed": len(rows),
            "trupocs": len(trupocs),
            "rejected": len(rejected),
            "unresolved": len(unresolved),
            "llm_calls": sum(
                int(dict(row.get("review_provenance", {}) or {}).get("llm_calls", 0) or 0)
                for row in rows
            ),
            "reviewer_stage_invocations": sum(
                int(
                    dict(row.get("review_provenance", {}) or {}).get(
                        "reviewer_stage_invocations", 0
                    )
                    or 0
                )
                for row in rows
            ),
        },
        "trupocs": trupocs,
        "rejected_alerts": rejected,
        "unresolved_alerts": unresolved,
    }
