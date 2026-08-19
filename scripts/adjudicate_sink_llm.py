#!/usr/bin/env python3
"""Run LLM adjudication for MINI semantic sink candidates.

Input:
  * sinks.json
  * sink_unconfirmed.json

Output:
  * response_LLM.txt in the format consumed by resolve_sink_llm.py
  * optional resolved sinks.json when --apply is passed

This script deliberately asks the LLM to decide sink *semantics* only.  It must
not classify a vulnerability or exploitability.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


SINK_LABELS = [
    "COPY_SINK",
    "MEMSET_SINK",
    "STORE_SINK",
    "LOOP_WRITE_SINK",
    "FORMAT_STRING_SINK",
    "FUNC_PTR_SINK",
    "LIFETIME_SINK",
    "UNKNOWN_SINK",
]

SEMANTIC_LABEL_HINTS = [
    "UNBOUNDED_WALK_SINK",
    "PARSING_OVERFLOW_SINK",
]


SYSTEM_PROMPT = """You are a firmware static-analysis reviewer.
Respond with ONLY valid JSON. Do not use markdown.
Your task is to decide whether a pre-mined call/function slice has sink semantics.
Do not decide whether a vulnerability is confirmed or exploitable.
Use only evidence present in the packet.
"""


def load_sourceagent(sourceagent_root: Path) -> None:
    """Load SourceAgent's .env and make its package importable."""
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
    code = code.strip()
    if len(code) <= max_chars:
        return code
    head = max_chars // 2
    tail = max_chars - head
    return code[:head].rstrip() + "\n/* ... truncated ... */\n" + code[-tail:].lstrip()


def compact_candidate(candidate: dict[str, Any], *, max_code_chars: int) -> dict[str, Any]:
    """Keep the LLM packet focused and bounded."""
    packet = {
        "candidate_id": candidate.get("id", ""),
        "reason": candidate.get("reason", ""),
        "function": candidate.get("function", ""),
        "plain_line": candidate.get("plain_line", 0),
        "callee": candidate.get("callee", ""),
        "callsite": candidate.get("callsite", ""),
        "actual_args": candidate.get("actual_args", []),
        "compat_sink_label": candidate.get("compat_sink_label", ""),
        "suggested_sink_label": candidate.get("suggested_sink_label", ""),
        "semantic_hint_label": candidate.get("semantic_hint_label", ""),
        "pattern": candidate.get("pattern", ""),
        "known_facts": candidate.get("known_facts", []),
        "callee_definition": compact_code(
            str(candidate.get("callee_definition", "")),
            max_chars=max_code_chars,
        ),
        "nested_definitions": [],
    }
    nested_limit = max(1200, max_code_chars // 3)
    for nested in list(candidate.get("nested_definitions", []) or [])[:3]:
        packet["nested_definitions"].append(
            {
                "callee": nested.get("callee", ""),
                "callsite": nested.get("callsite", ""),
                "definition": compact_code(
                    str(nested.get("definition", "")),
                    max_chars=nested_limit,
                ),
            }
        )
    return packet


def build_prompt(candidate: dict[str, Any], *, max_code_chars: int) -> str:
    packet = compact_candidate(candidate, max_code_chars=max_code_chars)
    instructions = {
        "decision_values": ["confirmed", "rejected", "unresolved"],
        "sink_label_values": SINK_LABELS,
        "semantic_label_hints": SEMANTIC_LABEL_HINTS,
        "decision_policy": [
            "Use confirmed only when the provided code shows memory copy/write/fill/format/control-flow/lifetime/parser-walk sink semantics.",
            "Use rejected when the code is clearly not a sink, for example a pure lookup, comparison, logging with literal format, or metadata registration.",
            "Use unresolved when the slice is insufficient, target function is missing, or roles cannot be inferred.",
            "A confirmed sink is not a confirmed vulnerability.",
            "sink_label must be one of sink_label_values and should remain compatible with CopperTrace's current SinkLabel enum.",
            "If a finer parser semantic applies, put it in semantic_label or notes; do not use it as sink_label unless it is in sink_label_values.",
            "Loop-copy, parser-store, and unbounded-walk patterns are semantic and may be confirmed as sink semantics when the code shape is clear.",
        ],
        "required_json_schema": {
            "candidate_id": "same id as packet",
            "decision": "confirmed | rejected | unresolved",
            "sink_label": "one value from sink_label_values",
            "semantic_label": "optional finer-grained label, e.g. one value from semantic_label_hints",
            "roles": {
                "dst": "destination expression if known",
                "src": "source expression if known",
                "len": "length/bound expression if known",
                "value": "stored value if known",
                "fmt": "format expression if known",
                "target": "function pointer target expression if known",
            },
            "evidence_refs": [
                "short references to callsite or definition snippets in this packet"
            ],
            "notes": "one concise sentence; mention unresolved assumptions",
        },
    }
    return (
        "Review this MINI semantic sink candidate.\n\n"
        "Rules and output schema:\n"
        + json.dumps(instructions, indent=2, sort_keys=False)
        + "\n\nCandidate packet:\n"
        + json.dumps(packet, indent=2, sort_keys=False)
    )


def extract_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start < 0 or end < start:
            raise
        data = _json_loads_tolerating_c_escapes(stripped[start : end + 1])
    if not isinstance(data, dict):
        raise ValueError("LLM response is not a JSON object")
    return data


def _json_loads_tolerating_c_escapes(text: str) -> Any:
    """Parse JSON, repairing common C-string escapes emitted from code snippets.

    Firmware snippets often contain C literals such as '\\0' or '\\x01'.  Models
    sometimes copy them into JSON strings as single-backslash escapes, which is
    invalid JSON.  Doubling only non-JSON escapes preserves the visible text
    without accepting arbitrary malformed structure.
    """
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        repaired = re.sub(r'\\(?!["\\/bfnrtu])', r"\\\\", text)
        return json.loads(repaired)


def normalize_decision(data: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    decision = str(data.get("decision", "unresolved")).strip().lower()
    if decision not in {"confirmed", "rejected", "unresolved"}:
        decision = "unresolved"
    sink_label = str(data.get("sink_label") or data.get("label") or "UNKNOWN_SINK").strip()
    if sink_label not in SINK_LABELS:
        sink_label = "UNKNOWN_SINK"
    semantic_label = str(data.get("semantic_label") or "").strip()
    if semantic_label.lower() in {"none", "null", "unknown", "n/a"}:
        semantic_label = ""
    roles = data.get("roles", {})
    if not isinstance(roles, dict):
        roles = {}
    evidence_refs = data.get("evidence_refs", [])
    if not isinstance(evidence_refs, list):
        evidence_refs = [str(evidence_refs)]
    cleaned_roles: dict[str, str] = {}
    for key, value in roles.items():
        value_text = str(value).strip()
        if not value_text or value_text.lower() in {"none", "null", "unknown", "n/a"}:
            continue
        cleaned_roles[str(key)] = value_text
    return {
        "candidate_id": str(data.get("candidate_id") or candidate.get("id", "")),
        "decision": decision,
        "sink_label": sink_label,
        "semantic_label": semantic_label,
        "roles": cleaned_roles,
        "evidence_refs": [str(x) for x in evidence_refs if str(x).strip()],
        "notes": str(data.get("notes", "")).strip(),
    }


def format_response(decisions: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for decision in decisions:
        cid = decision["candidate_id"]
        lines.append(f"{cid}:")
        lines.append(f"  decision: {decision['decision']}")
        lines.append(f"  sink_label: {decision['sink_label']}")
        if decision.get("semantic_label"):
            lines.append(f"  semantic_label: {decision['semantic_label']}")
        lines.append("  roles:")
        roles = decision.get("roles", {})
        if roles:
            for key in sorted(roles):
                lines.append(f"    {key}: {roles[key]}")
        lines.append("  evidence_refs:")
        evidence_refs = decision.get("evidence_refs", [])
        if evidence_refs:
            for ref in evidence_refs:
                lines.append(f"    - {ref}")
        notes = str(decision.get("notes", "")).replace("\n", " ").strip()
        lines.append(f"  notes: {notes}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


async def call_llm_for_candidates(
    *,
    candidates: list[dict[str, Any]],
    sourceagent_root: Path,
    model: str | None,
    max_code_chars: int,
) -> list[dict[str, Any]]:
    load_sourceagent(sourceagent_root)
    from sourceagent.llm.llm import LLM

    llm = LLM(model=model)
    try:
        llm.update_config(temperature=0.0)
    except Exception:
        pass
    decisions: list[dict[str, Any]] = []
    for candidate in candidates:
        prompt = build_prompt(candidate, max_code_chars=max_code_chars)
        response = await llm.generate(
            system_prompt=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
            tools=None,
            metadata={
                "component": "coppertrace-mini",
                "task": "sink_semantic_adjudication",
                "candidate_id": str(candidate.get("id", "")),
            },
        )
        content = response.content or ""
        if response.finish_reason == "error" or content.startswith("LLM Error:"):
            decisions.append(
                {
                    "candidate_id": str(candidate.get("id", "")),
                    "decision": "unresolved",
                    "sink_label": "UNKNOWN_SINK",
                    "roles": {},
                    "evidence_refs": [],
                    "notes": content.splitlines()[0] if content else "LLM error",
                }
            )
            continue
        try:
            parsed = extract_json_object(content)
            decisions.append(normalize_decision(parsed, candidate))
        except Exception as exc:  # noqa: BLE001 - keep adjudication robust.
            decisions.append(
                {
                    "candidate_id": str(candidate.get("id", "")),
                    "decision": "unresolved",
                    "sink_label": "UNKNOWN_SINK",
                    "roles": {},
                    "evidence_refs": [],
                    "notes": f"LLM parse error: {exc}",
                }
            )
    return decisions


async def call_llm_and_drain(
    *,
    candidates: list[dict[str, Any]],
    sourceagent_root: Path,
    model: str | None,
    max_code_chars: int,
) -> list[dict[str, Any]]:
    decisions = await call_llm_for_candidates(
        candidates=candidates,
        sourceagent_root=sourceagent_root,
        model=model,
        max_code_chars=max_code_chars,
    )
    # Some LiteLLM/httpx transports finish SSL close-notify callbacks just
    # after the final response. Give them one short tick before asyncio.run()
    # closes the loop; this keeps CLI output cleaner without changing results.
    await asyncio.sleep(0.25)
    return decisions


def selected_candidates(
    artifact: dict[str, Any],
    *,
    candidate_ids: set[str],
    limit: int | None,
) -> list[dict[str, Any]]:
    candidates = list(artifact.get("candidates", []) or [])
    if candidate_ids:
        candidates = [c for c in candidates if str(c.get("id", "")) in candidate_ids]
    if limit is not None:
        candidates = candidates[: max(0, limit)]
    return candidates


def run_resolver(
    *,
    script_dir: Path,
    sinks_json: Path,
    sink_unconfirmed_json: Path,
    response: Path,
    output_sinks_json: Path | None,
) -> None:
    cmd = [
        sys.executable,
        str(script_dir / "resolve_sink_llm.py"),
        "--sinks-json",
        str(sinks_json),
        "--sink-unconfirmed-json",
        str(sink_unconfirmed_json),
        "--response",
        str(response),
    ]
    if output_sinks_json:
        cmd.extend(["--output-sinks-json", str(output_sinks_json)])
    subprocess.run(cmd, check=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sinks-json", required=True, type=Path)
    parser.add_argument("--sink-unconfirmed-json", required=True, type=Path)
    parser.add_argument("--response", required=True, type=Path)
    parser.add_argument("--output-sinks-json", default=None, type=Path)
    parser.add_argument("--sourceagent-root", default=ROOT, type=Path)
    parser.add_argument("--model", default=None, help="Defaults to SOURCEAGENT_MODEL from SourceAgent .env.")
    parser.add_argument("--candidate-id", action="append", default=[])
    parser.add_argument("--limit", default=None, type=int)
    parser.add_argument("--max-code-chars", default=9000, type=int)
    parser.add_argument("--dry-run-prompts", default=None, type=Path)
    parser.add_argument("--apply", action="store_true", help="Run resolve_sink_llm.py after writing response_LLM.txt.")
    args = parser.parse_args()

    unconfirmed = json.loads(args.sink_unconfirmed_json.read_text())
    candidates = selected_candidates(
        unconfirmed,
        candidate_ids={str(x) for x in args.candidate_id},
        limit=args.limit,
    )

    args.response.parent.mkdir(parents=True, exist_ok=True)
    if args.dry_run_prompts:
        args.dry_run_prompts.parent.mkdir(parents=True, exist_ok=True)
        prompts = [
            {
                "candidate_id": str(candidate.get("id", "")),
                "prompt": build_prompt(candidate, max_code_chars=args.max_code_chars),
            }
            for candidate in candidates
        ]
        args.dry_run_prompts.write_text(json.dumps(prompts, indent=2, sort_keys=False) + "\n")
        print(json.dumps({"dry_run_prompts": len(prompts), "path": str(args.dry_run_prompts)}, indent=2))
        return 0

    if not candidates:
        args.response.write_text("")
        print(json.dumps({"adjudicated": 0, "response": str(args.response)}, indent=2))
        return 0

    model = args.model or os.getenv("SOURCEAGENT_MODEL")
    decisions = asyncio.run(
        call_llm_and_drain(
            candidates=candidates,
            sourceagent_root=args.sourceagent_root,
            model=model,
            max_code_chars=max(1000, args.max_code_chars),
        )
    )
    args.response.write_text(format_response(decisions))

    summary = {
        "input_candidates_total": len(list(unconfirmed.get("candidates", []) or [])),
        "selected_adjudicated": len(decisions),
        "selected_confirmed": sum(1 for d in decisions if d["decision"] == "confirmed"),
        "selected_rejected": sum(1 for d in decisions if d["decision"] == "rejected"),
        "selected_unresolved": sum(1 for d in decisions if d["decision"] == "unresolved"),
        "response": str(args.response),
    }
    if args.apply:
        run_resolver(
            script_dir=Path(__file__).resolve().parent,
            sinks_json=args.sinks_json,
            sink_unconfirmed_json=args.sink_unconfirmed_json,
            response=args.response,
            output_sinks_json=args.output_sinks_json,
        )
        summary["applied"] = True
        summary["output_sinks_json"] = str(args.output_sinks_json or args.sinks_json)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
