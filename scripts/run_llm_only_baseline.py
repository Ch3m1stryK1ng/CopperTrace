#!/usr/bin/env python3
"""Run one code-only vulnerability-discovery session per Decompiled C file."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "ct-mini-llm-only-baseline-v1"
REPORT_SCHEMA_VERSION = "ct-mini-llm-only-report-v1"
POLICY_VERSION = "code-only-taint-style-v1"
MAX_READ_LINES = 240
MAX_SEARCH_RESULTS = 50
MAX_FUNCTION_LINES = 600
CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


SYSTEM_PROMPT = """You are analyzing one complete Decompiled C file from a monolithic firmware image.
Find high-confidence taint-style vulnerabilities in which externally controlled data can cause:
- an out-of-bounds memory-buffer read or write through copy, move, string-copy, fill, a proved wrapper, or paired buffer-state mutation; or
- use of an externally controlled format string.

You have only read-only tools over decompiled.c. You do not have CVE descriptions, expected answers, P-code, or analyzer results. Establish a concrete Source, Sink, vulnerable parameters, data-flow path, relevant Checks, and why the Checks do not prevent the dangerous condition. Do not report a normal copy merely because it moves external data. Do not report standalone parser loads/pointer walks, NULL/type-state/lifetime/function-pointer/arithmetic/protocol/authentication bugs.

Search broadly enough to inspect input boundaries and dangerous operations. Evidence must cite exact line ranges returned by tools. Return zero reports when the code does not support a concrete vulnerability. Never invent a function, expression, line, Source, Sink, or Check.

Return one bare JSON object and no markdown.
"""


class ProtocolError(ValueError):
    pass


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sanitize_code(text: str) -> str:
    return CVE_RE.sub("REDACTED_PUBLIC_IDENTIFIER", text)


def validate_preflight(path: Path, expected_model_alias: str) -> dict[str, Any]:
    value = read_json(path)
    if value.get("status") != "READY":
        raise RuntimeError("CLIProxy preflight is not READY")
    if value.get("expected_model_alias") != expected_model_alias:
        raise RuntimeError("CLIProxy preflight model alias differs from this run")
    if not value.get("exact_model_callable", False) or value.get("fallback_allowed", True):
        raise RuntimeError("CLIProxy preflight does not prove exact no-fallback model access")
    return value


def strict_json_object(text: str) -> dict[str, Any]:
    stripped = str(text or "").strip()
    if not stripped or stripped.startswith("```"):
        raise ProtocolError("response is not a bare JSON object")
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ProtocolError("response is not a JSON object")
    return value


@dataclass(frozen=True)
class FunctionSpan:
    name: str
    start_line: int
    end_line: int


@dataclass(frozen=True)
class ToolSpec:
    value: dict[str, Any]
    enabled: bool = True

    def to_llm_format(self) -> dict[str, Any]:
        return self.value


class CodeStore:
    """Bounded read-only views derived exclusively from Decompiled C text."""

    def __init__(self, path: Path):
        self.path = path
        self.lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        self.functions = self._index_functions()
        self.query_log: list[dict[str, Any]] = []

    def _index_functions(self) -> list[FunctionSpan]:
        spans: list[FunctionSpan] = []
        control = {"if", "for", "while", "switch", "return", "sizeof"}
        for index, line in enumerate(self.lines):
            if "(" not in line:
                continue
            combined = line
            cursor = index
            while "{" not in combined and cursor + 1 < len(self.lines) and cursor - index < 8:
                cursor += 1
                combined += " " + self.lines[cursor].strip()
            if "{" not in combined:
                continue
            prefix = combined.split("(", 1)[0].strip()
            match = re.search(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*$", prefix)
            if not match or match.group(1) in control:
                continue
            name = match.group(1)
            depth = 0
            seen_open = False
            end = cursor
            for body_index in range(index, min(len(self.lines), index + 10000)):
                body_line = self.lines[body_index]
                depth += body_line.count("{")
                if "{" in body_line:
                    seen_open = True
                depth -= body_line.count("}")
                end = body_index
                if seen_open and depth <= 0:
                    break
            if seen_open:
                spans.append(FunctionSpan(name, index + 1, end + 1))
        unique: dict[tuple[str, int], FunctionSpan] = {}
        for span in spans:
            unique[(span.name, span.start_line)] = span
        return sorted(unique.values(), key=lambda span: span.start_line)

    def _record(self, tool: str, arguments: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        self.query_log.append(
            {
                "tool": tool,
                "arguments": arguments,
                "result_sha256": sha256_text(json.dumps(result, sort_keys=True)),
            }
        )
        return result

    def search_code(self, arguments: dict[str, Any]) -> dict[str, Any]:
        pattern = str(arguments.get("pattern", "") or "")
        if not pattern or len(pattern) > 240:
            raise ValueError("pattern must contain 1..240 characters")
        use_regex = bool(arguments.get("regex", False))
        max_results = min(MAX_SEARCH_RESULTS, max(1, int(arguments.get("max_results", 20) or 20)))
        matcher = re.compile(pattern, re.IGNORECASE) if use_regex else None
        hits: list[dict[str, Any]] = []
        for index, line in enumerate(self.lines):
            matched = bool(matcher.search(line)) if matcher else pattern.lower() in line.lower()
            if not matched:
                continue
            start = max(0, index - 2)
            end = min(len(self.lines), index + 3)
            hits.append(
                {
                    "line": index + 1,
                    "context": "\n".join(
                        f"{line_no + 1}: {self.lines[line_no]}" for line_no in range(start, end)
                    ),
                }
            )
            if len(hits) >= max_results:
                break
        result = {"pattern": pattern, "hits": hits, "truncated": len(hits) >= max_results}
        return self._record("search_code", arguments, result)

    def read_code(self, arguments: dict[str, Any]) -> dict[str, Any]:
        start = max(1, int(arguments.get("start_line", 1) or 1))
        end = max(start, int(arguments.get("end_line", start) or start))
        end = min(len(self.lines), end, start + MAX_READ_LINES - 1)
        result = {
            "start_line": start,
            "end_line": end,
            "code": "\n".join(f"{line_no}: {self.lines[line_no - 1]}" for line_no in range(start, end + 1)),
            "truncated": int(arguments.get("end_line", end) or end) > end,
        }
        return self._record("read_code", arguments, result)

    def list_functions(self, arguments: dict[str, Any]) -> dict[str, Any]:
        pattern = str(arguments.get("name_pattern", "") or "")
        max_results = min(200, max(1, int(arguments.get("max_results", 100) or 100)))
        matcher = re.compile(pattern, re.IGNORECASE) if pattern else None
        rows = [
            {"name": span.name, "start_line": span.start_line, "end_line": span.end_line}
            for span in self.functions
            if matcher is None or matcher.search(span.name)
        ]
        result = {"functions": rows[:max_results], "truncated": len(rows) > max_results}
        return self._record("list_functions", arguments, result)

    def get_function(self, arguments: dict[str, Any]) -> dict[str, Any]:
        name = str(arguments.get("name", "") or "")
        candidates = [span for span in self.functions if span.name == name]
        if not candidates:
            candidates = [span for span in self.functions if span.name.lower() == name.lower()]
        if not candidates:
            return self._record("get_function", arguments, {"error": "FUNCTION_NOT_FOUND", "name": name})
        span = candidates[0]
        end = min(span.end_line, span.start_line + MAX_FUNCTION_LINES - 1)
        result = {
            "name": span.name,
            "start_line": span.start_line,
            "end_line": end,
            "code": "\n".join(
                f"{line_no}: {self.lines[line_no - 1]}"
                for line_no in range(span.start_line, end + 1)
            ),
            "truncated": end < span.end_line,
        }
        return self._record("get_function", arguments, result)

    def tool_specs(self) -> list[ToolSpec]:
        return [ToolSpec(value) for value in [
            {
                "type": "function",
                "function": {
                    "name": "search_code",
                    "description": "Search the complete Decompiled C file and return bounded line-numbered contexts.",
                    "parameters": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "pattern": {"type": "string"},
                            "regex": {"type": "boolean"},
                            "max_results": {"type": "integer", "minimum": 1, "maximum": MAX_SEARCH_RESULTS},
                        },
                        "required": ["pattern"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_code",
                    "description": "Read a bounded line range from decompiled.c.",
                    "parameters": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "start_line": {"type": "integer", "minimum": 1},
                            "end_line": {"type": "integer", "minimum": 1},
                        },
                        "required": ["start_line", "end_line"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "list_functions",
                    "description": "List function names and line ranges recovered lexically from Decompiled C.",
                    "parameters": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "name_pattern": {"type": "string"},
                            "max_results": {"type": "integer", "minimum": 1, "maximum": 200},
                        },
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "get_function",
                    "description": "Read one complete decompiled function by exact name, subject to a fixed line bound.",
                    "parameters": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {"name": {"type": "string"}},
                        "required": ["name"],
                    },
                },
            },
        ]]

    def execute(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handlers = {
            "search_code": self.search_code,
            "read_code": self.read_code,
            "list_functions": self.list_functions,
            "get_function": self.get_function,
        }
        if name not in handlers:
            return {"error": "TOOL_NOT_ALLOWED", "tool": name}
        return handlers[name](arguments)


def validate_report(value: dict[str, Any], firmware_id: str, line_count: int) -> dict[str, Any]:
    if value.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ProtocolError("unexpected schema_version")
    if value.get("firmware_id") != firmware_id:
        raise ProtocolError("unexpected firmware_id")
    reports = value.get("reports")
    if not isinstance(reports, list):
        raise ProtocolError("reports must be an array")
    normalized: list[dict[str, Any]] = []
    required = {
        "report_id",
        "vulnerability_class",
        "source",
        "sink",
        "vulnerable_parameters",
        "path",
        "checks",
        "dangerous_condition",
        "reason",
        "evidence",
        "confidence",
    }
    for index, report in enumerate(reports):
        if not isinstance(report, dict) or not required.issubset(report):
            raise ProtocolError(f"report {index} is missing required fields")
        if report.get("vulnerability_class") not in {"OOB_READ", "OOB_WRITE", "FORMAT_STRING"}:
            raise ProtocolError(f"report {index} has unsupported vulnerability_class")
        evidence = report.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            raise ProtocolError(f"report {index} has no evidence")
        for item in evidence:
            if not isinstance(item, dict):
                raise ProtocolError(f"report {index} evidence is not an object")
            start = int(item.get("start_line", 0) or 0)
            end = int(item.get("end_line", 0) or 0)
            if not 1 <= start <= end <= line_count:
                raise ProtocolError(f"report {index} evidence line range is invalid")
        normalized.append(dict(report))
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "firmware_id": firmware_id,
        "reports": normalized,
    }


def response_prompt(firmware_id: str, store: CodeStore) -> str:
    return json.dumps(
        {
            "schema_version": "ct-mini-llm-only-request-v1",
            "firmware_id": firmware_id,
            "code_file": "decompiled.c",
            "line_count": len(store.lines),
            "lexically_indexed_functions": len(store.functions),
            "required_response": {
                "schema_version": REPORT_SCHEMA_VERSION,
                "firmware_id": firmware_id,
                "reports": [
                    {
                        "report_id": "stable local identifier",
                        "vulnerability_class": "OOB_READ | OOB_WRITE | FORMAT_STRING",
                        "source": {"function": "", "line": 0, "expression": "", "input_kind": ""},
                        "sink": {"function": "", "line": 0, "expression": "", "operation": ""},
                        "vulnerable_parameters": [{"role": "", "expression": ""}],
                        "path": ["ordered code-level data-flow steps"],
                        "checks": ["relevant Check or explicit absence in inspected path"],
                        "dangerous_condition": "concrete violated bound/invariant",
                        "reason": "concise code-grounded explanation",
                        "evidence": [{"start_line": 1, "end_line": 1, "purpose": ""}],
                        "confidence": "HIGH | MEDIUM | LOW",
                    }
                ],
            },
        },
        indent=2,
        sort_keys=True,
    )


def load_sourceagent(sourceagent_root: Path) -> None:
    env_path = sourceagent_root / ".env"
    if env_path.is_file():
        try:
            from dotenv import load_dotenv

            load_dotenv(env_path, override=False)
        except ImportError:
            pass
    if str(sourceagent_root.resolve()) not in sys.path:
        sys.path.insert(0, str(sourceagent_root.resolve()))


def tool_call_parts(raw: Any) -> tuple[str, str, dict[str, Any]]:
    call_id = str(getattr(raw, "id", "") or (raw.get("id", "") if isinstance(raw, dict) else ""))
    function = getattr(raw, "function", None)
    if function is None and isinstance(raw, dict):
        function = raw.get("function", {})
    name = str(getattr(function, "name", "") or (function.get("name", "") if isinstance(function, dict) else ""))
    arguments = getattr(function, "arguments", "")
    if isinstance(function, dict):
        arguments = function.get("arguments", arguments)
    if isinstance(arguments, str):
        arguments = json.loads(arguments or "{}")
    if not isinstance(arguments, dict):
        raise ProtocolError("tool arguments are not an object")
    return call_id, name, arguments


async def run_one(
    *,
    sample: dict[str, Any],
    output_root: Path,
    workspace_root: Path,
    sourceagent_root: Path,
    model: str,
    expected_model_alias: str,
    reasoning_effort: str,
    max_tool_rounds: int,
    request_timeout: float,
    resume: bool,
) -> dict[str, Any]:
    firmware_id = str(sample["sample_id"])
    output_path = output_root / "per_sample" / firmware_id / "report.json"
    if resume and output_path.is_file():
        existing = read_json(output_path)
        if existing.get("status") in {"COMPLETED", "FAILED"}:
            return existing
    source_path = Path(str(sample["decompiled_c_path"]))
    code = sanitize_code(source_path.read_text(encoding="utf-8", errors="replace"))
    neutral_code = workspace_root / firmware_id / "decompiled.c"
    neutral_code.parent.mkdir(parents=True, exist_ok=True)
    neutral_code.write_text(code, encoding="utf-8")
    store = CodeStore(neutral_code)
    load_sourceagent(sourceagent_root)
    from sourceagent.llm.llm import LLM

    attempts: list[dict[str, Any]] = []
    for attempt in range(1, 3):
        llm = LLM(model=model)
        try:
            llm.update_config(temperature=0.0, reasoning_effort=reasoning_effort)
        except Exception:
            pass
        messages: list[dict[str, Any]] = [{"role": "user", "content": response_prompt(firmware_id, store)}]
        usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        try:
            for round_index in range(max_tool_rounds + 1):
                final_round = round_index == max_tool_rounds
                if final_round and round_index:
                    messages.append({"role": "user", "content": "No query rounds remain. Return the required bare JSON object now."})
                response = await asyncio.wait_for(
                    llm.generate(
                        system_prompt=SYSTEM_PROMPT,
                        messages=messages,
                        tools=[] if final_round else store.tool_specs(),
                        metadata={"component": "coppertrace-mini", "task": "llm_only_baseline", "firmware_id": firmware_id},
                    ),
                    timeout=request_timeout,
                )
                for key in usage:
                    usage[key] += int(dict(getattr(response, "usage", {}) or {}).get(key, 0) or 0)
                calls = list(getattr(response, "tool_calls", []) or [])
                if not calls:
                    parsed = validate_report(strict_json_object(str(response.content or "")), firmware_id, len(store.lines))
                    resolved_model = str(getattr(response, "model", "") or "")
                    if resolved_model != expected_model_alias:
                        raise ProtocolError(
                            f"resolved model {resolved_model!r} != {expected_model_alias!r}"
                        )
                    result = {
                        "schema_version": SCHEMA_VERSION,
                        "policy_version": POLICY_VERSION,
                        "status": "COMPLETED",
                        "firmware_id": firmware_id,
                        "model_requested": model,
                        "model_resolved": resolved_model,
                        "reasoning_effort": reasoning_effort,
                        "code": {"line_count": len(store.lines), "sha256": sha256_text(code)},
                        "report": parsed,
                        "query_log": store.query_log,
                        "usage": usage,
                        "attempts": attempts + [{"attempt": attempt, "status": "OK"}],
                    }
                    write_json(output_path, result)
                    return result
                messages.append(
                    {
                        "role": "assistant",
                        "content": str(response.content or ""),
                        "tool_calls": [
                            {
                                "id": tool_call_parts(call)[0],
                                "type": "function",
                                "function": {
                                    "name": tool_call_parts(call)[1],
                                    "arguments": json.dumps(tool_call_parts(call)[2], sort_keys=True),
                                },
                            }
                            for call in calls
                        ],
                    }
                )
                for call in calls:
                    call_id, name, arguments = tool_call_parts(call)
                    try:
                        tool_result = store.execute(name, arguments)
                    except Exception as exc:  # bounded tool errors are returned to the model.
                        tool_result = {"error": "QUERY_REJECTED", "reason": str(exc)}
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": call_id,
                            "name": name,
                            "content": json.dumps(tool_result, sort_keys=True),
                        }
                    )
            raise RuntimeError("tool-round budget exhausted")
        except Exception as exc:  # one retry, then explicit failure.
            attempts.append({"attempt": attempt, "status": "ERROR", "error": f"{type(exc).__name__}: {exc}"})
    result = {
        "schema_version": SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "status": "FAILED",
        "firmware_id": firmware_id,
        "model_requested": model,
        "reasoning_effort": reasoning_effort,
        "code": {"line_count": len(store.lines), "sha256": sha256_text(code)},
        "report": {"schema_version": REPORT_SCHEMA_VERSION, "firmware_id": firmware_id, "reports": []},
        "query_log": store.query_log,
        "attempts": attempts,
    }
    write_json(output_path, result)
    return result


def policy_record(args: argparse.Namespace) -> dict[str, Any]:
    return {
        "schema_version": "ct-mini-llm-only-policy-freeze-v1",
        "policy_version": POLICY_VERSION,
        "system_prompt_sha256": sha256_text(SYSTEM_PROMPT),
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "runner_sha256": sha256_file(Path(__file__)),
        "model_requested": args.model,
        "expected_model_alias": args.expected_model_alias,
        "reasoning_effort": args.reasoning_effort,
        "max_tool_rounds": args.max_tool_rounds,
        "request_timeout": args.request_timeout,
        "tool_schema_sha256": hashlib.sha256(
            CodeStore.tool_specs.__code__.co_code
        ).hexdigest(),
        "scope": ["OOB_READ", "OOB_WRITE", "FORMAT_STRING"],
        "forbidden_inputs": [
            "CVE identity",
            "public endpoint",
            "P-code",
            "CopperTrace artifacts",
        ],
    }


async def run_corpus(args: argparse.Namespace) -> dict[str, Any]:
    preflight = validate_preflight(args.preflight_record, args.expected_model_alias)
    policy = policy_record(args)
    if args.policy_mode == "calibrate":
        write_json(args.policy_freeze, policy)
    elif args.policy_freeze.is_file():
        frozen = read_json(args.policy_freeze)
        if frozen != policy:
            raise RuntimeError("LLM-only policy differs from the frozen Development policy")
    else:
        raise FileNotFoundError("frozen LLM-only Development policy is missing")
    manifest = read_json(args.manifest)
    samples = [dict(row) for row in list(manifest.get("samples", []) or [])]
    semaphore = asyncio.Semaphore(max(1, args.max_concurrency))

    async def bounded(sample: dict[str, Any]) -> dict[str, Any]:
        async with semaphore:
            return await run_one(
                sample=sample,
                output_root=args.out,
                workspace_root=args.workspace,
                sourceagent_root=args.sourceagent_root,
                model=args.model,
                expected_model_alias=args.expected_model_alias,
                reasoning_effort=args.reasoning_effort,
                max_tool_rounds=args.max_tool_rounds,
                request_timeout=args.request_timeout,
                resume=args.resume,
            )

    results = await asyncio.gather(*(bounded(sample) for sample in samples))
    reports = sum(len(dict(row.get("report", {}) or {}).get("reports", []) or []) for row in results)
    counts = {
        "firmwares": len(samples),
        "completed": sum(row.get("status") == "COMPLETED" for row in results),
        "failed": sum(row.get("status") == "FAILED" for row in results),
        "vulnerability_reports": reports,
    }
    summary = {
        "schema_version": SCHEMA_VERSION,
        "policy_version": POLICY_VERSION,
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "policy_freeze": str(args.policy_freeze.resolve()),
        "preflight": preflight,
        "counts": counts,
        "samples": [
            {
                "firmware_id": row["firmware_id"],
                "status": row["status"],
                "reports": len(dict(row.get("report", {}) or {}).get("reports", []) or []),
            }
            for row in results
        ],
    }
    write_json(args.out / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--sourceagent-root", type=Path, default=ROOT)
    parser.add_argument("--model", default="openai/gpt-5.6-sol")
    parser.add_argument("--expected-model-alias", default="gpt-5.6-sol")
    parser.add_argument("--preflight-record", type=Path, required=True)
    parser.add_argument("--reasoning-effort", choices=["low", "medium", "high", "xhigh"], default="xhigh")
    parser.add_argument("--max-concurrency", type=int, default=2)
    parser.add_argument("--max-tool-rounds", type=int, default=10)
    parser.add_argument("--request-timeout", type=float, default=600.0)
    parser.add_argument("--policy-freeze", type=Path, required=True)
    parser.add_argument(
        "--policy-mode", choices=["calibrate", "frozen"], default="frozen"
    )
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    summary = asyncio.run(run_corpus(args))
    print(json.dumps(summary["counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
