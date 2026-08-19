#!/usr/bin/env python3
"""Sanitized, read-only evidence access for post-A2 LLM review."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from check_candidate_collector import ProgramFactsIndex


MAX_FUNCTION_CHARS = 24_000
MAX_INITIAL_FUNCTION_CHARS = 12_000
MAX_INITIAL_FUNCTIONS = 2
MAX_CODE_LINES = 200
MAX_PCODE_OPS = 64
FORBIDDEN_TEXT_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


def _stable_id(prefix: str, value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return f"{prefix}:{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:20]}"


def _safe_text(text: str) -> str:
    if FORBIDDEN_TEXT_RE.search(text):
        raise ValueError("review evidence contains a public CVE identifier")
    return text


def prepare_sanitized_decompiled_c(
    source_path: Path,
    destination: Path,
) -> dict[str, Any]:
    text = source_path.read_text(encoding="utf-8", errors="replace")
    _safe_text(text)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_path, destination)
    return {
        "path": str(destination),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "line_count": len(text.splitlines()),
    }


@dataclass
class EvidenceTool:
    name: str
    description: str
    parameters: dict[str, Any]
    execute_fn: Callable[[dict[str, Any]], dict[str, Any]]
    enabled: bool = True

    def to_llm_format(self) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }

    def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return self.execute_fn(arguments)


class ReviewEvidenceStore:
    """Serve allowlisted evidence without exposing filesystem or search."""

    def __init__(
        self,
        *,
        neutral_firmware_id: str,
        decompiled_c_path: Path,
        program_facts: dict[str, Any],
    ):
        self.neutral_firmware_id = neutral_firmware_id
        self.decompiled_c_path = decompiled_c_path
        self.program_facts = program_facts
        self.index = ProgramFactsIndex(program_facts)
        self.lines = decompiled_c_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        self.object_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for raw_row in list(program_facts.get("static_objects", []) or []):
            row = dict(raw_row or {})
            object_id = str(row.get("object_id", "") or "")
            if object_id:
                self.object_rows[object_id].append(row)
        self.query_log: list[dict[str, Any]] = []
        self.queried_reference_ids: set[str] = set()
        self.queried_reference_ids_by_alert: dict[str, set[str]] = defaultdict(set)
        self.allowed_references_by_alert: dict[str, set[str]] = {}

    def fork(
        self,
        *,
        allowed_references_by_alert: dict[str, set[str]] | None = None,
    ) -> "ReviewEvidenceStore":
        """Create one isolated query log while sharing immutable evidence indexes."""

        child = object.__new__(ReviewEvidenceStore)
        child.neutral_firmware_id = self.neutral_firmware_id
        child.decompiled_c_path = self.decompiled_c_path
        child.program_facts = self.program_facts
        child.index = self.index
        child.lines = self.lines
        child.object_rows = self.object_rows
        child.query_log = []
        child.queried_reference_ids = set()
        child.queried_reference_ids_by_alert = defaultdict(set)
        child.allowed_references_by_alert = {
            str(alert_id): set(values)
            for alert_id, values in dict(allowed_references_by_alert or {}).items()
        }
        return child

    def _scope_alert_id(self, arguments: dict[str, Any]) -> str:
        alert_id = str(arguments.get("alert_id", "") or "")
        if not alert_id and len(self.allowed_references_by_alert) == 1:
            alert_id = next(iter(self.allowed_references_by_alert))
        if self.allowed_references_by_alert and alert_id not in self.allowed_references_by_alert:
            raise ValueError("evidence query is outside the Alert namespace")
        return alert_id

    def _require_allowed(self, alert_id: str, *reference_ids: str) -> None:
        if not self.allowed_references_by_alert:
            return
        allowed = self.allowed_references_by_alert.get(alert_id, set())
        unknown = {value for value in reference_ids if value and value not in allowed}
        if unknown:
            raise ValueError(
                "evidence query references an ID outside the Alert namespace: "
                + ", ".join(sorted(unknown))
            )

    @staticmethod
    def _reference_ids(value: Any, key: str = "") -> set[str]:
        result: set[str] = set()
        if isinstance(value, dict):
            for child_key, child in value.items():
                result.update(
                    ReviewEvidenceStore._reference_ids(child, str(child_key))
                )
        elif isinstance(value, list):
            for child in value:
                result.update(ReviewEvidenceStore._reference_ids(child, key))
        elif isinstance(value, str) and (
            key.endswith("_id") or key.endswith("_ids")
        ):
            if value:
                result.add(value)
        return result

    @staticmethod
    def _function_id_from_site_id(site_id: str) -> str:
        parts = str(site_id or "").split(":")
        if len(parts) >= 2 and parts[0] == "site" and parts[1]:
            return f"fn:{parts[1]}"
        return ""

    def initial_decompiled_context(
        self, enriched_alert: dict[str, Any]
    ) -> dict[str, Any]:
        """Preload only the Sink/Check functions needed for semantic review."""

        ordered_ids: list[str] = []

        def add_function_id(value: Any) -> None:
            function_id = str(value or "")
            if function_id and function_id not in ordered_ids:
                ordered_ids.append(function_id)

        alert = dict(enriched_alert.get("alert", {}) or {})
        for key in ("sink_boundary_site_id", "sink_effect_site_id"):
            add_function_id(self._function_id_from_site_id(str(alert.get(key, ""))))

        represented = list(
            dict(enriched_alert.get("check_evidence", {}) or {}).get(
                "represented_alerts", []
            )
            or []
        )
        for represented_alert in represented:
            for parameter in list(represented_alert.get("parameters", []) or []):
                for candidate in list(parameter.get("check_candidates", []) or []):
                    add_function_id(candidate.get("function_id", ""))
                    for key in ("site_id", "branch_site_id", "target_site_id"):
                        add_function_id(
                            self._function_id_from_site_id(
                                str(candidate.get(key, ""))
                            )
                        )

        functions: list[dict[str, Any]] = []
        for function_id in ordered_ids:
            function = self.index.functions.get(function_id)
            if not function:
                continue
            code = _safe_text(str(function.get("decompiled_c", "") or ""))
            functions.append(
                {
                    "function_id": function_id,
                    "name": str(function.get("name", "") or ""),
                    "entry": str(function.get("entry", "") or ""),
                    "decompiled_c": code[:MAX_INITIAL_FUNCTION_CHARS],
                    "truncated": len(code) > MAX_INITIAL_FUNCTION_CHARS,
                }
            )
            if len(functions) >= MAX_INITIAL_FUNCTIONS:
                break
        return {
            "local_file": "decompiled.c",
            "functions": functions,
            "function_count": len(functions),
        }

    def _record(
        self,
        name: str,
        arguments: dict[str, Any],
        result: dict[str, Any],
        *,
        alert_id: str,
    ) -> dict[str, Any]:
        query_id = _stable_id(
            "query",
            {
                "firmware": self.neutral_firmware_id,
                "alert_id": alert_id,
                "ordinal": len(self.query_log),
                "tool": name,
                "arguments": arguments,
            },
        )
        wrapped = {
            "query_id": query_id,
            "firmware_id": self.neutral_firmware_id,
            "alert_id": alert_id,
            "tool": name,
            "result": result,
        }
        _safe_text(json.dumps(wrapped, ensure_ascii=False))
        self.query_log.append(
            {
                "query_id": query_id,
                "alert_id": alert_id,
                "tool": name,
                "arguments": arguments,
                "result_sha256": hashlib.sha256(
                    json.dumps(result, sort_keys=True).encode("utf-8")
                ).hexdigest(),
            }
        )
        result_refs = self._reference_ids(result)
        self.queried_reference_ids.update(result_refs)
        self.queried_reference_ids_by_alert[alert_id].update(
            {query_id, *result_refs}
        )
        return wrapped

    def get_function(self, arguments: dict[str, Any]) -> dict[str, Any]:
        alert_id = self._scope_alert_id(arguments)
        function_id = str(arguments.get("function_id", "") or "")
        self._require_allowed(alert_id, function_id)
        function = self.index.functions.get(function_id)
        if not function:
            result = {"error": "FUNCTION_NOT_FOUND", "function_id": function_id}
        else:
            code = str(function.get("decompiled_c", "") or "")
            result = {
                "function_id": function_id,
                "name": str(function.get("name", "") or ""),
                "entry": str(function.get("entry", "") or ""),
                "decompiled_c": _safe_text(code[:MAX_FUNCTION_CHARS]),
                "truncated": len(code) > MAX_FUNCTION_CHARS,
            }
        return self._record("get_function", arguments, result, alert_id=alert_id)

    def get_code_range(self, arguments: dict[str, Any]) -> dict[str, Any]:
        alert_id = self._scope_alert_id(arguments)
        start_line = max(1, int(arguments.get("start_line", 1) or 1))
        end_line = max(start_line, int(arguments.get("end_line", start_line) or start_line))
        end_line = min(end_line, start_line + MAX_CODE_LINES - 1, len(self.lines))
        excerpt = "\n".join(
            f"{line_number}: {self.lines[line_number - 1]}"
            for line_number in range(start_line, end_line + 1)
        )
        result = {
            "start_line": start_line,
            "end_line": end_line,
            "code": _safe_text(excerpt),
        }
        return self._record("get_code_range", arguments, result, alert_id=alert_id)

    def get_pcode_slice(self, arguments: dict[str, Any]) -> dict[str, Any]:
        alert_id = self._scope_alert_id(arguments)
        function_id = str(arguments.get("function_id", "") or "")
        site_ids = {
            str(value)
            for value in list(arguments.get("site_ids", []) or [])
            if str(value)
        }
        value_ids = {
            str(value)
            for value in list(arguments.get("value_ids", []) or [])
            if str(value)
        }
        self._require_allowed(alert_id, function_id, *site_ids, *value_ids)
        requested = max(1, int(arguments.get("max_ops", 32) or 32))
        max_ops = min(requested, MAX_PCODE_OPS)
        function = self.index.functions.get(function_id, {})
        rows: list[dict[str, Any]] = []
        for raw_op in list(function.get("pcode_ops", []) or []):
            op = dict(raw_op or {})
            op_values = {
                str(dict(op.get("output", {}) or {}).get("value_id", "") or ""),
                *(
                    str(dict(value or {}).get("value_id", "") or "")
                    for value in list(op.get("inputs", []) or [])
                ),
            }
            if site_ids and str(op.get("site_id", "")) not in site_ids and not (op_values & value_ids):
                continue
            if not site_ids and value_ids and not (op_values & value_ids):
                continue
            rows.append(
                {
                    "site_id": str(op.get("site_id", "") or ""),
                    "block_id": str(op.get("block_id", "") or ""),
                    "mnemonic": str(op.get("mnemonic", "") or ""),
                    "output": dict(op.get("output", {}) or {}),
                    "inputs": list(op.get("inputs", []) or []),
                }
            )
            if len(rows) >= max_ops:
                break
        result = {
            "function_id": function_id,
            "ops": rows,
            "truncated": len(rows) >= max_ops,
        }
        return self._record("get_pcode_slice", arguments, result, alert_id=alert_id)

    def get_cfg_relation(self, arguments: dict[str, Any]) -> dict[str, Any]:
        alert_id = self._scope_alert_id(arguments)
        branch_site_id = str(arguments.get("branch_site_id", "") or "")
        target_site_id = str(arguments.get("target_site_id", "") or "")
        self._require_allowed(alert_id, branch_site_id, target_site_id)
        entry = self.index.ops_by_site.get(branch_site_id)
        relation = None
        if entry and str(entry[1].get("mnemonic", "")) == "CBRANCH":
            relation = self.index.branch_relation(entry[0], entry[1], [target_site_id])
        result = {
            "branch_site_id": branch_site_id,
            "target_site_id": target_site_id,
            "relation": relation,
        }
        return self._record("get_cfg_relation", arguments, result, alert_id=alert_id)

    def get_object_fact(self, arguments: dict[str, Any]) -> dict[str, Any]:
        alert_id = self._scope_alert_id(arguments)
        object_id = str(arguments.get("object_id", "") or "")
        self._require_allowed(alert_id, object_id)
        rows = self.object_rows.get(object_id, [])
        allowed_rows: list[dict[str, Any]] = []
        for row in rows:
            allowed = {}
            for key in (
                "object_id",
                "kind",
                "function_id",
                "name",
                "storage_space",
                "base_offset",
                "extent",
                "writable",
                "extent_evidence",
            ):
                if key in row:
                    allowed[key] = row[key]
            allowed_rows.append(allowed)
        result = (
            {"object_id": object_id, "facts": allowed_rows}
            if allowed_rows
            else {"error": "OBJECT_NOT_FOUND", "object_id": object_id}
        )
        return self._record("get_object_fact", arguments, result, alert_id=alert_id)

    def tools(self) -> list[EvidenceTool]:
        return [
            EvidenceTool(
                "get_function",
                "Read one exact decompiled function by FunctionId.",
                {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "alert_id": {"type": "string"},
                        "function_id": {"type": "string"},
                    },
                    "required": ["alert_id", "function_id"],
                },
                self.get_function,
            ),
            EvidenceTool(
                "get_pcode_slice",
                "Read a bounded High P-code slice for exact FunctionId/SiteId/ValueId anchors.",
                {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "alert_id": {"type": "string"},
                        "function_id": {"type": "string"},
                        "site_ids": {"type": "array", "items": {"type": "string"}},
                        "value_ids": {"type": "array", "items": {"type": "string"}},
                        "max_ops": {"type": "integer", "minimum": 1, "maximum": MAX_PCODE_OPS},
                    },
                    "required": ["alert_id", "function_id"],
                },
                self.get_pcode_slice,
            ),
            EvidenceTool(
                "get_cfg_relation",
                "Verify the CFG relation between one exact branch and one target site.",
                {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "alert_id": {"type": "string"},
                        "branch_site_id": {"type": "string"},
                        "target_site_id": {"type": "string"},
                    },
                    "required": ["alert_id", "branch_site_id", "target_site_id"],
                },
                self.get_cfg_relation,
            ),
            EvidenceTool(
                "get_object_fact",
                "Read one exact static object extent/storage fact by ObjectId.",
                {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "alert_id": {"type": "string"},
                        "object_id": {"type": "string"},
                    },
                    "required": ["alert_id", "object_id"],
                },
                self.get_object_fact,
            ),
        ]

    def evidence_reference_ids(self, alert_id: str = "") -> set[str]:
        base = {
            str(row.get("query_id", ""))
            for row in self.query_log
            if str(row.get("query_id", ""))
            and (not alert_id or str(row.get("alert_id", "")) == alert_id)
        }
        if alert_id:
            return base | set(self.queried_reference_ids_by_alert.get(alert_id, set()))
        return base | set(self.queried_reference_ids)
