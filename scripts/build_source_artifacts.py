#!/usr/bin/env python3
"""Build CopperTrace Mini source artifacts from a decompiled C corpus.

The first MINI source miner mirrors the sink miner interface:
  * deterministic source sites go to sources.json;
  * semantic/ambiguous candidates go to source_unconfirmed.json;
  * raw status/config observations are deliberately not exported as sources.

This script is intentionally text-level over the decompiled corpus.  It does
not claim path feasibility or exploitability; it only identifies source
semantics and source-buffer bindings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hardware_profile_matcher
from mmio_register_resolver import MMIORegisterResolver, is_external_input_role
import software_source_engine
import device_dispatch_resolver
import finite_initialized_table
from elf_literal_enrichment import enrich_program_facts_with_elf_literals


DEFAULT_REGISTRY_PATH = Path(__file__).resolve().parents[1] / "registries" / "source_patterns.v0.json"
DEFAULT_SOFTWARE_SUMMARY_PACK = (
    Path(__file__).resolve().parents[1]
    / "registries"
    / "software_source_summaries.mango.json"
)
DEFAULT_HARDWARE_PROFILE_REGISTRY = (
    Path(__file__).resolve().parents[1] / "registries" / "hardware"
)

CONTROL_WORDS = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "sizeof",
}

TYPE_WORDS = {
    "void",
    "char",
    "short",
    "int",
    "long",
    "float",
    "double",
    "signed",
    "unsigned",
    "const",
    "volatile",
    "static",
    "struct",
    "union",
    "enum",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "size_t",
    "bool",
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
    "frame",
    "rx",
    "ptr",
}


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


@dataclass
class SourceSummary:
    function: str
    source_buffer_param: int
    source_buffer_param_name: str
    source_kind: str
    label: str
    evidence_line: int
    evidence_expr: str
    register_class_hint: str
    origin: str
    output_bindings: tuple[dict[str, Any], ...] = ()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(errors="replace"))


def verified_elf_identity(path: Path, identity: dict[str, Any]) -> dict[str, Any]:
    """Verify profile identity predicates against immutable ELF symbols."""

    required = list(identity.get("required_symbols", []) or [])
    if not required:
        return {"status": "not_declared", "matched_symbols": []}
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.elf.sections import SymbolTableSection
    except ImportError as exc:  # pragma: no cover - environment failure
        raise SystemExit("pyelftools is required for hardware profile identity") from exc

    symbols: dict[str, list[int]] = {}
    with path.open("rb") as stream:
        elf = ELFFile(stream)
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                name = str(symbol.name or "")
                if name:
                    symbols.setdefault(name, []).append(int(symbol["st_value"]))

    matched: list[dict[str, Any]] = []
    for raw in required:
        row = {"name": raw} if isinstance(raw, str) else dict(raw or {})
        name = str(row.get("name", ""))
        if not name or name not in symbols:
            raise SystemExit(f"hardware profile identity symbol is missing: {name or '<empty>'}")
        expected = parse_hex_value(row.get("value"))
        values = sorted(set(symbols[name]))
        if expected is not None and expected not in values:
            raise SystemExit(
                f"hardware profile identity value mismatch for {name}: "
                f"expected 0x{expected:x}, observed {values}"
            )
        matched.append({
            "name": name,
            "values": [f"0x{value:x}" for value in values],
            "expected_value": f"0x{expected:x}" if expected is not None else "",
        })
    return {"status": "verified", "matched_symbols": matched}


def apply_hardware_metadata(
    program_facts: dict[str, Any], metadata: dict[str, Any], *, elf_path: Path | None
) -> None:
    schema_version = str(metadata.get("schema_version", ""))
    expected_hash = str(metadata.get("binary_sha256", ""))
    scope = str(metadata.get("scope", "binary" if expected_hash else "platform"))
    if scope == "binary" and not expected_hash:
        raise SystemExit("binary-scoped hardware metadata requires binary_sha256")
    if expected_hash and (not elf_path or not elf_path.exists()):
        raise SystemExit("binary-bound hardware metadata requires --elf")
    if expected_hash and sha256_path(elf_path) != expected_hash:
        raise SystemExit("hardware metadata binary_sha256 does not match --elf")
    source = str(metadata.get("metadata_source", ""))
    if source not in {"svd", "typed_register_map", "trusted_platform_summary"}:
        raise SystemExit("hardware metadata must declare a trusted metadata_source")
    if schema_version not in {
        "ct-mini-hardware-metadata-v1",
        "ct-mini-hardware-metadata-v2",
    }:
        raise SystemExit(f"unsupported hardware metadata schema: {schema_version}")
    identity = dict(metadata.get("binary_identity", {}) or {})
    identity_result = {"status": "not_declared", "matched_symbols": []}
    if identity:
        if not elf_path or not elf_path.exists():
            raise SystemExit("hardware profile identity requires --elf")
        identity_result = verified_elf_identity(elf_path, identity)
    program_facts["hardware_profile"] = dict(metadata)
    program_facts["hardware_profile_identity"] = identity_result
    if identity_result["status"] == "verified":
        program_facts["verified_hardware_platform_id"] = str(
            metadata.get("platform_id", "")
        )
    program_facts["register_metadata"] = list(
        metadata.get("registers", metadata.get("register_metadata", [])) or []
    )
    by_id, _, _ = facts_function_indexes(program_facts)
    for function_id, dma_metadata in dict(metadata.get("dma_functions", {}) or {}).items():
        fact = by_id.get(str(function_id))
        if not fact:
            continue
        row = dict(dma_metadata or {})
        row.setdefault("metadata_source", source)
        fact["dma_metadata"] = row


def apply_automatic_hardware_profile(
    program_facts: dict[str, Any],
    *,
    elf_path: Path,
    registry_path: Path,
    initialized_memory: device_dispatch_resolver.InitializedMemory | None = None,
) -> dict[str, Any]:
    """Select a generic profile using only identity and MMIO facts in the ELF."""

    accesses = observed_mmio_accesses(
        program_facts,
        initialized_memory=initialized_memory,
    )
    profiles = hardware_profile_matcher.load_profile_registry(registry_path)
    symbols = hardware_profile_matcher.extract_elf_identity_symbols(elf_path)
    resolution = hardware_profile_matcher.select_hardware_profile(
        profiles,
        elf_symbols=symbols,
        observed_accesses=accesses,
    )
    public_resolution = {
        **resolution,
        "profile": {},
        "registry_profile_count": len(profiles),
        "observed_mmio_access_count": len(accesses),
        "observed_mmio_addresses": sorted(
            {str(row.get("address", "")) for row in accesses if row.get("address")}
        ),
        "target_name_evidence_used": False,
        "dwarf_source_filename_evidence_used": False,
        "decompiler_comment_evidence_used": False,
    }
    program_facts["hardware_resolution"] = public_resolution
    if resolution.get("status") != "resolved":
        return public_resolution

    profile = dict(resolution.get("profile", {}) or {})
    program_facts["hardware_profile"] = profile
    program_facts["hardware_profile_identity"] = {
        "status": str(resolution.get("mode", "")),
        "selected_profile_ids": list(
            resolution.get("selected_profile_ids", []) or []
        ),
    }
    program_facts["register_metadata"] = list(
        profile.get("registers", profile.get("register_metadata", [])) or []
    )
    return public_resolution


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=False) + "\n")


def clean_expr(expr: str) -> str:
    return re.sub(r"\s+", " ", str(expr or "").strip())


def normalize_expr_for_key(expr: str) -> str:
    return re.sub(r"\s+", "", clean_expr(expr))


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def stable_id(prefix: str, *parts: Any) -> str:
    payload = "\x1f".join(str(part or "") for part in parts).encode("utf-8", "replace")
    return f"{prefix}:{hashlib.sha256(payload).hexdigest()[:20]}"


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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


def parse_function_name(signature: str) -> str:
    if "(" not in signature:
        return ""
    before = signature.split("(", 1)[0]
    names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", before)
    return names[-1] if names else ""


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
        ids = [item for item in ids if item not in TYPE_WORDS]
        if ids:
            params.append(ids[-1])
    return params


def extract_signature(lines: list[str], brace_idx: int) -> tuple[int, str, str, list[str]]:
    start = brace_idx - 1
    while start >= 0:
        stripped = lines[start].strip()
        if not stripped:
            if start < brace_idx - 1:
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


def find_calls_in_function(func: FunctionRecord, callees: set[str]) -> list[Callsite]:
    text = "".join(func.lines)
    base_line = func.start_line
    calls: list[Callsite] = []
    seen: set[tuple[str, int, str]] = set()
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in pattern.finditer(text):
        callee = match.group(1)
        if callee not in callees or callee in CONTROL_WORDS:
            continue
        if callee == func.name and line_for_offset(text, base_line, match.start()) == func.start_line:
            continue
        open_idx = text.find("(", match.start(1))
        close_idx = find_matching_paren(text, open_idx)
        if close_idx < 0:
            continue
        args = split_args(text[open_idx + 1:close_idx])
        line = line_for_offset(text, base_line, match.start())
        expr = clean_expr(text[match.start():close_idx + 1])
        key = (callee, line, expr)
        if key in seen:
            continue
        seen.add(key)
        calls.append(Callsite(callee=callee, args=args, function=func.name, line=line, expr=expr))
    return calls


def find_all_calls_in_function(func: FunctionRecord) -> list[Callsite]:
    text = "".join(func.lines)
    base_line = func.start_line
    calls: list[Callsite] = []
    seen: set[tuple[str, int, str]] = set()
    pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
    for match in pattern.finditer(text):
        callee = match.group(1)
        if callee in CONTROL_WORDS:
            continue
        if callee == func.name and line_for_offset(text, base_line, match.start()) == func.start_line:
            continue
        open_idx = text.find("(", match.start(1))
        close_idx = find_matching_paren(text, open_idx)
        if close_idx < 0:
            continue
        args = split_args(text[open_idx + 1:close_idx])
        line = line_for_offset(text, base_line, match.start())
        expr = clean_expr(text[match.start():close_idx + 1])
        key = (callee, line, expr)
        if key in seen:
            continue
        seen.add(key)
        calls.append(Callsite(callee=callee, args=args, function=func.name, line=line, expr=expr))
    return calls


def function_definition(func: FunctionRecord, max_chars: int = 7000) -> str:
    code = "".join(func.lines).rstrip()
    if len(code) <= max_chars:
        return code
    head = max_chars // 2
    tail = max_chars - head
    return code[:head].rstrip() + "\n/* ... truncated ... */\n" + code[-tail:].lstrip()


def lowered_tokens(text: str) -> set[str]:
    return {tok.lower() for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text)}


def identifiers_in_expr(expr: str) -> list[str]:
    return [
        tok for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", str(expr or ""))
        if tok not in TYPE_WORDS and tok not in CONTROL_WORDS
    ]


def is_pointer_like_expr(expr: str) -> bool:
    text = str(expr or "")
    if any(op in text for op in ("&", "*", "->", "[", "]", "+")):
        return True
    return bool(lowered_tokens(text) & POINTER_HINT_TOKENS)


def is_simple_identifier(expr: str) -> bool:
    return re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", clean_expr(expr)) is not None


def is_memory_write_lhs(expr: str) -> bool:
    text = clean_expr(expr)
    return text.startswith("*") or "[" in text


def expr_mentions(expr: str, name: str) -> bool:
    if not name:
        return False
    return re.search(rf"\b{re.escape(name)}\b", str(expr or "")) is not None


def has_buffer_token(expr: str, extra_tokens: set[str] | None = None) -> bool:
    tokens = lowered_tokens(str(expr or "").lower())
    hints = set(POINTER_HINT_TOKENS)
    if extra_tokens:
        hints.update(extra_tokens)
    return any(any(hint in token for hint in hints) for token in tokens)


def buffer_argument_score(expr: str) -> int:
    text = clean_expr(expr).lower()
    identifiers = lowered_tokens(text)
    score = 0
    strong = {"buf", "buffer", "rx", "dst", "dest", "payload", "packet", "pkt", "frame", "msg"}
    for identifier in identifiers:
        parts = set(identifier.split("_"))
        score += 3 * len(parts & strong)
        if identifier in strong:
            score += 2
        elif any(identifier.startswith(hint) or identifier.endswith(hint) for hint in strong):
            score += 3
        if identifier == "data" or identifier.endswith("_data"):
            score += 1
    if text.startswith("&") or "[" in text:
        score += 1
    if any(token in text for token in ("device", "driver_data", "config", "callback", "user_data")):
        score -= 4
    return score


def is_likely_length_argument(expr: str) -> bool:
    text = clean_expr(expr).lower()
    if re.fullmatch(r"(?:0x[0-9a-f]+|\d+)", text):
        return True
    return any(
        part in {"len", "length", "size", "count", "max", "remaining", "avail", "available"}
        or part.endswith("len")
        for identifier in lowered_tokens(text)
        for part in identifier.split("_")
    )


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


def expr_base(expr: str) -> str:
    text = clean_expr(expr)
    text = re.sub(r"^\*\s*", "", text)
    text = re.sub(
        r"^\(?\s*(?:char|byte|uchar|uint|ushort|ulong|uint8_t|uint16_t|uint32_t|"
        r"undefined1|undefined2|undefined4|undefined8|int|void|size_t)\s*\*?\s*\)?",
        "",
        text,
    ).strip()
    ids = identifiers_in_expr(text)
    for ident in ids:
        if not ident.upper().startswith("_DAT_"):
            return ident
    return ids[0] if ids else text


def resolve_buffer_base(expr: str, params: list[str], aliases: dict[str, str]) -> str:
    text = clean_expr(expr)
    for param in params:
        if expr_mentions(text, param):
            return param
    base = expr_base(text)
    seen: set[str] = set()
    while base in aliases and base not in seen:
        seen.add(base)
        base = aliases[base]
        if base in params:
            return base
    return base


def update_aliases_from_assignment(
    aliases: dict[str, str],
    *,
    lhs: str,
    rhs: str,
    params: list[str],
) -> None:
    lhs_clean = clean_expr(lhs)
    if not is_simple_identifier(lhs_clean):
        return
    # Pointer increments such as puVar = puVar + 4 keep the old base.
    if expr_mentions(rhs, lhs_clean) and lhs_clean in aliases:
        return
    resolved = resolve_buffer_base(rhs, params, aliases)
    if resolved in params or resolved in aliases.values():
        aliases[lhs_clean] = resolved


def register_class_hint(expr: str, registry: dict[str, Any]) -> str:
    text = str(expr or "")
    upper = text.upper()
    has_mmio_shape = (
        "->" in text
        or re.search(r"_DAT_[45][0-9A-F]{7}", upper) is not None
        or "*(VOLATILE" in upper
        or re.search(r"\bREGS\b", upper) is not None
        or re.search(r"\b(?:UART|USART|SPI|I2C|USB|ETH|GPIO|ADC|DMA)\b", upper) is not None
    )
    if not has_mmio_shape:
        return ""
    mmio = registry.get("mmio_data_register_to_buffer", {}) or {}
    data_names = [str(x).upper() for x in mmio.get("data_register_names", [])]
    status_names = [str(x).upper() for x in mmio.get("status_register_names", [])]
    control_names = [str(x).upper() for x in mmio.get("control_register_names", [])]
    # Avoid treating ordinary struct fields such as arg.data as peripheral
    # data registers.  The generic DATA token only counts when it appears as an
    # uppercase register-like field/member.
    filtered_data_names = [name for name in data_names if name != "DATA"]
    if ".DATA" in text or "->DATA" in text:
        filtered_data_names.append("DATA")
    if any(re.search(rf"(?:^|[^A-Z0-9_]){re.escape(name)}(?:$|[^A-Z0-9_])", upper) for name in filtered_data_names):
        return "DATA"
    if any(re.search(rf"(?:^|[^A-Z0-9_]){re.escape(name)}(?:$|[^A-Z0-9_])", upper) for name in status_names):
        return "STATUS"
    if any(re.search(rf"(?:^|[^A-Z0-9_]){re.escape(name)}(?:$|[^A-Z0-9_])", upper) for name in control_names):
        return "CONTROL"
    if re.search(r"_DAT_[45][0-9A-F]{7}", upper) is not None:
        return "UNKNOWN_MMIO"
    return ""


def source_site_key(row: dict[str, Any]) -> str:
    parts = [
        str(row.get("site_id", "")),
        str(row.get("label", "")),
        str(row.get("function", "")),
        str(row.get("plain_line", "")),
        str(row.get("callee", "")),
        normalize_expr_for_key(str(row.get("source_site", ""))),
        normalize_expr_for_key(str(row.get("source_buffer", ""))),
    ]
    return "|".join(parts)


def candidate_site_key(row: dict[str, Any]) -> str:
    parts = [
        str(row.get("site_id", "")),
        str(row.get("candidate_kind", "")),
        str(row.get("function", "")),
        str(row.get("plain_line", "")),
        str(row.get("callee", "")),
        normalize_expr_for_key(str(row.get("source_site", ""))),
        normalize_expr_for_key(str(row.get("candidate_source_buffer", ""))),
    ]
    return "|".join(parts)


def dedupe_rows(rows: list[dict[str, Any]], key_fn) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    by_key: dict[str, dict[str, Any]] = {}
    for row in rows:
        key = key_fn(row)
        row["site_key"] = key
        row["dedupe_key"] = key
        existing = by_key.get(key)
        if existing is None:
            row["duplicate_count"] = 1
            by_key[key] = row
            out.append(row)
            continue
        existing["duplicate_count"] = int(existing.get("duplicate_count", 1)) + 1
        duplicate_ids = list(existing.get("duplicate_ids", []) or [])
        duplicate_ids.append(str(row.get("id", "")))
        existing["duplicate_ids"] = [item for item in duplicate_ids if item]
    return out


def confirmed_source_row(
    *,
    source_id: str,
    detection_kind: str,
    confirmation_source: str,
    label: str,
    source_kind: str,
    function: str,
    plain_line: int,
    source_site: str,
    source_buffer: str,
    callee: str = "",
    args: list[str] | None = None,
    length_expr: str = "",
    value_expr: str = "",
    site_id: str = "",
    source_object_id: str = "",
    source_value_id: str = "",
    source_output_kind: str = "",
    source_outputs: list[dict[str, Any]] | None = None,
    proof: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    output_kind = source_output_kind or (
        "memory_object" if source_buffer else ("scalar_value" if value_expr else "event")
    )
    resolved_site_id = site_id or stable_id("textsite", function, plain_line, source_site)
    resolved_object_id = (
        source_object_id or stable_id("textobj", function, source_buffer)
        if output_kind == "memory_object" else ""
    )
    def normalize_output(raw: dict[str, Any]) -> dict[str, Any]:
        kind = str(raw.get("kind", "") or output_kind)
        expression = str(
            raw.get("expression", "")
            or source_buffer
            or value_expr
            or source_site
        )
        object_id = str(raw.get("object_id", ""))
        value_id = str(raw.get("value_id", ""))
        exact_ram_object = bool(
            re.match(
                r"^(?:obj:)?(?:global|ram):(?:2|3)[0-9a-fA-F]{7}(?::|$)",
                object_id,
            )
        )
        binding_status = str(raw.get("binding_status", "")) or (
            "exact_object"
            if kind == "memory_object" and exact_ram_object
            else "high_pcode_value_bound"
            if kind == "memory_object" and value_id
            else "exact_value"
            if kind == "scalar_value" and value_id
            else "site_only"
            if kind == "event" and resolved_site_id.startswith("site:")
            else "text_only"
        )
        role = str(raw.get("role", "")) or (
            "output_buffer"
            if kind == "memory_object"
            else "return_value"
            if kind == "scalar_value"
            else "event"
        )
        return {
            "role": role,
            "kind": kind,
            "expression": expression,
            "object_id": object_id,
            "value_id": value_id,
            "binding_status": binding_status,
        }

    default_output = {
        "kind": output_kind,
        "expression": source_buffer or value_expr or source_site,
        "object_id": resolved_object_id,
        "value_id": source_value_id,
    }
    normalized_outputs = [
        normalize_output(dict(item or {}))
        for item in (source_outputs if source_outputs is not None else [default_output])
    ]
    if not normalized_outputs:
        normalized_outputs = [normalize_output(default_output)]
    primary_output = next(
        (
            output
            for output in normalized_outputs
            if output.get("role") == "output_buffer"
        ),
        normalized_outputs[0],
    )
    output_kind = str(primary_output["kind"])
    resolved_object_id = str(primary_output["object_id"])
    source_value_id = str(primary_output["value_id"])
    binding_status = str(primary_output["binding_status"])
    exact_binding_statuses = {
        "exact_object",
        "high_pcode_value_bound",
        "exact_value",
        "exact_call_actual",
        "exact_call_return",
        "exact_descriptor_access_path",
    }
    row: dict[str, Any] = {
        "id": source_id,
        "detection_kind": detection_kind,
        "confirmation_source": confirmation_source,
        "label": label,
        "source_kind": source_kind,
        "function": function,
        "plain_line": plain_line,
        "callee": callee,
        "args": args or [],
        "source_site": source_site,
        "source_buffer": source_buffer,
        "length_expr": length_expr,
        "value_expr": value_expr,
        "site_id": resolved_site_id,
        "source_object_id": resolved_object_id,
        "source_value_id": source_value_id,
        "source_output_kind": output_kind,
        "output_binding_status": binding_status,
        # The singular fields remain the primary-output compatibility view.
        "source_output": dict(primary_output),
        "source_outputs": normalized_outputs,
        "chain_ready": any(
            str(output.get("binding_status", "")) in exact_binding_statuses
            for output in normalized_outputs
        ),
        "proof": proof or {"kind": "decompiled_c_rule", "node_binding": "text_only"},
        "taint_status": "source_semantics_confirmed",
        "vulnerability_status": "not_evaluated",
        "decision": "ACCEPT_DETERMINISTIC",
        "evidence_level": "DETERMINISTIC_SOURCE_SEMANTICS",
        "rule_id": f"SOURCE_{detection_kind.upper()}",
    }
    if extra:
        row.update(extra)
    return row


def make_candidate(
    *,
    candidate_number: int,
    candidate_kind: str,
    label_hint: str,
    source_kind_hint: str,
    function: str,
    plain_line: int,
    source_site: str,
    candidate_source_buffer: str,
    callee: str = "",
    actual_args: list[str] | None = None,
    known_facts: list[str] | None = None,
    questions: list[str] | None = None,
    function_slice: str = "",
    unresolved: list[str] | None = None,
    site_id: str = "",
    candidate_source_object_id: str = "",
    static_bindings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": f"U{candidate_number:04d}",
        "candidate_kind": candidate_kind,
        "label_hint": label_hint,
        "allowed_source_labels": [label_hint] if label_hint else [],
        "source_kind_hint": source_kind_hint,
        "function": function,
        "plain_line": plain_line,
        "callee": callee,
        "source_site": source_site,
        "candidate_source_buffer": candidate_source_buffer,
        "site_id": site_id or stable_id("textsite", function, plain_line, source_site),
        "candidate_source_object_id": candidate_source_object_id or stable_id(
            "textobj", function, candidate_source_buffer
        ),
        "static_bindings": static_bindings or {},
        "actual_args": actual_args or [],
        "known_facts": known_facts or [],
        "questions": questions or [
            "Does the provided evidence show external/peripheral input entering firmware?",
            "What is the source buffer or source value?",
            "What assumptions remain unresolved?",
        ],
        "function_slice": function_slice,
        "unresolved": unresolved or [],
        "resolution_status": "requires_llm_or_review",
    }


def source_call_return_role(callee: str, category: str = "") -> str:
    """Classify a receive-like CALL output without private API summaries."""

    lowered = callee.lower()
    if category == "read_like_call":
        return "received_length"
    if category == "receive_like_call":
        if "transceive" in lowered or "transfer" in lowered:
            return "return_value"
        if re.search(r"(?:^|_)(?:recv|recvfrom|recvmsg|receive)(?:_|$)", lowered):
            return "received_length"
        return "return_value"
    if lowered == "read" or lowered.endswith("_read"):
        return "received_length"
    if re.search(r"(?:^|_)(?:recv|recvfrom|recvmsg)(?:_|$)", lowered):
        return "received_length"
    if any(token in lowered for token in ("receive", "transceive", "transfer", "rx")):
        return "return_value"
    return ""


def pcode_call_output(
    call_op: dict[str, Any], *, role: str, callee: str
) -> dict[str, Any] | None:
    """Return a typed scalar Source output for a non-void High P-code CALL."""

    output = dict(call_op.get("output", {}) or {})
    value_id = varnode_value_id(output)
    if not output or not value_id:
        return None
    return {
        "role": role or "return_value",
        "kind": "scalar_value",
        "expression": str(output.get("high_name", "")) or f"{callee} return",
        "object_id": str(output.get("object_id", "")),
        "value_id": value_id,
        "binding_status": "exact_value",
    }


def heuristic_source_row(candidate: dict[str, Any], source_id: str) -> dict[str, Any] | None:
    """Apply generalized local admission rules to source evidence candidates."""
    kind = str(candidate.get("candidate_kind", ""))
    bindings = dict(candidate.get("static_bindings", {}) or {})
    site_status = str(bindings.get("site_binding_status", ""))
    source_buffer = str(candidate.get("candidate_source_buffer", ""))
    object_id = str(
        candidate.get("candidate_source_object_id", "")
        or bindings.get("source_actual_object_id", "")
    )
    value_id = str(
        bindings.get("source_actual_value_id", "")
        or candidate.get("candidate_source_value_id", "")
    )

    def callee_body_writes_selected_formal() -> bool:
        actual_index = bindings.get("source_actual_arg_index")
        if not isinstance(actual_index, int):
            return False
        definition = str(candidate.get("callee_definition", ""))
        if not definition:
            return False
        parsed = parse_functions(definition.splitlines(keepends=True))
        if not parsed or actual_index >= len(parsed[0].params):
            return False
        formal = parsed[0].params[actual_index]
        for line in parsed[0].lines:
            parts = assignment_parts(line)
            if not parts:
                continue
            lhs, _ = parts
            if re.search(rf"\b{re.escape(formal)}\b", lhs) and (
                "*" in lhs or "[" in lhs or "->" in lhs
            ):
                return True
        return False

    def call_return_drives_receive_length_or_success() -> bool:
        callee = str(candidate.get("callee", ""))
        function_slice = str(candidate.get("function_slice", ""))
        if not callee or not function_slice:
            return False
        assignment = re.search(
            rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*{re.escape(callee)}\s*\(",
            function_slice,
        )
        if not assignment:
            return False
        result = assignment.group(1)
        tail = function_slice[assignment.end():]
        return bool(
            re.search(rf"(?:if|while)\s*\([^)]*\b{re.escape(result)}\b", tail)
            or re.search(rf"(?:len|length|size|count)[A-Za-z0-9_]*\s*\([^;]*\b{re.escape(result)}\b", tail, re.I)
        )

    rule_id = ""
    if kind == "unknown_mmio_to_buffer_candidate":
        if site_status != "verified_high_pcode_def_use_site" or not object_id:
            return None
        rule_id = "SOURCE_UNKNOWN_MMIO_TO_RAM_DEF_USE"
    elif kind == "semantic_callsite_source_candidate":
        if site_status != "verified_direct_call_site" or not (object_id or value_id):
            return None
        facts = " ".join(str(item) for item in list(candidate.get("known_facts", []) or []))
        actual_index = bindings.get("source_actual_arg_index")
        callee_writes_bound_formal = False
        for evidence in list(candidate.get("callee_peripheral_evidence", []) or []):
            use_summary = dict(evidence.get("use_summary", {}) or {})
            if "ram_store" not in list(use_summary.get("use_classes", []) or []):
                continue
            for destination in list(evidence.get("memory_destinations", []) or []):
                if destination.get("formal_parameter_slot") == actual_index:
                    callee_writes_bound_formal = True
                    break
        body_write = callee_body_writes_selected_formal()
        return_drives_receive = call_return_drives_receive_length_or_success()
        if (
            "used after callsite" not in facts
            and not callee_writes_bound_formal
            and not body_write
            and not return_drives_receive
        ):
            return None
        rule_id = (
            "SOURCE_BODY_MMIO_TO_BOUND_CALL_ARGUMENT"
            if callee_writes_bound_formal
            else "SOURCE_BODY_WRITES_BOUND_CALL_ARGUMENT"
            if body_write
            else "SOURCE_RECEIVE_CALL_RESULT_CONTROLS_LENGTH_OR_SUCCESS"
            if return_drives_receive
            else "SOURCE_RECEIVE_LIKE_CALL_BOUND_OUTPUT"
        )
    elif kind == "complex_body_ingress_candidate":
        if not site_status.startswith("verified_high_pcode") or not object_id:
            return None
        rule_id = "SOURCE_BODY_MMIO_TO_FORMAL_BUFFER"
    elif kind == "duplex_transfer_receive_candidate":
        if site_status != "verified_high_pcode_duplex_transfer_site" or not object_id:
            return None
        rule_id = "SOURCE_DUPLEX_TRANSFER_RECEIVE_OUTPUT"
    elif kind == "callback_output_copy_candidate":
        if site_status != "verified_high_pcode_callback_output_copy" or not object_id:
            return None
        rule_id = "SOURCE_CALLBACK_TABLE_OUTPUT_COPY"
    else:
        return None

    label = str(candidate.get("label_hint", "") or "BYTE_STREAM_INGRESS")
    output_kind = "memory_object" if source_buffer or object_id else "scalar_value"
    source_outputs: list[dict[str, Any]] = [{
        "role": "output_buffer" if output_kind == "memory_object" else "return_value",
        "kind": output_kind,
        "expression": source_buffer or str(candidate.get("candidate_source_value", "")),
        "object_id": object_id,
        "value_id": value_id,
    }]
    call_output = dict(bindings.get("call_output", {}) or {})
    call_output_value_id = str(call_output.get("value_id", ""))
    if (
        kind == "semantic_callsite_source_candidate"
        and site_status == "verified_direct_call_site"
        and call_output_value_id
    ):
        source_outputs.append({
            "role": str(bindings.get("call_output_role", "")) or "return_value",
            "kind": "scalar_value",
            "expression": str(call_output.get("expression", ""))
            or f"{candidate.get('callee', '')} return",
            "object_id": str(call_output.get("object_id", "")),
            "value_id": call_output_value_id,
            "binding_status": "exact_value",
        })
    row = confirmed_source_row(
        source_id=source_id,
        detection_kind=kind,
        confirmation_source="generalized_structural_heuristic",
        label=label,
        source_kind=str(candidate.get("source_kind_hint", "")),
        function=str(candidate.get("function", "")),
        plain_line=int(candidate.get("plain_line", 0) or 0),
        source_site=str(candidate.get("source_site", "")),
        source_buffer=source_buffer,
        callee=str(candidate.get("callee", "")),
        args=list(candidate.get("actual_args", []) or []),
        site_id=str(candidate.get("site_id", "")),
        source_object_id=object_id,
        source_value_id=value_id,
        source_output_kind=output_kind,
        source_outputs=source_outputs,
        proof={
            "kind": "generalized_structural_heuristic",
            "site_binding_status": site_status,
            "static_bindings": bindings,
            "known_facts": list(candidate.get("known_facts", []) or []),
        },
        extra={
            "decision": "ACCEPT_HEURISTIC",
            "evidence_level": "HEURISTIC_STRUCTURAL",
            "rule_id": rule_id,
            "origin_candidate_id": str(candidate.get("id", "")),
            "unresolved": list(candidate.get("unresolved", []) or []),
            "taint_status": "source_endpoint_candidate",
        },
    )
    return row


def infer_direct_source_summaries(
    functions: list[FunctionRecord],
    registry: dict[str, Any],
) -> dict[str, list[SourceSummary]]:
    summaries: dict[str, list[SourceSummary]] = {}
    mmio = registry.get("mmio_data_register_to_buffer", {}) or {}
    label = str(mmio.get("label", "MMIO_READ"))
    source_kind = str(mmio.get("source_kind", "peripheral_data_register_to_buffer"))
    for func in functions:
        if not func.params:
            continue
        aliases: dict[str, str] = {}
        for offset, line in enumerate(func.lines):
            parts = assignment_parts(line)
            if not parts:
                continue
            lhs, rhs = parts
            hint = register_class_hint(rhs, registry)
            if hint == "DATA" and is_memory_write_lhs(lhs):
                resolved = resolve_buffer_base(lhs, func.params, aliases)
                if resolved in func.params:
                    parameter_slot = func.params.index(resolved)
                    summaries.setdefault(func.name, []).append(
                        SourceSummary(
                            function=func.name,
                            source_buffer_param=parameter_slot,
                            source_buffer_param_name=resolved,
                            source_kind=source_kind,
                            label=label,
                            evidence_line=func.start_line + offset,
                            evidence_expr=clean_expr(line.strip().rstrip(";")),
                            register_class_hint=hint,
                            origin="body_mmio_data_to_formal_buffer",
                            output_bindings=({
                                "role": "output_buffer",
                                "binding_kind": "formal_pointee",
                                "parameter_slot": parameter_slot,
                            },),
                        )
                    )
            update_aliases_from_assignment(aliases, lhs=lhs, rhs=rhs, params=func.params)
    return summaries


def infer_wrapper_source_summaries(
    functions: list[FunctionRecord],
    summaries: dict[str, list[SourceSummary]],
    registry: dict[str, Any],
) -> dict[str, list[SourceSummary]]:
    cfg = registry.get("body_derived_source_summaries", {}) or {}
    max_depth = int(cfg.get("max_wrapper_depth", 3))
    by_name = {func.name: func for func in functions}
    for _ in range(max_depth):
        changed = False
        known_callees = set(summaries)
        for func in functions:
            if not func.params:
                continue
            aliases: dict[str, str] = {}
            for offset, line in enumerate(func.lines):
                parts = assignment_parts(line)
                if parts:
                    update_aliases_from_assignment(aliases, lhs=parts[0], rhs=parts[1], params=func.params)
                line_func = FunctionRecord(
                    name=func.name,
                    signature=func.signature,
                    params=func.params,
                    start_line=func.start_line + offset,
                    body_start_line=func.body_start_line,
                    end_line=func.start_line + offset,
                    lines=[line],
                )
                for call in find_calls_in_function(line_func, known_callees):
                    for callee_summary in summaries.get(call.callee, []):
                        idx = callee_summary.source_buffer_param
                        if idx < 0 or idx >= len(call.args):
                            continue
                        resolved = resolve_buffer_base(call.args[idx], func.params, aliases)
                        if resolved not in func.params:
                            continue
                        parameter_slot = func.params.index(resolved)
                        new_summary = SourceSummary(
                            function=func.name,
                            source_buffer_param=parameter_slot,
                            source_buffer_param_name=resolved,
                            source_kind="wrapper_forwarded_" + callee_summary.source_kind,
                            label=callee_summary.label,
                            evidence_line=func.start_line + offset,
                            evidence_expr=clean_expr(line.strip().rstrip(";")),
                            register_class_hint=callee_summary.register_class_hint,
                            origin=f"wrapper_forwarded_source_summary:{call.callee}",
                            output_bindings=({
                                "role": "output_buffer",
                                "binding_kind": "formal_pointee",
                                "parameter_slot": parameter_slot,
                            },),
                        )
                        existing = summaries.setdefault(func.name, [])
                        key = (new_summary.source_buffer_param, new_summary.origin, new_summary.evidence_expr)
                        if key not in {
                            (s.source_buffer_param, s.origin, s.evidence_expr)
                            for s in existing
                        }:
                            existing.append(new_summary)
                            changed = True
        if not changed:
            break
    return {name: vals for name, vals in summaries.items() if name in by_name}


def build_source_summaries(
    functions: list[FunctionRecord],
    registry: dict[str, Any],
) -> dict[str, list[SourceSummary]]:
    summaries = infer_direct_source_summaries(functions, registry)
    return infer_wrapper_source_summaries(functions, summaries, registry)


def scan_body_derived_source_calls(
    functions: list[FunctionRecord],
    registry: dict[str, Any],
    summaries: dict[str, list[SourceSummary]],
    *,
    start_source_index: int,
) -> tuple[list[dict[str, Any]], int]:
    cfg = registry.get("body_derived_source_summaries", {}) or {}
    callsite_label = str(cfg.get("callsite_label", "BYTE_STREAM_INGRESS"))
    callsite_kind = str(cfg.get("callsite_source_kind", "body_derived_peripheral_stream_into_actual_buffer"))
    rows: list[dict[str, Any]] = []
    next_id = start_source_index
    for func in functions:
        for call in find_calls_in_function(func, set(summaries)):
            for summary in summaries.get(call.callee, []):
                idx = summary.source_buffer_param
                if idx < 0 or idx >= len(call.args):
                    continue
                actual = call.args[idx]
                if not actual or actual in {"0", "NULL", "(void *)0x0"}:
                    continue
                source_id = f"SO{next_id:04d}"
                next_id += 1
                rows.append(
                    confirmed_source_row(
                        source_id=source_id,
                        detection_kind="body_derived_source_callsite",
                        confirmation_source="deterministic_body_summary",
                        label=callsite_label,
                        source_kind=callsite_kind,
                        function=func.name,
                        plain_line=call.line,
                        callee=call.callee,
                        args=call.args,
                        source_site=call.expr,
                        source_buffer=actual,
                        value_expr=actual,
                        extra={
                            "callee_summary_origin": summary.origin,
                            "callee_source_buffer_param": idx,
                            "callee_source_buffer_param_name": summary.source_buffer_param_name,
                            "callee_evidence_line": summary.evidence_line,
                            "callee_evidence_expr": summary.evidence_expr,
                            "underlying_label": summary.label,
                            "register_class_hint": summary.register_class_hint,
                        },
                    )
                )
    return rows, next_id


def scan_direct_api_sources(
    functions: list[FunctionRecord],
    registry: dict[str, Any],
    *,
    start_source_index: int,
) -> tuple[list[dict[str, Any]], int]:
    specs = {
        str(item.get("callee", "")): item
        for item in list(registry.get("deterministic_api_sources", []) or [])
        if str(item.get("callee", ""))
    }
    rows: list[dict[str, Any]] = []
    next_id = start_source_index
    for func in functions:
        for call in find_calls_in_function(func, set(specs)):
            spec = specs[call.callee]
            buf_idx = spec.get("source_buffer_arg")
            if not isinstance(buf_idx, int) or buf_idx < 0 or buf_idx >= len(call.args):
                continue
            len_idx = spec.get("length_arg")
            source_buffer = call.args[buf_idx]
            length_expr = call.args[len_idx] if isinstance(len_idx, int) and 0 <= len_idx < len(call.args) else ""
            source_id = f"SO{next_id:04d}"
            next_id += 1
            rows.append(
                confirmed_source_row(
                    source_id=source_id,
                    detection_kind="direct_api_callsite",
                    confirmation_source="deterministic_api_summary",
                    label=str(spec.get("label", "BYTE_STREAM_INGRESS")),
                    source_kind=str(spec.get("source_kind", "")),
                    function=func.name,
                    plain_line=call.line,
                    callee=call.callee,
                    args=call.args,
                    source_site=call.expr,
                    source_buffer=source_buffer,
                    length_expr=length_expr,
                    extra={"source_buffer_arg": buf_idx, "length_arg": len_idx},
                )
            )
    return rows, next_id


def scan_return_api_sources(
    functions: list[FunctionRecord],
    registry: dict[str, Any],
    *,
    start_source_index: int,
) -> tuple[list[dict[str, Any]], int]:
    specs = {
        str(item.get("callee", "")): item
        for item in list(registry.get("source_return_apis", []) or [])
        if str(item.get("callee", ""))
    }
    rows: list[dict[str, Any]] = []
    next_id = start_source_index
    for func in functions:
        for call in find_calls_in_function(func, set(specs)):
            spec = specs[call.callee]
            source_buffer = ""
            source_site = call.expr
            for raw_line in func.lines:
                if call.expr not in raw_line:
                    continue
                parts = assignment_parts(raw_line)
                if parts and call.expr in parts[1]:
                    source_buffer = expr_base(parts[0])
                    source_site = clean_expr(raw_line.strip().rstrip(";"))
                    break
            if not source_buffer:
                source_buffer = call.callee + "()"
            source_id = f"SO{next_id:04d}"
            next_id += 1
            rows.append(
                confirmed_source_row(
                    source_id=source_id,
                    detection_kind="source_return_api",
                    confirmation_source="deterministic_return_api_summary",
                    label=str(spec.get("label", "BYTE_STREAM_INGRESS")),
                    source_kind=str(spec.get("source_kind", "")),
                    function=func.name,
                    plain_line=call.line,
                    callee=call.callee,
                    args=call.args,
                    source_site=source_site,
                    source_buffer=source_buffer,
                    value_expr=source_buffer,
                    extra={"return_role": str(spec.get("return_role", ""))},
                )
            )
    return rows, next_id


def scan_framework_parameter_sources(
    functions: list[FunctionRecord],
    registry: dict[str, Any],
    *,
    start_source_index: int,
) -> tuple[list[dict[str, Any]], int]:
    specs = {
        str(item.get("function", "")): item
        for item in list(registry.get("framework_parameter_sources", []) or [])
        if str(item.get("function", ""))
    }
    rows: list[dict[str, Any]] = []
    next_id = start_source_index
    for func in functions:
        spec = specs.get(func.name)
        if not spec:
            continue
        param_idx = spec.get("source_buffer_param")
        if not isinstance(param_idx, int) or param_idx < 0 or param_idx >= len(func.params):
            continue
        source_buffer = func.params[param_idx]
        source_id = f"SO{next_id:04d}"
        next_id += 1
        rows.append(
            confirmed_source_row(
                source_id=source_id,
                detection_kind="framework_parameter_summary",
                confirmation_source="curated_framework_source_summary",
                label=str(spec.get("label", "BYTE_STREAM_INGRESS")),
                source_kind=str(spec.get("source_kind", "")),
                function=func.name,
                plain_line=func.start_line,
                source_site=func.signature,
                source_buffer=source_buffer,
                args=func.params,
                extra={"source_buffer_param": param_idx},
            )
        )
    return rows, next_id


def scan_mmio_data_register_to_buffer(
    functions: list[FunctionRecord],
    registry: dict[str, Any],
    *,
    start_source_index: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int, int]:
    rows: list[dict[str, Any]] = []
    raw_observations: list[dict[str, Any]] = []
    next_id = start_source_index
    raw_count = 0
    for func in functions:
        aliases: dict[str, str] = {}
        for offset, line in enumerate(func.lines):
            parts = assignment_parts(line)
            if not parts:
                continue
            lhs, rhs = parts
            hint = register_class_hint(rhs, registry)
            if not hint:
                update_aliases_from_assignment(aliases, lhs=lhs, rhs=rhs, params=func.params)
                continue
            plain_line = func.start_line + offset
            if hint == "DATA" and is_memory_write_lhs(lhs):
                source_buffer = resolve_buffer_base(lhs, func.params, aliases)
                if not source_buffer or source_buffer == lhs:
                    source_buffer = expr_base(lhs)
                source_id = f"SO{next_id:04d}"
                next_id += 1
                rows.append(
                    confirmed_source_row(
                        source_id=source_id,
                        detection_kind="mmio_data_register_to_buffer",
                        confirmation_source="deterministic_mmio_data_register_use",
                        label=str((registry.get("mmio_data_register_to_buffer") or {}).get("label", "MMIO_READ")),
                        source_kind=str((registry.get("mmio_data_register_to_buffer") or {}).get("source_kind", "")),
                        function=func.name,
                        plain_line=plain_line,
                        source_site=clean_expr(line.strip().rstrip(";")),
                        source_buffer=source_buffer,
                        value_expr=rhs,
                        extra={
                            "register_class_hint": hint,
                            "lhs": lhs,
                            "rhs": rhs,
                        },
                    )
                )
            else:
                raw_count += 1
                raw_observations.append(
                    {
                        "id": f"R{raw_count:04d}",
                        "observation": "MMIO_READ",
                        "function": func.name,
                        "plain_line": plain_line,
                        "expr": clean_expr(line.strip().rstrip(";")),
                        "register_class_hint": hint,
                        "exported_as_source": False,
                    }
                )
            update_aliases_from_assignment(aliases, lhs=lhs, rhs=rhs, params=func.params)
    return rows, raw_observations, next_id, raw_count


def assigned_lhs_for_call(func: FunctionRecord, call: Callsite) -> str:
    for raw_line in func.lines:
        if call.expr not in raw_line:
            continue
        parts = assignment_parts(raw_line)
        if parts and call.expr in parts[1]:
            return expr_base(parts[0])
    return ""


def arg_used_after_call(func: FunctionRecord, call: Callsite, arg: str) -> bool:
    if not arg or not is_simple_identifier(expr_base(arg)):
        return False
    base = expr_base(arg)
    after = "".join(func.lines[max(0, call.line - func.start_line + 1):])
    return expr_mentions(after, base)


def source_label_hint_for_call(callee: str, registry: dict[str, Any]) -> str:
    tokens = {
        str(tok).lower()
        for tok in (registry.get("semantic_callsite_triggers", {}) or {}).get("control_state_tokens", [])
    }
    lowered = callee.lower()
    if any(tok in lowered for tok in tokens):
        return "CONTROL_STATE"
    return "BYTE_STREAM_INGRESS"


def semantic_callsite_reason(callee: str, registry: dict[str, Any]) -> str:
    lowered = callee.lower()
    if any(tok in lowered for tok in ("set_", "_set", "set", "create", "thread", "state", "submit", "available", "copy", "send", "write")):
        if not any(tok in lowered for tok in ("dataptr", "datalen", "max_payload")):
            return ""
    if any(tok in lowered for tok in ("recv", "receive", "rx", "transceive")):
        return "receive_like_call"
    if lowered == "read" or lowered.endswith("_read") or "fifo_read" in lowered or "frame_read" in lowered:
        if lowered.startswith("net_pkt_read") or lowered.startswith("read_"):
            return ""
        return "read_like_call"
    tokens = {str(x).lower() for x in (registry.get("semantic_callsite_triggers", {}) or {}).get("callee_tokens", [])}
    if any(tok in lowered for tok in tokens):
        return "source_like_name_token"
    return ""


def select_source_fact_functions(
    functions: list[FunctionRecord], registry: dict[str, Any], *, caller_depth: int = 2
) -> list[str]:
    """Select High P-code export scope without CVE/profile knowledge.

    Seeds come only from generalized MMIO/DMA/semantic syntax.  Direct callers
    are added so body-derived summaries can be instantiated.  Public expected
    Source profiles are intentionally not accepted by this API.
    """

    seeds: set[str] = set()
    calls_by_function: dict[str, set[str]] = {}
    semantic_tokens = {
        str(token).lower()
        for token in (registry.get("semantic_ingress_triggers", {}) or {}).get("function_tokens", [])
    }
    for func in functions:
        body = "".join(func.lines)
        callees = {call.callee for call in find_all_calls_in_function(func)}
        calls_by_function.setdefault(func.name, set()).update(callees)
        mmio_or_dma = any(
            register_class_hint(parts[1], registry)
            for line in func.lines
            if (parts := assignment_parts(line))
        ) or bool(re.search(r"\bDMA\b|->(?:PAR|M0AR|M1AR|NDTR|CNDTR|CPAR|CMAR)\b", body, re.I))
        semantic_context = any(token in func.name.lower() for token in semantic_tokens)
        semantic_call = any(semantic_callsite_reason(callee, registry) for callee in callees)
        # Include initializer-like code that binds a constant-named framework
        # object to storage.  This enables later CALLIND resolution; the regex
        # is only export-scope discovery and never confirms Source semantics.
        constant_named_object_binding = bool(
            re.search(
                r"=\s*[A-Za-z_]\w*\s*\([^;\n]*\"[^\"\n]+\"[^;\n]*\)",
                body,
            )
        )
        if mmio_or_dma or semantic_context or semantic_call or constant_named_object_binding:
            seeds.add(func.name)

    selected = set(seeds)
    for _ in range(max(0, caller_depth)):
        callers = {
            function_name
            for function_name, callees in calls_by_function.items()
            if callees & selected
        }
        if callers <= selected:
            break
        selected.update(callers)
    return sorted(selected)


def expand_selected_source_callees(
    functions: list[FunctionRecord], selected_functions: list[str], registry: dict[str, Any]
) -> list[str]:
    """Add statically named, Source-like direct targets to fact export scope.

    This is a corpus-completeness operation, not a Source decision rule.  A
    selected caller may delegate an input operation to an otherwise neutral-
    body function whose symbol looks like a receive API.  Exporting that exact
    target lets body-summary analysis prove (or reject) the operation from its
    implementation.  Arbitrary callees are deliberately not added: doing so
    would turn a local Source-fact export into almost a whole-program export.
    """

    calls_by_function = {
        function.name: {
            call.callee
            for call in find_all_calls_in_function(function)
            if semantic_callsite_reason(call.callee, registry)
        }
        for function in functions
    }
    selected = set(selected_functions)
    pending = list(selected)
    while pending:
        function_name = pending.pop()
        for callee in calls_by_function.get(function_name, set()):
            if callee in selected:
                continue
            selected.add(callee)
            pending.append(callee)
    return sorted(selected)


def scan_semantic_callsite_source_candidates(
    functions: list[FunctionRecord],
    registry: dict[str, Any],
    *,
    confirmed_keys: set[str],
    start_candidate_index: int,
) -> tuple[list[dict[str, Any]], int]:
    triggers = registry.get("semantic_callsite_triggers", {}) or {}
    return_tokens = {str(x).lower() for x in triggers.get("return_value_tokens", [])}
    candidates: list[dict[str, Any]] = []
    next_id = start_candidate_index
    for func in functions:
        all_calls = find_all_calls_in_function(func)
        callee_totals: dict[str, int] = {}
        for observed_call in all_calls:
            callee_totals[observed_call.callee] = callee_totals.get(observed_call.callee, 0) + 1
        callee_seen: dict[str, int] = {}
        for call in all_calls:
            call_ordinal = callee_seen.get(call.callee, 0)
            callee_seen[call.callee] = call_ordinal + 1
            lowered = call.callee.lower()
            reason = semantic_callsite_reason(call.callee, registry)
            if not reason:
                continue
            if lowered == "input" or lowered.endswith("_input"):
                # input-style functions conventionally consume an already
                # populated packet; they do not write a new Source Buffer.
                continue
            if any(tok in lowered for tok in ("init", "disable", "enable", "clock", "config_setup")):
                continue
            candidate_buffer = ""
            chosen_index = -1
            known_facts = [f"semantic callsite trigger: {reason} ({call.callee})"]
            assigned_lhs = assigned_lhs_for_call(func, call)
            if assigned_lhs and any(tok in lowered for tok in return_tokens):
                candidate_buffer = assigned_lhs
                known_facts.append(f"return value is assigned to candidate source value: {assigned_lhs}")
            if not candidate_buffer:
                scored_args = [
                    (buffer_argument_score(arg), index, arg)
                    for index, arg in enumerate(call.args)
                    if arg and not re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+|'.*'|\".*\")", arg)
                ]
                scored_args = [row for row in scored_args if row[0] >= 3]
                used_after = [row for row in scored_args if arg_used_after_call(func, call, row[2])]
                ranked = sorted(used_after or scored_args, reverse=True)
                chosen = ranked[0][2] if ranked else ""
                chosen_index = ranked[0][1] if ranked else -1
                has_length = any(
                    is_likely_length_argument(arg)
                    for index, arg in enumerate(call.args)
                    if index != chosen_index
                )
                transceive_pair = "transceive" in lowered and any(
                    buffer_argument_score(arg) >= 3 and "tx" in str(arg).lower()
                    for arg in call.args
                )
                receive_call_shape = (
                    reason in {"read_like_call", "receive_like_call"}
                    and len(call.args) >= 2
                )
                if chosen and not has_length and not transceive_pair and not receive_call_shape:
                    chosen = ""
                if chosen:
                    candidate_buffer = expr_base(chosen)
                    known_facts.append(f"buffer-like argument selected as candidate source buffer: {chosen}")
                    if used_after:
                        known_facts.append(f"candidate buffer is used after callsite: {candidate_buffer}")
            if not candidate_buffer:
                continue
            provisional_key = "|".join([
                source_label_hint_for_call(call.callee, registry),
                func.name,
                str(call.line),
                call.callee,
                normalize_expr_for_key(call.expr),
                normalize_expr_for_key(candidate_buffer),
            ])
            if provisional_key in confirmed_keys:
                continue
            candidate_row = make_candidate(
                    candidate_number=next_id,
                    candidate_kind="semantic_callsite_source_candidate",
                    label_hint=source_label_hint_for_call(call.callee, registry),
                    source_kind_hint="semantic_callsite_or_accessor_source",
                    function=func.name,
                    plain_line=call.line,
                    callee=call.callee,
                    source_site=call.expr,
                    candidate_source_buffer=candidate_buffer,
                    actual_args=call.args,
                    known_facts=known_facts,
                    function_slice=function_definition(func),
                    unresolved=["semantic_callsite_source_confirmation_required"],
                    static_bindings={
                        "source_actual_arg_index": chosen_index,
                        "binding_origin": "decompiled_call_argument_role",
                        "semantic_callsite_category": reason,
                        "callee_call_ordinal": call_ordinal,
                        "callee_call_count": callee_totals.get(call.callee, 0),
                    },
                )
            candidates.append(candidate_row)
            next_id += 1
    return candidates, next_id


def scan_semantic_source_candidates(
    functions: list[FunctionRecord],
    registry: dict[str, Any],
    *,
    confirmed_keys: set[str],
    start_candidate_index: int,
) -> tuple[list[dict[str, Any]], int]:
    triggers = registry.get("semantic_ingress_triggers", {}) or {}
    function_tokens = {str(x).lower() for x in triggers.get("function_tokens", [])}
    buffer_tokens = {str(x).lower() for x in triggers.get("buffer_tokens", [])}
    candidates: list[dict[str, Any]] = []
    next_id = start_candidate_index
    for func in functions:
        fn_lower = func.name.lower()
        token_hits = {tok for tok in function_tokens if tok in fn_lower}
        if not token_hits:
            continue
        if any(tok in fn_lower for tok in ("init", "disable", "enable", "clock", "config_setup")):
            continue
        pointer_params = [
            param for param in func.params
            if lowered_tokens(param.lower()) & (buffer_tokens | POINTER_HINT_TOKENS)
        ]
        calls = [call.callee for call in find_all_calls_in_function(func)]
        # Exact framework/sample helper names are deliberately not source proof.
        # Generic call tokens may create a candidate, but only body/data-flow
        # evidence or later adjudication can confirm it.
        generic_source_calls = [
            name for name in calls
            if semantic_callsite_reason(name, registry)
        ]
        if not generic_source_calls:
            continue
        if not pointer_params and not generic_source_calls:
            continue
        candidate_buffer = pointer_params[0] if pointer_params else ""
        source_site = func.signature
        provisional_key = "|".join([
            "BYTE_STREAM_INGRESS",
            func.name,
            str(func.start_line),
            "",
            normalize_expr_for_key(source_site),
            normalize_expr_for_key(candidate_buffer),
        ])
        if provisional_key in confirmed_keys:
            continue
        known_facts = [
            f"function name contains ingress-like token: {func.name}",
        ]
        if pointer_params:
            known_facts.append(f"buffer-like parameters: {', '.join(pointer_params[:5])}")
        if generic_source_calls:
            known_facts.append(
                "generic source-like call tokens inside function: "
                + ", ".join(sorted(set(generic_source_calls)))
            )
        candidates.append(
            make_candidate(
                candidate_number=next_id,
                candidate_kind="semantic_ingress_candidate",
                label_hint="BYTE_STREAM_INGRESS",
                source_kind_hint="semantic_ingress_function_or_param",
                function=func.name,
                plain_line=func.start_line,
                source_site=source_site,
                candidate_source_buffer=candidate_buffer,
                known_facts=known_facts,
                function_slice=function_definition(func),
                unresolved=["semantic_source_confirmation_required"],
            )
        )
        next_id += 1
    return candidates, next_id


def scan_complex_body_ingress_candidates(
    functions: list[FunctionRecord],
    registry: dict[str, Any],
    *,
    confirmed_functions: set[Any],
    start_candidate_index: int,
) -> tuple[list[dict[str, Any]], int]:
    """Find receive-like bodies whose device-read semantics need adjudication."""

    candidates: list[dict[str, Any]] = []
    next_id = start_candidate_index
    context_tokens = {"recv", "receive", "read", "rx", "transceive"}
    for func in functions:
        lowered = func.name.lower()
        if not any(token in lowered for token in context_tokens):
            continue
        aliases: dict[str, str] = {}
        evidence: list[tuple[int, str, str, str, int, str]] = []
        for offset, raw_line in enumerate(func.lines):
            parts = assignment_parts(raw_line)
            if not parts:
                continue
            lhs, rhs = parts
            if is_memory_write_lhs(lhs):
                rhs_text = clean_expr(rhs)
                unknown_device_read = bool(
                    re.search(r"\*\s*\([^)]*\)\s*\([^)]*\+\s*(?:0x)?[0-9a-f]+\)", rhs_text, re.I)
                    or re.search(r"\b_DAT_[45][0-9A-Fa-f]{7}\b", rhs_text)
                    or register_class_hint(rhs_text, registry) in {"DATA", "UNKNOWN_MMIO"}
                )
                resolved = resolve_buffer_base(lhs, func.params, aliases)
                if unknown_device_read and resolved in func.params:
                    param_index = func.params.index(resolved)
                    if (func.name, resolved) not in confirmed_functions:
                        evidence.append((
                            func.start_line + offset,
                            clean_expr(raw_line.strip().rstrip(";")),
                            lhs,
                            rhs,
                            param_index,
                            resolved,
                        ))
            update_aliases_from_assignment(aliases, lhs=lhs, rhs=rhs, params=func.params)
        for line, expression, lhs, rhs, param_index, source_buffer in evidence:
            row = make_candidate(
                candidate_number=next_id,
                candidate_kind="complex_body_ingress_candidate",
                label_hint="MMIO_READ",
                source_kind_hint="receive_like_body_writes_device_value_to_formal_buffer",
                function=func.name,
                plain_line=line,
                source_site=expression,
                candidate_source_buffer=source_buffer,
                known_facts=[
                    f"receive-like function body writes a dereferenced device value: {expression}",
                    f"the store LHS resolves to formal arg{param_index}: {source_buffer}",
                ],
                function_slice=function_definition(func),
                unresolved=["device_pointer_role_and_external_controllability_require_semantic_confirmation"],
                static_bindings={
                    "source_parameter_index": param_index,
                    "body_store_lhs": lhs,
                    "body_store_rhs": rhs,
                    "lhs_to_formal_binding": "local_alias_resolution",
                },
            )
            row["allowed_source_labels"] = ["MMIO_READ"]
            candidates.append(row)
            next_id += 1
    return candidates, next_id


PASS_THROUGH_PCODE = {
    "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "PIECE",
    "MULTIEQUAL", "INDIRECT",
}
POINTER_ARITH_PCODE = {"INT_ADD", "INT_SUB", "PTRADD", "PTRSUB"}


def parse_hex_value(value: Any) -> int | None:
    text = str(value or "").strip()
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except (TypeError, ValueError):
        return None


def is_peripheral_address(value: int | None) -> bool:
    return value is not None and 0x40000000 <= value < 0x60000000


def is_ram_address(value: int | None) -> bool:
    return value is not None and (
        0x20000000 <= value < 0x40000000
        or 0x60000000 <= value < 0xA0000000
    )


def facts_functions(program_facts: dict[str, Any] | None) -> list[dict[str, Any]]:
    return list((program_facts or {}).get("functions", []) or [])


def facts_function_indexes(
    program_facts: dict[str, Any] | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], set[str]]:
    """Index facts without silently collapsing duplicate function names."""

    by_id: dict[str, dict[str, Any]] = {}
    name_rows: dict[str, list[dict[str, Any]]] = {}
    for row in facts_functions(program_facts):
        function_id = str(row.get("function_id", ""))
        if function_id:
            by_id[function_id] = row
        name = str(row.get("name", ""))
        if name:
            name_rows.setdefault(name, []).append(row)
    unique_by_name = {name: rows[0] for name, rows in name_rows.items() if len(rows) == 1}
    ambiguous_names = {name for name, rows in name_rows.items() if len(rows) > 1}
    return by_id, unique_by_name, ambiguous_names


def varnode_value_id(node: dict[str, Any]) -> str:
    value_id = str(node.get("value_id", ""))
    if value_id:
        return value_id
    object_id = str(node.get("object_id", ""))
    def_site = str(node.get("def_site_id", ""))
    return f"legacy-value:{object_id}:{def_site}" if def_site else object_id


def pcode_indexes(
    function_fact: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    """Build exact SiteId and definition indexes for one function."""

    sites = {
        str(row.get("site_id", "")): row
        for row in list(function_fact.get("pcode_ops", []) or [])
        if str(row.get("site_id", ""))
    }
    defs: dict[str, dict[str, Any]] = {}
    for row in sites.values():
        output = row.get("output") or {}
        value_id = varnode_value_id(output)
        if value_id:
            defs[value_id] = row
    return sites, defs


def pcode_use_index(
    sites: dict[str, dict[str, Any]],
) -> dict[str, list[tuple[dict[str, Any], int]]]:
    """Index every exact ValueId use once for bounded local traversals."""

    uses: dict[str, list[tuple[dict[str, Any], int]]] = {}
    for row in sites.values():
        for input_index, item in enumerate(list(row.get("inputs", []) or [])):
            value_id = varnode_value_id(item)
            if value_id:
                uses.setdefault(value_id, []).append((row, input_index))
    return uses


def bind_source_rows_to_program_functions(
    rows: list[dict[str, Any]],
    program_facts: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Fill missing FunctionId fields from an exact, unique SiteId owner."""

    owners: dict[str, set[str]] = {}
    for function in facts_functions(program_facts):
        function_id = str(function.get("function_id", ""))
        if not function_id:
            continue
        for op in list(function.get("pcode_ops", []) or []):
            site_id = str(op.get("site_id", ""))
            if site_id:
                owners.setdefault(site_id, set()).add(function_id)

    blockers: list[dict[str, Any]] = []
    for row in rows:
        if str(row.get("function_id", "")):
            continue
        site_id = str(row.get("site_id", ""))
        if not site_id.startswith("site:"):
            continue
        candidates = sorted(owners.get(site_id, set()))
        if len(candidates) == 1:
            row["function_id"] = candidates[0]
            row["function_id_binding"] = {
                "kind": "unique_program_facts_site_owner",
                "site_id": site_id,
                "function_id": candidates[0],
            }
            continue
        reason = (
            "source_site_function_mapping_not_found"
            if not candidates
            else "source_site_function_mapping_not_unique"
        )
        blocker = {
            "kind": "source_definition_function_binding",
            "reason": reason,
            "source_id": str(row.get("id", "")),
            "site_id": site_id,
            "candidate_function_ids": candidates,
        }
        row.setdefault("analysis_blockers", []).append(dict(blocker))
        blockers.append(blocker)
    return blockers


def constant_from_varnode(
    node: dict[str, Any],
    defs: dict[str, dict[str, Any]],
    *,
    depth: int = 0,
    seen: set[str] | None = None,
    allow_address_literal: bool = False,
) -> int | None:
    if depth > 12:
        return None
    if bool(node.get("is_constant")):
        return parse_hex_value(node.get("offset"))
    if node.get("initial_memory_source") == "elf_initialized_nonwritable_segment":
        return parse_hex_value(node.get("initial_memory_value"))
    if allow_address_literal and bool(node.get("is_address")) and str(node.get("space", "")).lower() in {
        "ram", "mem", "memory"
    }:
        return parse_hex_value(node.get("offset"))
    value_id = varnode_value_id(node)
    if not value_id:
        return None
    seen = set(seen or ())
    if value_id in seen:
        return None
    seen.add(value_id)
    defining = defs.get(value_id)
    if not defining:
        return None
    mnemonic = str(defining.get("mnemonic", ""))
    inputs = list(defining.get("inputs", []) or [])
    if mnemonic == "INDIRECT" and inputs:
        # P-code INDIRECT(input, iop-reference) forwards input; the second
        # operand identifies the causing operation and is not a data value.
        return constant_from_varnode(
            inputs[0], defs, depth=depth + 1, seen=seen,
            allow_address_literal=allow_address_literal,
        )
    if mnemonic in PASS_THROUGH_PCODE and inputs:
        values = [
            constant_from_varnode(
                item, defs, depth=depth + 1, seen=seen,
                allow_address_literal=allow_address_literal,
            )
            for item in inputs
        ]
        concrete = [item for item in values if item is not None]
        return concrete[0] if concrete and all(item == concrete[0] for item in concrete) else None
    if mnemonic == "PTRADD" and len(inputs) >= 3:
        base = constant_from_varnode(inputs[0], defs, depth=depth + 1, seen=seen, allow_address_literal=allow_address_literal)
        index = constant_from_varnode(inputs[1], defs, depth=depth + 1, seen=seen, allow_address_literal=allow_address_literal)
        scale = constant_from_varnode(inputs[2], defs, depth=depth + 1, seen=seen, allow_address_literal=allow_address_literal)
        if base is None or index is None or scale is None:
            return None
        return base + index * scale
    if mnemonic in {"INT_ADD", "INT_SUB", "PTRSUB"} and len(inputs) >= 2:
        left = constant_from_varnode(inputs[0], defs, depth=depth + 1, seen=seen, allow_address_literal=allow_address_literal)
        right = constant_from_varnode(inputs[1], defs, depth=depth + 1, seen=seen, allow_address_literal=allow_address_literal)
        if left is None or right is None:
            return None
        if mnemonic == "INT_SUB":
            return left - right
        # Ghidra PTRSUB represents a pointer plus a constant subcomponent
        # offset; it is not arithmetic subtraction.
        return left + right
    return None


def dispatch_formal_constants(
    program_facts: dict[str, Any] | None,
) -> tuple[dict[str, dict[int, int]], dict[str, list[dict[str, Any]]]]:
    """Collect only unique formal constants proven by resolved dispatches."""

    values: dict[tuple[str, int], set[int]] = {}
    evidence: dict[str, list[dict[str, Any]]] = {}
    resolution = dict((program_facts or {}).get("device_dispatch_resolution", {}) or {})
    for row in list(resolution.get("resolved", []) or []):
        if str(row.get("binding_scope", "")) != "target_function":
            continue
        target_id = str((row.get("target") or {}).get("function_id", ""))
        if not target_id:
            continue
        for binding in list(row.get("target_formal_constant_bindings", []) or []):
            if str(binding.get("binding_scope", "")) != "target_function":
                continue
            slot = binding.get("target_parameter_slot")
            value = parse_hex_value(binding.get("value"))
            if not isinstance(slot, int) or value is None:
                continue
            values.setdefault((target_id, slot), set()).add(value)
            evidence.setdefault(target_id, []).append({
                "callsite": str((row.get("callsite") or {}).get("site_id", "")),
                "resolution_kind": str(row.get("resolution_kind", "")),
                "target_parameter_slot": slot,
                "value": f"0x{value:x}",
                "source": str(binding.get("source", "")),
            })
    constants: dict[str, dict[int, int]] = {}
    for (function_id, slot), candidates in values.items():
        if len(candidates) == 1:
            constants.setdefault(function_id, {})[slot] = next(iter(candidates))
    return constants, evidence


def constant_from_bound_varnode(
    node: dict[str, Any],
    defs: dict[str, dict[str, Any]],
    *,
    parameter_constants: dict[int, int],
    initialized_memory: device_dispatch_resolver.InitializedMemory | None,
    depth: int = 0,
    seen: set[str] | None = None,
) -> int | None:
    """Evaluate one High P-code value after exact formal substitution.

    Unlike the ordinary literal resolver, this evaluator may dereference
    initialized ELF memory.  It is used only when an exact device/API-table
    resolution supplied a unique constant for the relevant formal parameter.
    """

    if depth > 24:
        return None
    slot = node.get("parameter_slot")
    if not isinstance(slot, int):
        object_id = str(node.get("object_id", ""))
        if object_id.startswith("param:"):
            try:
                slot = int(object_id.rsplit(":", 1)[1])
            except ValueError:
                slot = None
    if isinstance(slot, int) and slot in parameter_constants:
        return parameter_constants[slot]
    if bool(node.get("is_constant")):
        return parse_hex_value(node.get("offset"))
    if bool(node.get("is_address")) and str(node.get("space", "")).lower() in {
        "ram", "mem", "memory"
    }:
        return parse_hex_value(node.get("offset"))
    initial = parse_hex_value(node.get("initial_memory_value"))
    if initial is not None:
        return initial
    value_id = varnode_value_id(node)
    if not value_id:
        return None
    seen = set(seen or ())
    if value_id in seen:
        return None
    seen.add(value_id)
    defining = defs.get(value_id)
    if not defining:
        return None
    mnemonic = str(defining.get("mnemonic", ""))
    inputs = [dict(item) for item in list(defining.get("inputs", []) or [])]
    if mnemonic == "INDIRECT" and inputs:
        return constant_from_bound_varnode(
            inputs[0], defs, parameter_constants=parameter_constants,
            initialized_memory=initialized_memory, depth=depth + 1, seen=seen,
        )
    if mnemonic in PASS_THROUGH_PCODE and inputs:
        values = [
            constant_from_bound_varnode(
                item, defs, parameter_constants=parameter_constants,
                initialized_memory=initialized_memory, depth=depth + 1, seen=seen,
            )
            for item in inputs
        ]
        concrete = [value for value in values if value is not None]
        return concrete[0] if concrete and all(value == concrete[0] for value in concrete) else None
    if mnemonic == "PTRADD" and len(inputs) >= 3:
        parts = [
            constant_from_bound_varnode(
                item, defs, parameter_constants=parameter_constants,
                initialized_memory=initialized_memory, depth=depth + 1, seen=seen,
            )
            for item in inputs[:3]
        ]
        if all(value is not None for value in parts):
            return int(parts[0]) + int(parts[1]) * int(parts[2])
        return None
    if mnemonic in {"INT_ADD", "INT_SUB", "PTRSUB"} and len(inputs) >= 2:
        left = constant_from_bound_varnode(
            inputs[0], defs, parameter_constants=parameter_constants,
            initialized_memory=initialized_memory, depth=depth + 1, seen=seen,
        )
        right = constant_from_bound_varnode(
            inputs[1], defs, parameter_constants=parameter_constants,
            initialized_memory=initialized_memory, depth=depth + 1, seen=seen,
        )
        if left is None or right is None:
            return None
        return left - right if mnemonic == "INT_SUB" else left + right
    if mnemonic == "LOAD" and len(inputs) >= 2 and initialized_memory is not None:
        address = constant_from_bound_varnode(
            inputs[-1], defs, parameter_constants=parameter_constants,
            initialized_memory=initialized_memory, depth=depth + 1, seen=seen,
        )
        output = dict(defining.get("output", {}) or {})
        size = int(output.get("size", initialized_memory.pointer_size) or 0)
        if address is not None and size in {1, 2, 4, 8}:
            return initialized_memory.read_uint(address, size)
    return None


def backward_parameter(
    node: dict[str, Any],
    defs: dict[str, dict[str, Any]],
    depth: int = 0,
    *,
    cache: dict[tuple[str, int], dict[str, Any] | None] | None = None,
    active: set[tuple[str, int]] | None = None,
) -> dict[str, Any] | None:
    """Resolve a pointer/value to one unique formal parameter.

    High P-code DAGs reuse the same SSA definitions at many MMIO stores.  The
    previous recursive implementation recomputed every upstream branch for
    every STORE, which became effectively exponential on large firmware
    functions.  Cache by SSA identity and remaining depth; an active set keeps
    malformed/cyclic facts conservative.
    """

    if depth > 12:
        return None
    cache = cache if cache is not None else {}
    active = active if active is not None else set()
    identity = (
        varnode_value_id(node)
        or str(node.get("object_id", ""))
        or str(node.get("address", ""))
    )
    key = (identity, depth)
    if identity and key in cache:
        return cache[key]
    if identity and key in active:
        return None
    if identity:
        active.add(key)

    result: dict[str, Any] | None
    if bool(node.get("is_parameter")) or str(node.get("object_id", "")).startswith("param:"):
        result = node
    else:
        defining = defs.get(varnode_value_id(node))
        if not defining:
            result = None
        else:
            mnemonic = str(defining.get("mnemonic", ""))
            inputs = list(defining.get("inputs", []) or [])
            if mnemonic == "LOAD" and len(inputs) >= 2:
                # The destination pointer may itself be loaded from a field
                # such as rx_buf->buf. Trace the field address back to the
                # formal container.
                result = backward_parameter(
                    inputs[1],
                    defs,
                    depth + 1,
                    cache=cache,
                    active=active,
                )
            elif mnemonic not in PASS_THROUGH_PCODE | POINTER_ARITH_PCODE:
                result = None
            else:
                concrete: list[dict[str, Any]] = []
                for item in inputs:
                    found = backward_parameter(
                        item,
                        defs,
                        depth + 1,
                        cache=cache,
                        active=active,
                    )
                    if found:
                        concrete.append(found)
                        if len(concrete) > 1:
                            break
                result = concrete[0] if len(concrete) == 1 else None

    if identity:
        active.discard(key)
        cache[key] = result
    return result


def register_evidence(function_fact: dict[str, Any], registry: dict[str, Any]) -> str:
    code = str(function_fact.get("decompiled_c", ""))
    mmio = registry.get("mmio_data_register_to_buffer", {}) or {}
    for kind, field in (
        ("STATUS", "status_register_names"),
        ("CONTROL", "control_register_names"),
        ("DATA", "data_register_names"),
    ):
        for raw_name in list(mmio.get(field, []) or []):
            name = str(raw_name)
            if not name:
                continue
            if re.search(rf"(?:->|\.)\s*{re.escape(name)}\b", code, re.IGNORECASE):
                return kind
    return "UNKNOWN_MMIO"


def structured_c_data_assignments(
    function_fact: dict[str, Any], registry: dict[str, Any]
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for raw_line in str(function_fact.get("decompiled_c", "")).splitlines():
        for fragment in raw_line.split(";"):
            statement = fragment.rsplit("{", 1)[-1].strip()
            parts = assignment_parts(statement)
            if not parts:
                continue
            lhs, rhs = parts
            if register_class_hint(rhs, registry) != "DATA" or not is_memory_write_lhs(lhs):
                continue
            rows.append({
                "expr": clean_expr(statement),
                "lhs": lhs,
                "rhs": rhs,
                "buffer": expr_base(lhs),
            })
    return rows


def forward_memory_writes(
    start: dict[str, Any],
    uses: dict[str, list[tuple[dict[str, Any], int]]],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    output = start.get("output") or {}
    work = [varnode_value_id(output)]
    seen: set[str] = set()
    stores: list[tuple[dict[str, Any], dict[str, Any]]] = []
    while work:
        value_id = work.pop()
        if not value_id or value_id in seen:
            continue
        seen.add(value_id)
        for op, input_index in uses.get(value_id, []):
            inputs = list(op.get("inputs", []) or [])
            mnemonic = str(op.get("mnemonic", ""))
            if mnemonic == "STORE" and input_index == 2 and len(inputs) >= 3:
                stores.append((op, inputs[1]))
                continue
            if mnemonic in PASS_THROUGH_PCODE | POINTER_ARITH_PCODE:
                out = op.get("output") or {}
                next_value_id = varnode_value_id(out)
                if next_value_id:
                    work.append(next_value_id)
    return stores


def compact_varnode(node: dict[str, Any] | None) -> dict[str, Any]:
    node = dict(node or {})
    return {
        "object_id": str(node.get("object_id", "")),
        "value_id": varnode_value_id(node),
        "name": str(node.get("high_name", "")),
        "space": str(node.get("space", "")),
        "offset": str(node.get("offset", "")),
        "size": int(node.get("size", 0) or 0),
        "is_constant": bool(node.get("is_constant")),
        "is_parameter": bool(node.get("is_parameter")),
        "parameter_slot": node.get("parameter_slot"),
    }


def compact_pcode_op(op: dict[str, Any], matched_inputs: list[int] | None = None) -> dict[str, Any]:
    call = dict(op.get("call", {}) or {})
    row: dict[str, Any] = {
        "site_id": str(op.get("site_id", "")),
        "instruction_address": str(op.get("instruction_address", "")),
        "op_order": int(op.get("op_order", 0) or 0),
        "mnemonic": str(op.get("mnemonic", "")),
        "matched_input_indexes": list(matched_inputs or []),
        "output": compact_varnode(op.get("output")) if op.get("output") else None,
        "inputs": [compact_varnode(item) for item in list(op.get("inputs", []) or [])],
    }
    if call:
        row["call"] = {
            "kind": str(call.get("kind", "")),
            "target_function": str(call.get("target_function", "")),
            "target_function_id": str(call.get("target_function_id", "")),
        }
    return row


def forward_value_semantic_slice(
    start: dict[str, Any],
    uses: dict[str, list[tuple[dict[str, Any], int]]],
    *,
    max_ops: int = 32,
) -> list[dict[str, Any]]:
    """Return a bounded, exact-ValueId forward slice for semantic review."""

    output = dict(start.get("output", {}) or {})
    work = [varnode_value_id(output)]
    seen_values: set[str] = set()
    seen_sites: set[str] = set()
    rows: list[dict[str, Any]] = []
    while work and len(rows) < max_ops:
        value_id = work.pop(0)
        if not value_id or value_id in seen_values:
            continue
        seen_values.add(value_id)
        for op, input_index in uses.get(value_id, []):
            matched = [input_index]
            sid = str(op.get("site_id", ""))
            if sid and sid not in seen_sites:
                rows.append(compact_pcode_op(op, matched))
                seen_sites.add(sid)
                if len(rows) >= max_ops:
                    break
            mnemonic = str(op.get("mnemonic", ""))
            if mnemonic in PASS_THROUGH_PCODE | POINTER_ARITH_PCODE | {
                "INT_ADD", "INT_MULT", "INT_AND", "INT_OR", "INT_XOR",
                "INT_LEFT", "INT_RIGHT", "INT_SRIGHT", "INT_EQUAL",
                "INT_NOTEQUAL", "INT_LESS", "INT_SLESS", "INT_LESSEQUAL",
                "INT_SLESSEQUAL", "BOOL_AND", "BOOL_OR", "BOOL_XOR",
                "BOOL_NEGATE",
            }:
                next_value = varnode_value_id(dict(op.get("output", {}) or {}))
                if next_value and next_value not in seen_values:
                    work.append(next_value)
    return sorted(rows, key=lambda row: (row["instruction_address"], row["op_order"], row["site_id"]))


def mmio_load_use_summary(
    load: dict[str, Any],
    defs: dict[str, dict[str, Any]],
    uses: dict[str, list[tuple[dict[str, Any], int]]],
) -> dict[str, Any]:
    inputs = list(load.get("inputs", []) or [])
    address = constant_from_varnode(inputs[1], defs, allow_address_literal=True) if len(inputs) >= 2 else None
    slice_rows = forward_value_semantic_slice(load, uses)
    mnemonics = [str(row.get("mnemonic", "")) for row in slice_rows]
    calls = [
        str((row.get("call") or {}).get("target_function", ""))
        for row in slice_rows if row.get("call")
    ]
    use_classes = {
        "branch" if mnemonic == "CBRANCH" else
        "ram_store" if mnemonic == "STORE" else
        "call_argument" if mnemonic in {"CALL", "CALLIND", "CALLOTHER"} else
        "pointer_or_arithmetic"
        for mnemonic in mnemonics
    }
    if any(re.search(r"mem(?:cpy|move|set)|str(?:cpy|ncpy)", name, re.I) for name in calls):
        use_classes.add("copy_or_memory_api")
    if any(re.search(r"parse|decode|packet|frame|header|input", name, re.I) for name in calls):
        use_classes.add("parser_or_protocol_api")
    return {
        "load_site_id": str(load.get("site_id", "")),
        "register_address": f"0x{address:x}" if address is not None else "",
        "value_id": varnode_value_id(dict(load.get("output", {}) or {})),
        "use_classes": sorted(use_classes),
        "called_functions": sorted({name for name in calls if name}),
        "forward_slice": slice_rows,
        "slice_truncated": len(slice_rows) >= 32,
    }


def mmio_c_statement(function_fact: dict[str, Any], address: int | None) -> str:
    if address is None:
        return ""
    address_hex = f"{address:x}"
    patterns = (
        re.compile(rf"\b0x0*{re.escape(address_hex)}\b", re.I),
        re.compile(rf"\b_?DAT_0*{re.escape(address_hex)}\b", re.I),
    )
    for line in str(function_fact.get("decompiled_c", "")).splitlines():
        if any(pattern.search(line) for pattern in patterns):
            return clean_expr(line.strip().rstrip(";"))
    return ""


def mmio_semantic_slice(
    *,
    function_fact: dict[str, Any],
    load: dict[str, Any],
    store: dict[str, Any],
    destination: dict[str, Any],
    destination_object_id: str,
    source_statement: str,
    register_address: int | None,
    register_hint: str,
    trusted_register_role: str,
    sites: dict[str, dict[str, Any]],
    defs: dict[str, dict[str, Any]],
    uses: dict[str, list[tuple[dict[str, Any], int]]],
    peer_loads: list[dict[str, Any]],
) -> dict[str, Any]:
    """Package static MMIO facts without assigning data/status semantics."""

    anchor_site = str(load.get("site_id", ""))
    peers = [
        mmio_load_use_summary(peer, defs, uses)
        for peer in peer_loads
        if str(peer.get("site_id", "")) != anchor_site
    ][:16]
    return {
        "schema_version": "ct-mini-mmio-semantic-slice-v1",
        "anchor": {
            "c_statement": source_statement,
            "function": str(function_fact.get("name", "")),
            "function_id": str(function_fact.get("function_id", "")),
            "mmio_load_site_id": anchor_site,
            "memory_store_site_id": str(store.get("site_id", "")),
            "register_address": (
                f"0x{register_address:x}" if register_address is not None else ""
            ),
            "register_class_hint": register_hint,
            "address_region": (
                "peripheral_mmio" if is_peripheral_address(register_address) else "unknown"
            ),
            "destination": {
                "expression": str(destination.get("high_name", "")),
                "object_id": destination_object_id,
                "pointer_object_id": str(destination.get("object_id", "")),
                "pointer_value_id": varnode_value_id(destination),
            },
        },
        "anchor_use": mmio_load_use_summary(load, defs, uses),
        "peer_mmio_loads": peers,
        "function_context": {
            "is_interrupt_entry": bool(function_fact.get("is_interrupt_entry")),
            "interrupt_vector_slots": list(
                function_fact.get("interrupt_vector_slots", []) or []
            ),
            "decompiled_c": str(function_fact.get("decompiled_c", "")),
        },
        "trusted_register_metadata": {
            "role": trusted_register_role,
            "available": trusted_register_role in {"DATA", "STATUS", "CONTROL"},
        },
    }


def exact_register_role(
    program_facts: dict[str, Any] | None,
    function_fact: dict[str, Any],
    address: int | None,
) -> str:
    if address is None:
        return ""
    address_text = f"0x{address:x}".lower()
    for owner in (function_fact, program_facts or {}):
        metadata = owner.get("register_metadata", {}) or {}
        if isinstance(metadata, dict):
            item = metadata.get(address_text) or metadata.get(str(address))
            if isinstance(item, str):
                return item.upper()
            if isinstance(item, dict):
                return str(item.get("role", "")).upper()
        if isinstance(metadata, list):
            for item in metadata:
                if str(item.get("address", "")).lower() == address_text:
                    return str(item.get("role", "")).upper()
    return ""


def normalize_high_pointer_type(value: Any) -> str:
    """Normalize a recovered pointer type for hardware-profile lookup."""

    text = re.sub(r"\b(?:const|volatile|restrict|struct)\b", " ", str(value or ""))
    text = text.replace("*", " ")
    return re.sub(r"\s+", " ", text).strip()


def function_parameter_type(function_fact: dict[str, Any], node: dict[str, Any]) -> str:
    raw_type = str(node.get("high_data_type", ""))
    if raw_type:
        return normalize_high_pointer_type(raw_type)
    slot = node.get("parameter_slot")
    if slot is None and str(node.get("object_id", "")).startswith("param:"):
        try:
            slot = int(str(node["object_id"]).rsplit(":", 1)[1])
        except (TypeError, ValueError):
            slot = None
    for parameter in list(function_fact.get("parameters", []) or []):
        if slot is not None and int(parameter.get("index", -1)) == int(slot):
            return normalize_high_pointer_type(parameter.get("data_type", ""))
    return ""


def mmio_load_register_query(
    load: dict[str, Any],
    defs: dict[str, dict[str, Any]],
    function_fact: dict[str, Any],
    *,
    parameter_constants: dict[int, int] | None = None,
    initialized_memory: device_dispatch_resolver.InitializedMemory | None = None,
) -> dict[str, Any]:
    """Recover address or typed-base-plus-offset facts for one High P-code LOAD."""

    inputs = list(load.get("inputs", []) or [])
    if len(inputs) < 2:
        return {}
    pointer = inputs[1]
    absolute_address = constant_from_varnode(pointer, defs, allow_address_literal=True)
    if absolute_address is None and parameter_constants:
        absolute_address = constant_from_bound_varnode(
            pointer,
            defs,
            parameter_constants=parameter_constants,
            initialized_memory=initialized_memory,
        )
    query: dict[str, Any] = {}
    # A decompiler may simplify an unresolved ``base + field_offset`` to the
    # offset alone.  Values such as 0x8 or 0xc are not absolute MMIO
    # addresses; retaining them here masks the stronger typed-base query.
    if is_peripheral_address(absolute_address):
        query["absolute_address"] = absolute_address

    defining = defs.get(varnode_value_id(pointer))
    if not defining:
        return query
    mnemonic = str(defining.get("mnemonic", ""))
    address_inputs = list(defining.get("inputs", []) or [])
    if mnemonic not in {"PTRSUB", "PTRADD", "INT_ADD"} or len(address_inputs) < 2:
        return query

    base = address_inputs[0]
    offset: int | None = None
    if mnemonic == "PTRADD" and len(address_inputs) >= 3:
        index = constant_from_varnode(address_inputs[1], defs)
        scale = constant_from_varnode(address_inputs[2], defs)
        if index is not None and scale is not None:
            offset = index * scale
    else:
        offset = constant_from_varnode(address_inputs[1], defs)
    if offset is None:
        return query

    peripheral_type = function_parameter_type(function_fact, base)
    if not peripheral_type:
        peripheral_type = normalize_high_pointer_type(base.get("high_data_type", ""))
    base_address = constant_from_varnode(base, defs, allow_address_literal=True)
    if peripheral_type:
        query["peripheral_type"] = peripheral_type
        query["constant_offset"] = offset
        if is_peripheral_address(base_address):
            query["typed_base"] = base_address
    elif is_peripheral_address(base_address):
        query["instance_base"] = base_address
        query["constant_offset"] = offset
    return query


MMIO_RESOLVER_QUERY_KEYS = {
    "absolute_address",
    "address",
    "peripheral_type",
    "typed_base",
    "constant_offset",
    "instance_base",
    "offset",
    "field_offset",
    "base_address",
}


def mmio_load_register_queries(
    load: dict[str, Any],
    defs: dict[str, dict[str, Any]],
    function_fact: dict[str, Any],
    *,
    parameter_constants: dict[int, int] | None = None,
    initialized_memory: device_dispatch_resolver.InitializedMemory | None = None,
) -> list[dict[str, Any]]:
    """Return every finite register query represented by one High P-code LOAD.

    Existing concrete and typed-base queries take precedence and remain a
    singleton.  The finite-table recognizer is consulted only when that
    compatibility path produces no query.
    """

    direct = mmio_load_register_query(
        load,
        defs,
        function_fact,
        parameter_constants=parameter_constants,
        initialized_memory=initialized_memory,
    )
    if direct:
        return [direct]

    table = finite_initialized_table.enumerate_computed_mmio_load(
        load,
        defs,
        initialized_memory,
    )
    status = str(table.get("status", ""))
    if status == "no_match":
        return []
    if status != "enumerated":
        return [{"finite_table": table}]

    addresses = [int(value) for value in list(table.get("address_candidates", []) or [])]
    return [
        {
            "absolute_address": address,
            "address_candidates": addresses,
            "finite_table_candidate_index": index,
            "finite_table": table,
        }
        for index, address in enumerate(addresses)
    ]


def resolve_mmio_register_queries(
    queries: list[dict[str, Any]],
    register_resolver: MMIORegisterResolver | None,
) -> dict[str, Any]:
    """Resolve all address alternatives without choosing one table entry."""

    finite_table = next(
        (dict(row.get("finite_table", {}) or {}) for row in queries if row.get("finite_table")),
        {},
    )
    concrete_queries = [
        {key: value for key, value in row.items() if key in MMIO_RESOLVER_QUERY_KEYS}
        for row in queries
        if any(key in row for key in MMIO_RESOLVER_QUERY_KEYS)
    ]
    resolutions = [
        register_resolver.resolve(**query)
        if register_resolver is not None
        else {
            "status": "unresolved",
            "resolved": False,
            "role": "UNKNOWN",
            "reason": "hardware_profile_unavailable",
            "address": (
                f"0x{int(query['absolute_address']):x}"
                if query.get("absolute_address") is not None
                else ""
            ),
            "query": query,
            "evidence": [],
            "candidates": [],
        }
        for query in concrete_queries
    ]
    if len(resolutions) == 1 and not finite_table:
        return resolutions[0]

    roles = [str(row.get("role", "UNKNOWN") or "UNKNOWN").upper() for row in resolutions]
    all_resolved = bool(resolutions) and all(bool(row.get("resolved")) for row in resolutions)
    all_external = bool(roles) and all(is_external_input_role(role) for role in roles)
    unique_roles = sorted(set(roles))
    if all_external:
        role = unique_roles[0] if len(unique_roles) == 1 else "EXTERNAL_INPUT_DATA"
    else:
        role = unique_roles[0] if all_resolved and len(unique_roles) == 1 else "UNKNOWN"
    if all_external:
        reason = ""
    elif not resolutions and finite_table:
        reason = str(finite_table.get("reason", "finite_table_enumeration_unresolved"))
    elif not all_resolved:
        reason = "not_all_address_candidates_have_hardware_metadata"
    else:
        reason = "address_candidates_do_not_share_external_input_role"

    addresses = sorted(
        {
            int(query["absolute_address"])
            for query in concrete_queries
            if query.get("absolute_address") is not None
        }
    )
    return {
        "status": "resolved" if all_resolved and (all_external or len(unique_roles) == 1) else "unresolved",
        "resolved": all_resolved and (all_external or len(unique_roles) == 1),
        "role": role,
        "reason": reason,
        "match_kind": "finite_initialized_table" if finite_table else "",
        "address": f"0x{addresses[0]:x}" if len(addresses) == 1 else "",
        "address_candidates": [f"0x{address:x}" for address in addresses],
        "all_candidates_external_input": all_external,
        "finite_table": finite_table,
        "candidate_resolutions": resolutions,
        "evidence": [
            evidence
            for row in resolutions
            for evidence in list(row.get("evidence", []) or [])
        ],
    }


def observed_mmio_accesses(
    program_facts: dict[str, Any],
    *,
    initialized_memory: device_dispatch_resolver.InitializedMemory | None = None,
) -> list[dict[str, Any]]:
    """Extract target-independent MMIO access facts for profile selection."""

    formal_constants, _ = dispatch_formal_constants(program_facts)
    rows: dict[tuple[str, str, str], dict[str, Any]] = {}
    for function_fact in facts_functions(program_facts):
        function_id = str(function_fact.get("function_id", ""))
        sites, defs = pcode_indexes(function_fact)
        uses = pcode_use_index(sites)
        for op in sites.values():
            mnemonic = str(op.get("mnemonic", ""))
            inputs = list(op.get("inputs", []) or [])
            if mnemonic == "LOAD" and len(inputs) >= 2:
                queries = mmio_load_register_queries(
                    op,
                    defs,
                    function_fact,
                    parameter_constants=formal_constants.get(function_id, {}),
                    initialized_memory=initialized_memory,
                )
                for query in queries:
                    address = query.get("absolute_address")
                    if not is_peripheral_address(address):
                        continue
                    use_summary = mmio_load_use_summary(op, defs, uses)
                    use_classes = set(use_summary.get("use_classes", []) or [])
                    behaviors = {"LOAD"}
                    if "branch" in use_classes:
                        behaviors.add("BIT_TEST_OR_BRANCH")
                    if "ram_store" in use_classes:
                        behaviors.add("VALUE_TO_MEMORY")
                    if "call_argument" in use_classes:
                        behaviors.add("VALUE_TO_CALL")
                    row = {
                        "address": f"0x{int(address):x}",
                        "access": "READ",
                        "behaviors": sorted(behaviors),
                        "function_id": function_id,
                        "site_id": str(op.get("site_id", "")),
                    }
                    if query.get("finite_table"):
                        row["address_recovery"] = "finite_initialized_table"
                    rows[(row["address"], row["access"], row["site_id"])] = row
                continue
            if mnemonic != "STORE" or len(inputs) < 3:
                continue
            address = constant_from_varnode(
                inputs[1], defs, allow_address_literal=True
            )
            if not is_peripheral_address(address):
                continue
            stored = dict(inputs[2] or {})
            stored_constant = constant_from_varnode(
                stored, defs, allow_address_literal=True
            )
            behaviors = {"STORE"}
            if is_ram_address(stored_constant):
                behaviors.add("RAM_POINTER_STORE")
            elif is_peripheral_address(stored_constant):
                behaviors.add("PERIPHERAL_POINTER_STORE")
            elif stored_constant is not None:
                behaviors.add("CONSTANT_STORE")
            elif "*" in str(stored.get("high_data_type", "")) or bool(
                stored.get("is_address")
            ):
                behaviors.add("POINTER_STORE")
            else:
                behaviors.add("VALUE_STORE")
            row = {
                "address": f"0x{int(address):x}",
                "access": "WRITE",
                "behaviors": sorted(behaviors),
                "function_id": function_id,
                "site_id": str(op.get("site_id", "")),
                "stored_value_id": varnode_value_id(stored),
                "stored_constant": (
                    f"0x{stored_constant:x}" if stored_constant is not None else ""
                ),
            }
            rows[(row["address"], row["access"], row["site_id"])] = row
    return sorted(
        rows.values(),
        key=lambda row: (
            str(row.get("address", "")),
            str(row.get("function_id", "")),
            str(row.get("site_id", "")),
        ),
    )


def hardware_profile_mmio_address(profile: dict[str, Any], address: int | None) -> bool:
    if address is None:
        return False
    ranges = list(profile.get("mmio_ranges", []) or [])
    if not ranges:
        return is_peripheral_address(address)
    for row in ranges:
        start = parse_hex_value(row.get("start"))
        end = parse_hex_value(row.get("end"))
        if start is not None and end is not None and start <= address <= end:
            return True
    return False


def profile_dma_groups(
    register_resolver: MMIORegisterResolver | None,
    descriptor_stores: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Group MMIO stores by a profile-proved peripheral/DMA instance.

    The grouping is independent of function or register names. Each role is
    resolved from the automatically selected hardware profile, and stores are
    joined only when that profile assigns them to the same peripheral instance
    (or the same instance base when no instance name is available).
    """

    if register_resolver is None:
        return []
    groups: dict[str, dict[str, Any]] = {}
    for store in descriptor_stores:
        address = parse_hex_value(store.get("register_address"))
        if address is None:
            continue
        resolution = register_resolver.resolve(absolute_address=address)
        if not bool(resolution.get("resolved")):
            continue
        candidates = list(resolution.get("candidates", []) or [])
        primary = dict(candidates[0] or {}) if candidates else {}
        instance = str(
            resolution.get("peripheral_instance", "")
            or primary.get("peripheral_instance", "")
        )
        instance_base = str(primary.get("instance_base", ""))
        group_id = (
            f"instance:{instance}"
            if instance
            else f"base:{instance_base}"
            if instance_base
            else ""
        )
        if not group_id:
            continue
        group = groups.setdefault(
            group_id,
            {
                "descriptor_id": group_id,
                "peripheral_instance": instance,
                "instance_base": instance_base,
                "stores": [],
            },
        )
        group["stores"].append(
            {
                **store,
                "register_role": str(resolution.get("role", "")),
                "register_resolution": resolution,
            }
        )
    return list(groups.values())


def legacy_trusted_dma_groups(
    function_fact: dict[str, Any], descriptor_stores: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Compatibility path for an explicitly supplied debug metadata overlay."""

    metadata = dict(function_fact.get("dma_metadata", {}) or {})
    if metadata.get("metadata_source") not in {
        "svd", "typed_register_map", "trusted_platform_summary"
    }:
        return []
    by_address = {
        str(row.get("address", "")).lower(): row
        for row in list(metadata.get("register_roles", []) or [])
        if str(row.get("address", "")) and str(row.get("descriptor_id", ""))
    }
    groups: dict[str, dict[str, Any]] = {}
    for store in descriptor_stores:
        role = by_address.get(str(store.get("register_address", "")).lower())
        if not role:
            continue
        descriptor_id = str(role["descriptor_id"])
        group = groups.setdefault(descriptor_id, {
            "descriptor_id": descriptor_id,
            "direction": str(role.get("direction", metadata.get("direction", ""))),
            "stores": [],
        })
        group["stores"].append({**store, "register_role": str(role.get("role", ""))})
    return list(groups.values())


def is_writable_actual(
    node: dict[str, Any], defs: dict[str, dict[str, Any]] | None = None
) -> bool:
    if not node or bool(node.get("is_constant")):
        return False
    object_id = str(node.get("object_id", ""))
    if not object_id or object_id.startswith("const:"):
        return False
    value = parse_hex_value(node.get("offset"))
    if bool(node.get("is_address")) and value == 0:
        return False
    if defs is not None and constant_from_varnode(node, defs) == 0:
        return False
    return True


def abstract_memory_object_id(
    pointer: dict[str, Any],
    *,
    parameter: dict[str, Any] | None = None,
    concrete_address: int | None = None,
) -> str:
    if is_ram_address(concrete_address):
        return f"global:{int(concrete_address):08x}:unknown"
    bound = parameter or pointer
    object_id = str(bound.get("object_id", ""))
    if object_id.startswith(("param:", "global:", "stack:")):
        return object_id
    value_id = varnode_value_id(pointer)
    return f"pointee:{value_id}" if value_id else ""


def canonical_formal_parameter(
    function_fact: dict[str, Any],
    inferred_parameter: dict[str, Any] | None,
    formal_access: tuple[int, tuple[int, ...]] | None,
) -> dict[str, Any] | None:
    """Prefer the exact formal root recovered from the destination access path."""

    if formal_access is None:
        return inferred_parameter
    slot = int(formal_access[0])
    parameter = next(
        (
            dict(row or {})
            for row in list(function_fact.get("parameters", []) or [])
            if int(dict(row or {}).get("index", -1)) == slot
        ),
        {},
    )
    inferred_slot = (
        inferred_parameter.get("parameter_slot")
        if inferred_parameter is not None
        else None
    )
    if not parameter and inferred_slot == slot:
        return inferred_parameter
    function_id = str(function_fact.get("function_id", ""))
    address = function_id.removeprefix("fn:")
    return {
        **parameter,
        "is_parameter": True,
        "parameter_slot": slot,
        "index": slot,
        "high_name": str(parameter.get("name", "")),
        "object_id": str(parameter.get("object_id", ""))
        or (f"param:{address}:{slot}" if address else ""),
    }


def memory_destination_group_key(
    pointer: dict[str, Any],
    *,
    parameter: dict[str, Any] | None = None,
    concrete_address: int | None = None,
) -> str:
    """Group flows that target the same logical C-level destination."""

    if parameter:
        return str(parameter.get("object_id", ""))
    if is_ram_address(concrete_address):
        return f"global:{int(concrete_address):08x}"
    high_name = str(pointer.get("high_name", "")).strip().lower()
    if high_name and high_name != "unnamed":
        return f"high:{high_name}"
    return str(pointer.get("object_id", ""))


def structured_mmio_and_dma_scan(
    program_facts: dict[str, Any] | None,
    registry: dict[str, Any],
    *,
    start_source_index: int,
    start_candidate_index: int,
    initialized_memory: device_dispatch_resolver.InitializedMemory | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], int, int]:
    confirmed: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    raw: list[dict[str, Any]] = []
    next_source = start_source_index
    next_candidate = start_candidate_index
    _, unique_by_name, _ = facts_function_indexes(program_facts)
    structured_summaries: dict[str, list[dict[str, Any]]] = {}
    hardware_profile = dict((program_facts or {}).get("hardware_profile", {}) or {})
    if not hardware_profile and (program_facts or {}).get("register_metadata"):
        hardware_profile = {
            "schema_version": "inline-register-metadata",
            "metadata_source": "typed_register_map",
            "register_metadata": list((program_facts or {}).get("register_metadata", []) or []),
        }
    register_resolver = (
        MMIORegisterResolver(
            hardware_profile,
            platform_id=str(
                (program_facts or {}).get("verified_hardware_platform_id", "")
            ) or None,
            binary_sha256=str((program_facts or {}).get("binary_sha256", "")) or None,
        )
        if hardware_profile else None
    )
    formal_constants, formal_constant_evidence = dispatch_formal_constants(program_facts)

    for function_fact in facts_functions(program_facts):
        function_name = str(function_fact.get("name", ""))
        function_id = str(function_fact.get("function_id", ""))
        sites, defs = pcode_indexes(function_fact)
        uses = pcode_use_index(sites)
        parameter_cache: dict[tuple[str, int], dict[str, Any] | None] = {}
        register_hint = register_evidence(function_fact, registry)
        c_data_assignments = structured_c_data_assignments(function_fact, registry)
        mmio_loads: list[dict[str, Any]] = []
        load_queries: dict[str, list[dict[str, Any]]] = {}
        load_resolutions: dict[str, dict[str, Any]] = {}
        descriptor_stores: list[dict[str, Any]] = []

        for op in sites.values():
            mnemonic = str(op.get("mnemonic", ""))
            inputs = list(op.get("inputs", []) or [])
            if mnemonic == "LOAD" and len(inputs) >= 2:
                queries = mmio_load_register_queries(
                    op,
                    defs,
                    function_fact,
                    parameter_constants=formal_constants.get(function_id, {}),
                    initialized_memory=initialized_memory,
                )
                resolution = resolve_mmio_register_queries(
                    queries,
                    register_resolver,
                )
                addresses = [
                    row.get("absolute_address")
                    for row in queries
                    if is_peripheral_address(row.get("absolute_address"))
                ]
                finite_table = dict(resolution.get("finite_table", {}) or {})
                if (
                    bool(resolution.get("resolved"))
                    or any(
                        hardware_profile_mmio_address(hardware_profile, address)
                        for address in addresses
                    )
                    or (not hardware_profile and bool(addresses))
                    or str(finite_table.get("status", "")) in {"enumerated", "unresolved"}
                ):
                    mmio_loads.append(op)
                    site = str(op.get("site_id", ""))
                    load_queries[site] = queries
                    load_resolutions[site] = resolution
            if mnemonic == "STORE" and len(inputs) >= 3:
                descriptor_address = constant_from_varnode(inputs[1], defs, allow_address_literal=True)
                if is_peripheral_address(descriptor_address):
                    stored_node = dict(inputs[2] or {})
                    stored_parameter = backward_parameter(
                        stored_node,
                        defs,
                        cache=parameter_cache,
                    )
                    stored_formal_access = software_source_engine.formal_access_path(
                        stored_node, defs
                    )
                    stored_parameter = canonical_formal_parameter(
                        function_fact,
                        stored_parameter,
                        stored_formal_access,
                    )
                    stored_value = constant_from_varnode(
                        stored_node, defs, allow_address_literal=True
                    )
                    descriptor_stores.append({
                        "site_id": op.get("site_id"),
                        "register_address": f"0x{descriptor_address:x}",
                        "stored_value_object_id": stored_node.get("object_id"),
                        "stored_value_id": varnode_value_id(stored_node),
                        "stored_value": stored_value,
                        "stored_value_name": stored_node.get("high_name", ""),
                        "stored_value_node": stored_node,
                        "stored_value_parameter": stored_parameter,
                        "stored_value_formal_access": (
                            {
                                "parameter_slot": stored_formal_access[0],
                                "access_path": list(stored_formal_access[1]),
                            }
                            if stored_formal_access is not None else None
                        ),
                        "stored_value_memory_object_id": abstract_memory_object_id(
                            stored_node,
                            parameter=stored_parameter,
                            concrete_address=stored_value,
                        ),
                    })

        write_target_counts: dict[str, int] = {}
        for candidate_load in mmio_loads:
            for _, candidate_destination in forward_memory_writes(candidate_load, uses):
                candidate_address = constant_from_varnode(
                    candidate_destination, defs, allow_address_literal=True
                )
                candidate_parameter = backward_parameter(
                    candidate_destination,
                    defs,
                    cache=parameter_cache,
                )
                target_key = memory_destination_group_key(
                    candidate_destination,
                    parameter=candidate_parameter,
                    concrete_address=candidate_address,
                )
                if target_key:
                    write_target_counts[target_key] = write_target_counts.get(target_key, 0) + 1

        for load in mmio_loads:
            load_site = str(load.get("site_id", ""))
            queries = load_queries.get(load_site, [])
            resolution = load_resolutions.get(load_site, {})
            addresses = sorted({
                int(row["absolute_address"])
                for row in queries
                if is_peripheral_address(row.get("absolute_address"))
            })
            address = addresses[0] if addresses else None
            resolved_address = parse_hex_value(resolution.get("address"))
            register_address = address if address is not None else resolved_address
            register_addresses = [f"0x{value:x}" for value in addresses]
            finite_table = dict(resolution.get("finite_table", {}) or {})
            if str(finite_table.get("status", "")) == "unresolved":
                raw.append({
                    "observation": "COMPUTED_MMIO_READ",
                    "function": function_name,
                    "function_id": function_id,
                    "site_id": load_site,
                    "register_addresses": [],
                    "finite_table": finite_table,
                    "exported_as_source": False,
                    "reason": str(
                        finite_table.get("reason", "finite_table_enumeration_unresolved")
                    ),
                })
                continue
            resolved_role = str(resolution.get("role", "UNKNOWN") or "UNKNOWN").upper()
            writes = forward_memory_writes(load, uses)
            use_summary = mmio_load_use_summary(load, defs, uses)
            if resolved_role in {"STATUS", "CONTROL", "TX_DATA"}:
                raw.append({
                    "observation": "MMIO_READ",
                    "function": function_name,
                    "site_id": load_site,
                    "register_address": (
                        f"0x{register_address:x}" if register_address is not None else ""
                    ),
                    "register_addresses": register_addresses,
                    "register_role": resolved_role,
                    "register_resolution": resolution,
                    "dispatch_formal_constant_evidence": formal_constant_evidence.get(
                        function_id, []
                    ),
                    "exported_as_source": False,
                    "reason": f"hardware_profile_role_{resolved_role.lower()}",
                })
                continue
            if not writes:
                load_value = dict(load.get("output", {}) or {})
                value_id = varnode_value_id(load_value)
                forward_slice = list(use_summary.get("forward_slice", []) or [])
                if is_external_input_role(resolved_role) and value_id and forward_slice:
                    source_id = f"SO{next_source:04d}"
                    next_source += 1
                    is_isr = bool(function_fact.get("is_interrupt_entry"))
                    proof = {
                        "kind": "high_pcode_mmio_value_def_use",
                        "site_binding_status": "verified_high_pcode_def_use_site",
                        "mmio_load_site_id": load_site,
                        "mmio_load_value_id": value_id,
                        "register_address": (
                            f"0x{register_address:x}" if register_address is not None else ""
                        ),
                        "register_addresses": register_addresses,
                        "address_recovery": (
                            "finite_initialized_table"
                            if finite_table else "direct_or_typed_base"
                        ),
                        "finite_table": finite_table,
                        "register_resolution": resolution,
                        "use_summary": use_summary,
                        "dispatch_formal_constant_evidence": formal_constant_evidence.get(
                            function_id, []
                        ),
                    }
                    source_statement = (
                        mmio_c_statement(function_fact, address)
                        or f"MMIO {resolved_role} LOAD -> scalar value"
                    )
                    confirmed.append(confirmed_source_row(
                        source_id=source_id,
                        detection_kind="high_pcode_mmio_data_to_value",
                        confirmation_source="deterministic_hardware_profile_high_pcode_def_use",
                        label="ISR_MMIO_READ" if is_isr else "MMIO_READ",
                        source_kind="peripheral_data_register_to_value",
                        function=function_name,
                        plain_line=0,
                        source_site=source_statement,
                        source_buffer="",
                        value_expr=str(load_value.get("high_name", "")) or value_id,
                        site_id=load_site,
                        source_value_id=value_id,
                        source_output_kind="scalar_value",
                        proof=proof,
                        extra={"function_id": function_id},
                    ))
                    continue
                raw.append({
                    "observation": "MMIO_READ",
                    "function": function_name,
                    "site_id": load_site,
                    "register_address": (
                        f"0x{register_address:x}" if register_address is not None else ""
                    ),
                    "register_addresses": register_addresses,
                    "register_class_hint": register_hint,
                    "register_role": resolved_role,
                    "register_resolution": resolution,
                    "dispatch_formal_constant_evidence": formal_constant_evidence.get(
                        function_id, []
                    ),
                    "exported_as_source": False,
                    "reason": "no relevant def-use from MMIO load",
                })
                continue
            for store, destination in writes:
                destination_address = constant_from_varnode(
                    destination, defs, allow_address_literal=True
                )
                destination_parameter = backward_parameter(
                    destination,
                    defs,
                    cache=parameter_cache,
                )
                destination_formal_access = software_source_engine.formal_access_path(
                    destination, defs
                )
                destination_parameter = canonical_formal_parameter(
                    function_fact,
                    destination_parameter,
                    destination_formal_access,
                )
                destination_pointer_name = str(destination.get("high_name", ""))
                buffer_name = destination_pointer_name
                if destination_parameter:
                    buffer_name = str(destination_parameter.get("high_name", "")) or buffer_name
                if not buffer_name:
                    buffer_name = (
                        f"RAM@0x{destination_address:x}"
                        if is_ram_address(destination_address)
                        else str(destination.get("object_id", ""))
                    )
                matching_assignments = [
                    row for row in c_data_assignments
                    if (buffer_name or destination_pointer_name)
                    and (
                        row["buffer"] == buffer_name
                        or expr_mentions(row["lhs"], buffer_name)
                        or expr_mentions(buffer_name, row["buffer"])
                        or (
                            destination_pointer_name
                            and (
                                row["buffer"] == destination_pointer_name
                                or expr_mentions(row["lhs"], destination_pointer_name)
                            )
                        )
                    )
                ]
                object_identity = abstract_memory_object_id(
                    destination,
                    parameter=destination_parameter,
                    concrete_address=destination_address,
                )
                destination_group = memory_destination_group_key(
                    destination,
                    parameter=destination_parameter,
                    concrete_address=destination_address,
                )
                exact_c_binding = bool(
                    matching_assignments and write_target_counts.get(destination_group, 0) == 1
                )
                proof = {
                    "kind": "high_pcode_def_use",
                    "site_binding_status": "verified_high_pcode_def_use_site",
                    "mmio_load_site_id": load.get("site_id"),
                    "mmio_load_value_id": varnode_value_id(dict(load.get("output", {}) or {})),
                    "memory_store_site_id": store.get("site_id"),
                    "register_address": (
                        f"0x{register_address:x}" if register_address is not None else ""
                    ),
                    "register_addresses": register_addresses,
                    "address_recovery": (
                        "finite_initialized_table"
                        if finite_table else "direct_or_typed_base"
                    ),
                    "finite_table": finite_table,
                    "register_role": resolved_role,
                    "register_resolution": resolution,
                    "register_class_hint": resolved_role if resolution.get("resolved") else (
                        "DATA" if exact_c_binding else "UNKNOWN_MMIO"
                    ),
                    "destination_pointer_object_id": destination.get("object_id", ""),
                    "destination_pointer_value_id": varnode_value_id(destination),
                    "destination_object_id": object_identity,
                    "source_buffer_binding_kind": (
                        "formal_or_formal_field_container"
                        if destination_parameter else "resolved_memory_or_pointer"
                    ),
                    "source_buffer_formal_access": (
                        {
                            "parameter_slot": destination_formal_access[0],
                            "access_path": list(destination_formal_access[1]),
                        }
                        if destination_formal_access is not None else None
                    ),
                }
                # Decompiled names remain hints. Deterministic admission needs
                # an RX/input role from trusted hardware metadata.
                deterministic_data_role = is_external_input_role(resolved_role)
                heuristic_data_role = bool(exact_c_binding)
                source_statement = (
                    matching_assignments[0]["expr"]
                    if matching_assignments
                    else mmio_c_statement(function_fact, address)
                    or (
                        f"MMIO LOAD {', '.join(register_addresses)} -> memory STORE"
                        if register_addresses
                        else "computed MMIO LOAD -> memory STORE"
                    )
                )
                if deterministic_data_role:
                    source_id = f"SO{next_source:04d}"
                    next_source += 1
                    is_isr = bool(function_fact.get("is_interrupt_entry"))
                    confirmed.append(confirmed_source_row(
                        source_id=source_id,
                        detection_kind="high_pcode_mmio_data_to_buffer",
                        confirmation_source="deterministic_hardware_profile_high_pcode_def_use",
                        label="ISR_MMIO_READ" if is_isr else "MMIO_READ",
                        source_kind="peripheral_data_register_to_buffer",
                        function=function_name,
                        plain_line=0,
                        source_site=source_statement,
                        source_buffer=buffer_name,
                        value_expr=str((load.get("output") or {}).get("object_id", "")),
                        site_id=str(load.get("site_id", "")),
                        source_object_id=object_identity,
                        source_value_id=varnode_value_id(dict(load.get("output", {}) or {})),
                        proof=proof,
                        extra={"function_id": function_id},
                    ))
                    if destination_parameter and destination_parameter.get("parameter_slot") is not None:
                        summary_key = function_id or (
                            f"name:{function_name}" if function_name in unique_by_name else ""
                        )
                        if summary_key:
                            structured_summaries.setdefault(summary_key, []).append({
                                "parameter_slot": int(destination_parameter["parameter_slot"]),
                                "output_bindings": [{
                                    "role": "output_buffer",
                                    "binding_kind": "formal_pointee",
                                    "parameter_slot": int(destination_parameter["parameter_slot"]),
                                }],
                                "source_row": confirmed[-1],
                            })
                else:
                    candidate = make_candidate(
                        candidate_number=next_candidate,
                        candidate_kind="unknown_mmio_to_buffer_candidate",
                        label_hint="ISR_MMIO_READ" if function_fact.get("is_interrupt_entry") else "MMIO_READ",
                        source_kind_hint="unknown_mmio_register_to_memory",
                        function=function_name,
                        plain_line=0,
                        source_site=source_statement,
                        candidate_source_buffer=buffer_name,
                        known_facts=[
                            "High P-code proves the loaded MMIO value reaches this memory store.",
                            *(
                                [
                                    "An immutable initialized ELF object provides a finite set of MMIO address candidates."
                                ]
                                if finite_table else []
                            ),
                            (
                                "Decompiler field/use evidence suggests a DATA register, but trusted hardware metadata is absent."
                                if heuristic_data_role
                                else "Register data/status/control semantics are not statically proven."
                            ),
                        ],
                        function_slice=str(function_fact.get("decompiled_c", "")),
                        unresolved=["mmio_register_role_requires_semantic_or_metadata_confirmation"],
                        site_id=str(load.get("site_id", "")),
                        candidate_source_object_id=object_identity,
                        static_bindings=proof,
                    )
                    candidate["function_id"] = function_id
                    candidate["candidate_source_nodes"] = [{
                        "id": "mmio_destination",
                        "kind": "memory_object",
                        "expression": buffer_name,
                        "object_id": object_identity,
                        "value_id": varnode_value_id(destination),
                        "binding_status": "verified_high_pcode_def_use_site",
                    }]
                    candidate["semantic_slice"] = mmio_semantic_slice(
                        function_fact=function_fact,
                        load=load,
                        store=store,
                        destination=destination,
                        destination_object_id=object_identity,
                        source_statement=source_statement,
                        register_address=register_address,
                        register_hint=resolved_role if resolution.get("resolved") else register_hint,
                        trusted_register_role=resolved_role if resolution.get("resolved") else "",
                        sites=sites,
                        defs=defs,
                        uses=uses,
                        peer_loads=mmio_loads,
                    )
                    candidates.append(candidate)
                    next_candidate += 1

        if descriptor_stores:
            groups = profile_dma_groups(register_resolver, descriptor_stores)
            groups.extend(legacy_trusted_dma_groups(function_fact, descriptor_stores))
            if not groups:
                exact_ram_values = [
                    row
                    for row in descriptor_stores
                    if is_ram_address(row.get("stored_value"))
                ]
                exact_peripheral_values = [
                    row
                    for row in descriptor_stores
                    if is_peripheral_address(row.get("stored_value"))
                ]
                if exact_ram_values and exact_peripheral_values:
                    destination = exact_ram_values[0]
                    candidate = make_candidate(
                        candidate_number=next_candidate,
                        candidate_kind="dma_descriptor_candidate",
                        label_hint="DMA_BACKED_BUFFER",
                        source_kind_hint="unresolved_dma_descriptor",
                        function=function_name,
                        plain_line=0,
                        source_site=(
                            "High P-code stores peripheral and RAM addresses "
                            "into MMIO registers"
                        ),
                        candidate_source_buffer=(
                            str(destination.get("stored_value_name", ""))
                            or f"RAM@0x{int(destination['stored_value']):x}"
                        ),
                        known_facts=[
                            "High P-code proves exact peripheral and RAM pointer stores.",
                            "No selected hardware profile proves register roles or transfer direction.",
                        ],
                        function_slice=str(function_fact.get("decompiled_c", "")),
                        unresolved=[
                            "dma_register_roles_and_transfer_direction_unresolved"
                        ],
                        site_id=str(destination.get("site_id", "")),
                        candidate_source_object_id=str(
                            destination.get("stored_value_memory_object_id", "")
                        ),
                        static_bindings={
                            "site_binding_status": "verified_high_pcode_mmio_stores",
                            "direction_proven": False,
                            "destination_store_site_id": str(
                                destination.get("site_id", "")
                            ),
                            "destination_object_id": str(
                                destination.get(
                                    "stored_value_memory_object_id", ""
                                )
                            ),
                            "peripheral_value_store_site_ids": [
                                str(row.get("site_id", ""))
                                for row in exact_peripheral_values
                            ],
                        },
                    )
                    candidate["function_id"] = function_id
                    candidates.append(candidate)
                    next_candidate += 1
            for group in groups:
                stores = list(group.get("stores", []) or [])
                roles = {
                    str(row.get("register_role", "")).upper()
                    for row in stores
                }
                dedicated_rx_buffers = [
                    row for row in stores
                    if str(row.get("register_role", "")).upper()
                    == "DMA_RX_BUFFER_POINTER"
                ]
                shared_buffers = [
                    row for row in stores
                    if str(row.get("register_role", "")).upper()
                    == "DMA_BUFFER_POINTER"
                ]
                memory_destinations = [
                    row for row in stores
                    if str(row.get("register_role", "")).upper()
                    in {"DMA_MEMORY_DESTINATION", "MEMORY_DESTINATION"}
                ]
                peripheral_sources = [
                    row for row in stores
                    if str(row.get("register_role", "")).upper()
                    in {"DMA_PERIPHERAL_SOURCE", "PERIPHERAL_ADDRESS"}
                    and is_peripheral_address(row.get("stored_value"))
                ]
                rx_started = "RX_START" in roles

                destination_candidates: list[dict[str, Any]] = []
                proof_kind = ""
                if len(dedicated_rx_buffers) == 1:
                    destination_candidates = dedicated_rx_buffers
                    proof_kind = "dedicated_rx_buffer_pointer"
                elif len(shared_buffers) == 1 and rx_started:
                    destination_candidates = shared_buffers
                    proof_kind = "shared_packet_pointer_plus_rx_start"
                elif (
                    len(memory_destinations) == 1
                    and len(peripheral_sources) == 1
                ):
                    destination_candidates = memory_destinations
                    proof_kind = "peripheral_source_and_memory_destination_descriptor"
                elif (
                    str(group.get("direction", "")).lower()
                    == "peripheral_to_memory"
                    and len(memory_destinations) == 1
                ):
                    # Explicit debug metadata retains its old compatibility
                    # behavior but remains outside the canonical pipeline.
                    destination_candidates = memory_destinations
                    proof_kind = "manual_overlay_peripheral_to_memory"
                if len(destination_candidates) != 1:
                    continue

                destination = destination_candidates[0]
                stored_value = destination.get("stored_value")
                object_id = str(
                    destination.get("stored_value_memory_object_id", "")
                )
                value_id = str(destination.get("stored_value_id", ""))
                source_buffer = str(destination.get("stored_value_name", ""))
                if is_ram_address(stored_value):
                    object_id = f"global:{int(stored_value):08x}:unknown"
                    source_buffer = source_buffer or f"RAM@0x{int(stored_value):x}"
                if not object_id or not value_id:
                    raw.append(
                        {
                            "observation": "DMA_RX_CONFIGURATION",
                            "function": function_name,
                            "site_id": str(destination.get("site_id", "")),
                            "exported_as_source": False,
                            "reason": "dma_destination_object_or_value_unresolved",
                            "descriptor_id": str(group.get("descriptor_id", "")),
                            "proof_kind": proof_kind,
                        }
                    )
                    continue

                binding = {
                    "kind": "high_pcode_profile_dma_binding",
                    "site_binding_status": "verified_high_pcode_dma_register_stores",
                    "descriptor_id": str(group.get("descriptor_id", "")),
                    "peripheral_instance": str(
                        group.get("peripheral_instance", "")
                    ),
                    "instance_base": str(group.get("instance_base", "")),
                    "proof_kind": proof_kind,
                    "same_function_proven": True,
                    "same_profile_instance_proven": True,
                    "destination_store_site_id": str(
                        destination.get("site_id", "")
                    ),
                    "destination_register_address": str(
                        destination.get("register_address", "")
                    ),
                    "destination_object_id": object_id,
                    "destination_value_id": value_id,
                    "rx_start_site_ids": [
                        str(row.get("site_id", ""))
                        for row in stores
                        if str(row.get("register_role", "")).upper()
                        == "RX_START"
                    ],
                    "peripheral_source_site_ids": [
                        str(row.get("site_id", ""))
                        for row in peripheral_sources
                    ],
                    "register_store_evidence": [
                        {
                            "site_id": str(row.get("site_id", "")),
                            "register_address": str(
                                row.get("register_address", "")
                            ),
                            "register_role": str(
                                row.get("register_role", "")
                            ),
                            "stored_value_id": str(
                                row.get("stored_value_id", "")
                            ),
                            "stored_value": (
                                f"0x{int(row['stored_value']):x}"
                                if row.get("stored_value") is not None
                                else ""
                            ),
                        }
                        for row in stores
                    ],
                }
                confirmed.append(
                    confirmed_source_row(
                        source_id=f"SO{next_source:04d}",
                        detection_kind="high_pcode_dma_register_binding",
                        confirmation_source=(
                            "manual_debug_hardware_overlay"
                            if proof_kind == "manual_overlay_peripheral_to_memory"
                            else "deterministic_hardware_profile_high_pcode_dma_binding"
                        ),
                        label="DMA_BACKED_BUFFER",
                        source_kind="peripheral_to_memory_dma",
                        function=function_name,
                        plain_line=0,
                        source_site=(
                            "profile-proved peripheral RX writes the bound RAM buffer"
                        ),
                        source_buffer=source_buffer,
                        site_id=str(destination.get("site_id", "")),
                        source_object_id=object_id,
                        source_value_id=value_id,
                        proof=binding,
                        extra={"function_id": function_id},
                    )
                )
                next_source += 1

    # Propagate body-proved summaries through direct wrappers. A wrapper earns
    # a summary only when High P-code maps the callee output actual back to one
    # of the wrapper's own formal parameters.
    max_wrapper_depth = int(
        (registry.get("body_derived_source_summaries", {}) or {}).get("max_wrapper_depth", 3)
    )
    for _ in range(max_wrapper_depth):
        changed = False
        for function_fact in facts_functions(program_facts):
            function_name = str(function_fact.get("name", ""))
            function_id = str(function_fact.get("function_id", ""))
            caller_key = function_id or (
                f"name:{function_name}" if function_name in unique_by_name else ""
            )
            if not caller_key:
                continue
            _, defs = pcode_indexes(function_fact)
            parameter_cache: dict[tuple[str, int], dict[str, Any] | None] = {}
            for op in list(function_fact.get("pcode_ops", []) or []):
                call = op.get("call") or {}
                callee = str(call.get("target_function", ""))
                target_function_id = str(call.get("target_function_id", ""))
                callee_key = target_function_id or (
                    f"name:{callee}" if callee in unique_by_name else ""
                )
                if not callee_key or callee_key not in structured_summaries:
                    continue
                inputs = list(op.get("inputs", []) or [])
                for summary in list(structured_summaries[callee_key]):
                    callee_bindings = list(summary.get("output_bindings", []) or [{
                        "role": "output_buffer",
                        "binding_kind": "formal_pointee",
                        "parameter_slot": int(summary["parameter_slot"]),
                    }])
                    propagated_bindings: list[dict[str, Any]] = []
                    for binding in callee_bindings:
                        if binding.get("binding_kind") != "formal_pointee":
                            continue
                        arg_index = 1 + int(binding["parameter_slot"])
                        if arg_index >= len(inputs) or not is_writable_actual(inputs[arg_index], defs):
                            continue
                        caller_parameter = backward_parameter(
                            inputs[arg_index],
                            defs,
                            cache=parameter_cache,
                        )
                        if not caller_parameter or caller_parameter.get("parameter_slot") is None:
                            continue
                        propagated_bindings.append({
                            "role": str(binding.get("role", "")) or "output_buffer",
                            "binding_kind": "formal_pointee",
                            "parameter_slot": int(caller_parameter["parameter_slot"]),
                        })
                    if not propagated_bindings:
                        continue
                    propagated = {
                        "parameter_slot": int(propagated_bindings[0]["parameter_slot"]),
                        "output_bindings": propagated_bindings,
                        "source_row": summary["source_row"],
                        "via_call_site_id": str(op.get("site_id", "")),
                        "via_callee_function_id": target_function_id,
                    }
                    existing_keys = {
                        (
                            int(row["parameter_slot"]),
                            str(row["source_row"].get("site_id", "")),
                        )
                        for row in structured_summaries.setdefault(caller_key, [])
                    }
                    key = (
                        propagated["parameter_slot"],
                        str(propagated["source_row"].get("site_id", "")),
                    )
                    if key not in existing_keys:
                        structured_summaries[caller_key].append(propagated)
                        changed = True
        if not changed:
            break

    # Instantiate body-proved source summaries at direct High P-code calls.
    for function_fact in facts_functions(program_facts):
        function_name = str(function_fact.get("name", ""))
        caller_function_id = str(function_fact.get("function_id", ""))
        _, caller_defs = pcode_indexes(function_fact)
        caller_parameter_cache: dict[
            tuple[str, int], dict[str, Any] | None
        ] = {}
        for op in list(function_fact.get("pcode_ops", []) or []):
            call = op.get("call") or {}
            callee = str(call.get("target_function", ""))
            target_function_id = str(call.get("target_function_id", ""))
            summary_key = target_function_id
            if not summary_key and callee in unique_by_name:
                summary_key = f"name:{callee}"
            if not summary_key or summary_key not in structured_summaries:
                continue
            inputs = list(op.get("inputs", []) or [])
            for summary in structured_summaries[summary_key]:
                summary_bindings = list(summary.get("output_bindings", []) or [{
                    "role": "output_buffer",
                    "binding_kind": "formal_pointee",
                    "parameter_slot": int(summary["parameter_slot"]),
                }])
                source_outputs: list[dict[str, Any]] = []
                resolved_actuals: list[tuple[dict[str, Any], str, int]] = []
                for binding in summary_bindings:
                    if binding.get("binding_kind") != "formal_pointee":
                        continue
                    parameter_slot = int(binding["parameter_slot"])
                    arg_index = 1 + parameter_slot
                    if arg_index >= len(inputs):
                        continue
                    actual = inputs[arg_index]
                    if not is_writable_actual(actual, caller_defs):
                        continue
                    actual_parameter = (
                        actual
                        if bool(actual.get("is_parameter"))
                        else backward_parameter(
                            actual,
                            caller_defs,
                            cache=caller_parameter_cache,
                        )
                    )
                    actual_object_id = abstract_memory_object_id(
                        actual, parameter=actual_parameter
                    )
                    actual_value_id = varnode_value_id(actual)
                    source_outputs.append({
                        "role": str(binding.get("role", "")) or "output_buffer",
                        "kind": "memory_object",
                        "expression": str(
                            actual.get("high_name") or actual.get("object_id", "")
                        ),
                        "object_id": actual_object_id,
                        "value_id": actual_value_id,
                    })
                    resolved_actuals.append((actual, actual_object_id, parameter_slot))
                if not resolved_actuals:
                    continue
                return_role = source_call_return_role(
                    callee, semantic_callsite_reason(callee, registry)
                )
                return_output = pcode_call_output(
                    op, role=return_role, callee=callee
                ) if return_role else None
                if return_output:
                    source_outputs.append(return_output)
                actual, actual_object_id, primary_parameter_slot = resolved_actuals[0]
                actual_value_id = varnode_value_id(actual)
                call_args = [
                    str(item.get("high_name") or item.get("object_id"))
                    for item in inputs[1:]
                ]
                confirmed.append(confirmed_source_row(
                    source_id=f"SO{next_source:04d}",
                    detection_kind="high_pcode_body_summary_callsite",
                    confirmation_source="deterministic_high_pcode_summary_instantiation",
                    label="BYTE_STREAM_INGRESS",
                    source_kind="body_proved_peripheral_stream_into_actual_buffer",
                    function=function_name,
                    plain_line=0,
                    callee=callee,
                    args=call_args,
                    source_site=f"direct CALL {callee}({', '.join(call_args)})",
                    source_buffer=str(actual.get("high_name") or actual.get("object_id", "")),
                    site_id=str(op.get("site_id", "")),
                    source_object_id=actual_object_id,
                    source_value_id=actual_value_id,
                    source_outputs=source_outputs,
                    proof={
                        "kind": "high_pcode_function_summary",
                        "call_site_id": op.get("site_id"),
                        "callee": callee,
                        "callee_function_id": target_function_id,
                        "callee_parameter_slot": primary_parameter_slot,
                        "callee_output_bindings": summary_bindings,
                        "actual_object_id": actual_object_id,
                        "actual_value_id": actual_value_id,
                        "underlying_source_site_id": summary["source_row"].get("site_id", ""),
                    },
                    extra={"function_id": caller_function_id},
                ))
                next_source += 1

    return confirmed, candidates, raw, next_source, next_candidate


def _is_pointer_type(value: Any) -> bool:
    return "*" in str(value or "")


def _is_scalar_size_type(value: Any) -> bool:
    text = str(value or "").lower()
    return "*" not in text and any(
        token in text
        for token in (
            "char", "short", "int", "long", "size_t",
            "uint8", "uint16", "uint32", "uint64",
        )
    )


def _constant_node(node: dict[str, Any]) -> int | None:
    return (
        parse_hex_value(node.get("offset"))
        if bool(node.get("is_constant"))
        else None
    )


def _pointee_object_id(node: dict[str, Any]) -> str:
    value_id = varnode_value_id(node)
    return f"pointee:{value_id}" if value_id else abstract_memory_object_id(node)


def scan_duplex_transfer_receive_candidates(
    program_facts: dict[str, Any] | None,
    *,
    start_candidate_index: int,
) -> tuple[list[dict[str, Any]], int]:
    """Find an RX output from a typed duplex-transfer call shape.

    The rule is deliberately name-independent.  It requires two adjacent
    pointer/length pairs in the resolved callee signature.  At one callsite,
    one pair must be exactly ``NULL, 0`` while the other pair carries a
    non-constant pointer and a non-zero, non-constant extent.  The latter is a
    possible receive output.  This admits a heuristic Source because the call
    shape proves an output direction but not the platform's external-input
    threat model.
    """

    if not program_facts:
        return [], start_candidate_index
    index = software_source_engine.ProgramIndex(program_facts)
    rows: list[dict[str, Any]] = []
    next_candidate = start_candidate_index
    for caller, op in index.calls:
        if str(op.get("mnemonic", "")) != "CALL":
            continue
        target = index.resolve_call_target(caller, op)
        if not target:
            continue
        parameters = sorted(
            [dict(row or {}) for row in list(target.get("parameters", []) or [])],
            key=lambda row: int(row.get("index", -1)),
        )
        actuals = index.call_actuals(caller, op)
        if len(parameters) != len(actuals):
            continue
        pair_slots: list[tuple[int, int]] = []
        for index_in_signature in range(len(parameters) - 1):
            pointer_parameter = parameters[index_in_signature]
            length_parameter = parameters[index_in_signature + 1]
            if (
                int(pointer_parameter.get("index", -1)) == index_in_signature
                and int(length_parameter.get("index", -1)) == index_in_signature + 1
                and _is_pointer_type(pointer_parameter.get("data_type"))
                and _is_scalar_size_type(length_parameter.get("data_type"))
            ):
                pair_slots.append((index_in_signature, index_in_signature + 1))
        # This heuristic models the common asynchronous duplex contract:
        #   context, tx_buffer, tx_length, rx_buffer, rx_length, callback, ...
        # Requiring a trailing callback-like pointer excludes unrelated
        # five-argument diagnostics that happen to contain two pointer/scalar
        # pairs.  Pair order is part of this heuristic contract: the first
        # pair is transmit and the second pair is receive.
        if len(pair_slots) < 2:
            continue
        first_pair, second_pair = pair_slots[:2]
        trailing_index = second_pair[1] + 1
        if (
            trailing_index >= len(parameters)
            or not _is_pointer_type(parameters[trailing_index].get("data_type"))
        ):
            continue

        disabled_pairs: list[tuple[int, int]] = []
        active_pairs: list[tuple[int, int]] = []
        for pointer_slot, length_slot in pair_slots:
            pointer_constant = _constant_node(actuals[pointer_slot])
            length_constant = _constant_node(actuals[length_slot])
            if pointer_constant == 0 and length_constant == 0:
                disabled_pairs.append((pointer_slot, length_slot))
            elif (
                pointer_constant is None
                and length_constant != 0
                and not bool(actuals[length_slot].get("is_constant"))
            ):
                active_pairs.append((pointer_slot, length_slot))
        if (
            disabled_pairs != [first_pair]
            or active_pairs != [second_pair]
        ):
            continue

        pointer_slot, length_slot = active_pairs[0]
        pointer = dict(actuals[pointer_slot])
        length = dict(actuals[length_slot])
        source_buffer = str(pointer.get("high_name", "")) or str(
            pointer.get("object_id", "")
        )
        if not source_buffer:
            continue
        object_id = _pointee_object_id(pointer)
        value_id = varnode_value_id(pointer)
        site_id = str(op.get("site_id", ""))
        target_name = str(target.get("name", ""))
        candidate = make_candidate(
            candidate_number=next_candidate,
            candidate_kind="duplex_transfer_receive_candidate",
            label_hint="BYTE_STREAM_INGRESS",
            source_kind_hint="duplex_transfer_receive_output",
            function=str(caller.get("name", "")),
            plain_line=0,
            callee=target_name,
            source_site=(
                f"CALL {target_name} "
                f"[receive_buffer={source_buffer}, "
                f"receive_length={str(length.get('high_name', '')) or str(length.get('object_id', ''))}]"
            ),
            candidate_source_buffer=source_buffer,
            actual_args=[
                str(node.get("high_name", "")) or str(node.get("object_id", ""))
                for node in actuals
            ],
            known_facts=[
                "Resolved callee signature contains two pointer/length pairs.",
                (
                    "At this callsite one pair is exactly NULL/0 and the other "
                    "pair carries the receive buffer and a variable extent."
                ),
                "High P-code binds the receive buffer to one exact call actual.",
            ],
            function_slice=str(caller.get("decompiled_c", "")),
            unresolved=["external_input_role_is_structural_not_platform_proven"],
            site_id=site_id,
            candidate_source_object_id=object_id,
            static_bindings={
                "site_binding_status": "verified_high_pcode_duplex_transfer_site",
                "call_site_id": site_id,
                "callee_function_id": str(target.get("function_id", "")),
                "source_actual_arg_index": pointer_slot,
                "source_actual_object_id": object_id,
                "source_actual_value_id": value_id,
                "length_actual_arg_index": length_slot,
                "length_actual_object_id": str(length.get("object_id", "")),
                "length_actual_value_id": varnode_value_id(length),
                "disabled_pair_slots": list(disabled_pairs[0]),
                "active_pair_slots": [pointer_slot, length_slot],
            },
        )
        candidate["function_id"] = str(caller.get("function_id", ""))
        rows.append(candidate)
        next_candidate += 1
    return rows, next_candidate


def _object_extent_containing(
    memory: device_dispatch_resolver.InitializedMemory,
    address: int,
) -> dict[str, Any] | None:
    matches = [
        extent
        for extent in memory.symbol_extents("STT_OBJECT")
        if memory.extent_contains(extent, address)
    ]
    return matches[0] if len(matches) == 1 else None


def scan_callback_output_copy_candidates(
    program_facts: dict[str, Any] | None,
    initialized_memory: device_dispatch_resolver.InitializedMemory | None,
    *,
    start_candidate_index: int,
) -> tuple[list[dict[str, Any]], int]:
    """Find callback-table functions that copy a static frame into a formal.

    This models a common driver boundary without naming a framework API.  The
    function must be referenced from one exact ELF object, copy from a static
    writable object into a pointer formal, and return a value derived from the
    same copy extent on at least one path.
    """

    if not program_facts or initialized_memory is None:
        return [], start_candidate_index
    index = software_source_engine.ProgramIndex(program_facts)
    rows: list[dict[str, Any]] = []
    next_candidate = start_candidate_index
    primitive_names = {"memcpy", "memmove", "__aeabi_memcpy", "__aeabi_memmove"}
    writable_objects = initialized_memory.symbol_extents("STT_OBJECT")

    for function in index.functions:
        function_id = str(function.get("function_id", ""))
        entry = parse_hex_value(function.get("entry"))
        if not function_id or entry is None:
            continue
        references = device_dispatch_resolver.function_pointer_references(
            initialized_memory, entry
        )
        table_bindings = [
            {
                "reference": reference,
                "object": extent,
            }
            for reference in references
            for extent in writable_objects
            if initialized_memory.extent_contains(
                extent,
                int(reference["address"]),
                initialized_memory.pointer_size,
            )
        ]
        if len(table_bindings) != 1:
            continue

        definitions = index.definitions_by_function.get(function_id, {})
        for caller, op in index.calls:
            if str(caller.get("function_id", "")) != function_id:
                continue
            target = index.resolve_call_target(caller, op)
            if not target or str(target.get("name", "")) not in primitive_names:
                continue
            actuals = index.call_actuals(caller, op)
            if len(actuals) < 3:
                continue
            destination = dict(actuals[0])
            source = dict(actuals[1])
            extent_node = dict(actuals[2])
            destination_access = software_source_engine.formal_access_path(
                destination, definitions
            )
            if destination_access is None:
                continue
            destination_slot, destination_path = destination_access
            if destination_path:
                continue
            source_address = constant_from_varnode(source, definitions)
            source_extent = (
                _object_extent_containing(initialized_memory, source_address)
                if source_address is not None
                else None
            )
            if not source_extent or not bool(source_extent.get("writable")):
                continue
            extent_value_id = varnode_value_id(extent_node)
            if not extent_value_id:
                continue
            return_sites = []
            for return_op in index.returns_by_function.get(function_id, []):
                returned = [
                    dict(node)
                    for node in list(return_op.get("inputs", []) or [])[1:]
                ]
                if any(
                    software_source_engine.depends_on_value(
                        node, extent_value_id, definitions
                    )
                    for node in returned
                ):
                    return_sites.append(str(return_op.get("site_id", "")))
            if not return_sites:
                continue

            parameter = next(
                (
                    dict(row)
                    for row in list(function.get("parameters", []) or [])
                    if int(row.get("index", -1)) == destination_slot
                ),
                {},
            )
            source_buffer = str(parameter.get("name", "")) or str(
                destination.get("high_name", "")
            )
            pointer_value_id = varnode_value_id(destination)
            object_id = (
                f"pointee:{pointer_value_id}"
                if pointer_value_id
                else str(parameter.get("object_id", ""))
            )
            site_id = str(op.get("site_id", ""))
            target_name = str(target.get("name", ""))
            source_name = ",".join(source_extent.get("names", []) or []) or (
                f"RAM@0x{int(source_extent['address']):x}"
            )
            candidate = make_candidate(
                candidate_number=next_candidate,
                candidate_kind="callback_output_copy_candidate",
                label_hint="BYTE_STREAM_INGRESS",
                source_kind_hint="callback_table_static_frame_to_output_buffer",
                function=str(function.get("name", "")),
                plain_line=0,
                callee=target_name,
                source_site=(
                    f"CALL {target_name} "
                    f"[output_buffer={source_buffer}, frame_object={source_name}]"
                ),
                candidate_source_buffer=source_buffer,
                actual_args=[
                    str(node.get("high_name", "")) or str(node.get("object_id", ""))
                    for node in actuals
                ],
                known_facts=[
                    "The function address occurs in one exact initialized ELF object.",
                    "High P-code binds the copy destination to a pointer formal.",
                    "The copy source belongs to one exact static writable object.",
                    "At least one return value depends on the copy extent.",
                ],
                function_slice=str(function.get("decompiled_c", "")),
                unresolved=["external_writer_of_static_frame_object_is_not_proven"],
                site_id=site_id,
                candidate_source_object_id=object_id,
                static_bindings={
                    "site_binding_status": "verified_high_pcode_callback_output_copy",
                    "call_site_id": site_id,
                    "callee_function_id": str(target.get("function_id", "")),
                    "source_actual_arg_index": 0,
                    "source_actual_object_id": object_id,
                    "source_actual_value_id": pointer_value_id,
                    "output_parameter_slot": destination_slot,
                    "copy_source_address": f"0x{source_address:x}",
                    "copy_source_object": source_extent,
                    "copy_extent_value_id": extent_value_id,
                    "return_site_ids": return_sites,
                    "callback_table_binding": table_bindings[0],
                },
            )
            candidate["function_id"] = function_id
            rows.append(candidate)
            next_candidate += 1
    return rows, next_candidate


def enrich_candidates_with_program_facts(
    candidates: list[dict[str, Any]], program_facts: dict[str, Any] | None
) -> list[dict[str, Any]]:
    if not program_facts:
        return candidates
    by_id, by_name, ambiguous_names = facts_function_indexes(program_facts)
    callers: dict[str, list[dict[str, str]]] = {}
    for fact in facts_functions(program_facts):
        function_name = str(fact.get("name", ""))
        function_id = str(fact.get("function_id", ""))
        for op in list(fact.get("pcode_ops", []) or []):
            call = op.get("call") or {}
            target = str(call.get("target_function", ""))
            target_id = str(call.get("target_function_id", ""))
            caller_key = target_id or (f"name:{target}" if target and target not in ambiguous_names else "")
            if caller_key:
                callers.setdefault(caller_key, []).append({
                    "function": function_name,
                    "function_id": function_id,
                    "site_id": str(op.get("site_id", "")),
                })

    for candidate in candidates:
        function_name = str(candidate.get("function", ""))
        candidate_function_id = str(candidate.get("function_id", ""))
        fact = by_id.get(candidate_function_id) if candidate_function_id else by_name.get(function_name)
        if not fact:
            continue
        candidate["function_id"] = str(fact.get("function_id", ""))
        caller_key = candidate["function_id"] or f"name:{function_name}"
        candidate["caller_context"] = callers.get(caller_key, [])[:32]
        if isinstance(candidate.get("semantic_slice"), dict):
            candidate["semantic_slice"]["caller_context"] = candidate["caller_context"][:1]
        candidate["unresolved_indirect_calls"] = [
            {
                "site_id": str(op.get("site_id", "")),
                "argument_object_ids": list((op.get("call") or {}).get("argument_object_ids", []) or []),
            }
            for op in list(fact.get("pcode_ops", []) or [])
            if str((op.get("call") or {}).get("kind", "")) == "CALLIND"
        ][:32]
        callee = str(candidate.get("callee", ""))
        callee_function_id = str(candidate.get("callee_function_id", ""))
        callee_fact = by_id.get(callee_function_id) if callee_function_id else by_name.get(callee)
        if callee_fact:
            candidate["callee_definition"] = str(callee_fact.get("decompiled_c", ""))
            candidate["callee_function_id"] = str(callee_fact.get("function_id", ""))
            callee_sites, callee_defs = pcode_indexes(callee_fact)
            callee_uses = pcode_use_index(callee_sites)
            peripheral_flows: list[dict[str, Any]] = []
            for callee_op in callee_sites.values():
                callee_inputs = list(callee_op.get("inputs", []) or [])
                if str(callee_op.get("mnemonic", "")) != "LOAD" or len(callee_inputs) < 2:
                    continue
                peripheral_address = constant_from_varnode(
                    callee_inputs[1], callee_defs, allow_address_literal=True
                )
                if not is_peripheral_address(peripheral_address):
                    continue
                stores = forward_memory_writes(callee_op, callee_uses)
                peripheral_flows.append({
                    "load_site_id": str(callee_op.get("site_id", "")),
                    "register_address": f"0x{peripheral_address:x}",
                    "use_summary": mmio_load_use_summary(callee_op, callee_defs, callee_uses),
                    "memory_destinations": [
                        {
                            "store_site_id": str(store.get("site_id", "")),
                            "object_id": abstract_memory_object_id(
                                destination,
                                parameter=backward_parameter(destination, callee_defs),
                                concrete_address=constant_from_varnode(
                                    destination, callee_defs, allow_address_literal=True
                                ),
                            ),
                            "formal_parameter_slot": (
                                backward_parameter(destination, callee_defs) or {}
                            ).get("parameter_slot"),
                        }
                        for store, destination in stores
                    ],
                })
            candidate["callee_peripheral_evidence"] = peripheral_flows[:16]

        matched_calls = []
        if callee:
            for op in list(fact.get("pcode_ops", []) or []):
                call = op.get("call") or {}
                if callee_fact and str(call.get("target_function_id", "")):
                    if str(call.get("target_function_id", "")) == str(callee_fact.get("function_id", "")):
                        matched_calls.append(op)
                elif callee not in ambiguous_names and str(call.get("target_function", "")) == callee:
                    matched_calls.append(op)
        call_op: dict[str, Any] | None = matched_calls[0] if len(matched_calls) == 1 else None
        candidate_bindings = candidate.get("static_bindings", {}) or {}
        source_arg_index = int(candidate_bindings.get("source_actual_arg_index", -1))
        call_ordinal = int(candidate_bindings.get("callee_call_ordinal", -1))
        corpus_call_count = int(candidate_bindings.get("callee_call_count", -1))
        if (
            call_op is None
            and corpus_call_count == len(matched_calls)
            and 0 <= call_ordinal < len(matched_calls)
        ):
            call_op = matched_calls[call_ordinal]
        if call_op is None and matched_calls and source_arg_index >= 0:
            actual_args = list(candidate.get("actual_args", []) or [])
            expected_actual = (
                expr_base(str(actual_args[source_arg_index]))
                if source_arg_index < len(actual_args) else ""
            )
            exact_calls: list[dict[str, Any]] = []
            for possible in matched_calls:
                inputs = list(possible.get("inputs", []) or [])[1:]
                if source_arg_index >= len(inputs):
                    continue
                node = inputs[source_arg_index]
                name = str(node.get("high_name", "")).lower()
                if expected_actual and (
                    name == expected_actual.lower()
                    or expr_mentions(name, expected_actual)
                    or expr_mentions(expected_actual, name)
                ):
                    exact_calls.append(possible)
            # Without C-token-to-P-code source mapping, repeated calls with
            # the same actual remain ambiguous and must not be hard-bound.
            if len(exact_calls) == 1:
                call_op = exact_calls[0]

        if call_op is not None:
            candidate["site_id"] = str(call_op.get("site_id", ""))
            static_bindings = candidate.setdefault("static_bindings", {})
            static_bindings.update({
                "call_site_id": call_op.get("site_id", ""),
                "callee_function_id": str((callee_fact or {}).get("function_id", "")),
                "actual_formal_binding_status": "direct_call",
            })
            static_bindings.setdefault(
                "site_binding_status", "verified_direct_call_site"
            )
            return_role = source_call_return_role(
                callee,
                str(candidate["static_bindings"].get("semantic_callsite_category", "")),
            )
            return_output = pcode_call_output(
                call_op, role=return_role, callee=callee
            ) if return_role else None
            if return_output:
                candidate["static_bindings"]["call_output"] = return_output
                candidate["static_bindings"]["call_output_role"] = return_role
            buffer_expr = expr_base(str(candidate.get("candidate_source_buffer", "")))
            actual_args = list(candidate.get("actual_args", []) or [])
            pcode_inputs = list(call_op.get("inputs", []) or [])[1:]
            if not str(candidate.get("candidate_source_object_id", "")) or str(
                candidate.get("candidate_source_object_id", "")
            ).startswith("textobj:"):
                if 0 <= source_arg_index < len(pcode_inputs):
                    node = pcode_inputs[source_arg_index]
                    node_object_id = abstract_memory_object_id(node)
                    candidate["candidate_source_object_id"] = node_object_id
                    candidate["static_bindings"]["source_actual_arg_index"] = source_arg_index
                    candidate["static_bindings"]["source_actual_object_id"] = node_object_id
                    candidate["static_bindings"]["source_actual_value_id"] = varnode_value_id(node)
                else:
                    for index, actual in enumerate(actual_args):
                        if index >= len(pcode_inputs):
                            break
                        if buffer_expr and (
                            expr_base(str(actual)) == buffer_expr
                            or expr_mentions(str(actual), buffer_expr)
                        ):
                            node = pcode_inputs[index]
                            node_object_id = abstract_memory_object_id(node)
                            candidate["candidate_source_object_id"] = node_object_id
                            candidate["static_bindings"]["source_actual_arg_index"] = index
                            candidate["static_bindings"]["source_actual_object_id"] = node_object_id
                            candidate["static_bindings"]["source_actual_value_id"] = varnode_value_id(node)
                            break
        elif not callee:
            buffer_expr = expr_base(str(candidate.get("candidate_source_buffer", "")))
            for parameter in list(fact.get("parameters", []) or []):
                if str(parameter.get("name", "")) == buffer_expr:
                    candidate["candidate_source_object_id"] = str(parameter.get("object_id", ""))
                    candidate.setdefault("static_bindings", {})["source_parameter_index"] = parameter.get("index")
                    if not str(candidate["static_bindings"].get("site_binding_status", "")):
                        candidate["static_bindings"]["site_binding_status"] = "unresolved_pcode_store_site"
                    break
        candidate["binding_required"] = bool(
            candidate.get("candidate_source_buffer")
            or candidate.get("candidate_source_value")
            or candidate.get("candidate_source_expression")
            or candidate.get("candidate_source_nodes")
        )
    return candidates


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--sources-json", required=True, type=Path)
    parser.add_argument("--source-unconfirmed-json", required=True, type=Path)
    parser.add_argument("--elf", default="", type=str)
    parser.add_argument("--registry", default=DEFAULT_REGISTRY_PATH, type=Path)
    parser.add_argument(
        "--software-summary-pack",
        default=DEFAULT_SOFTWARE_SUMMARY_PACK,
        type=Path,
        help="Versioned Mango-compatible API/callback Source summaries.",
    )
    parser.add_argument(
        "--program-facts",
        default=None,
        type=Path,
        help="Optional Ghidra High P-code facts from ghidra_export_source_facts.py.",
    )
    parser.add_argument(
        "--hardware-metadata",
        default=None,
        type=Path,
        help=(
            "Diagnostic-only manual profile override. Canonical analysis uses "
            "--hardware-profile-registry and ELF evidence."
        ),
    )
    parser.add_argument(
        "--hardware-profile-registry",
        default=DEFAULT_HARDWARE_PROFILE_REGISTRY,
        type=Path,
        help="Generic hardware profiles automatically selected from ELF evidence.",
    )
    parser.add_argument(
        "--disable-mcu-source-recognition",
        action="store_true",
        help=(
            "Controlled ablation: retain Mango-compatible software-interface "
            "summaries, but disable MMIO, DMA, ISR, and generalized structural "
            "MCU Source recognition."
        ),
    )
    args = parser.parse_args()
    mcu_source_recognition_enabled = not args.disable_mcu_source_recognition

    registry = read_json(args.registry)
    program_facts = read_json(args.program_facts) if args.program_facts else None
    initialized_memory: device_dispatch_resolver.InitializedMemory | None = None
    if program_facts and args.elf:
        elf_path = Path(args.elf)
        expected_hash = str(program_facts.get("binary_sha256", ""))
        if elf_path.exists() and expected_hash and sha256_path(elf_path) != expected_hash:
            raise SystemExit("program facts binary_sha256 does not match --elf")
        if elf_path.exists():
            enrich_program_facts_with_elf_literals(program_facts, elf_path)
    if args.hardware_metadata:
        if not program_facts:
            raise SystemExit("--hardware-metadata requires --program-facts")
        apply_hardware_metadata(
            program_facts,
            read_json(args.hardware_metadata),
            elf_path=Path(args.elf) if args.elf else None,
        )
    if program_facts and args.elf and Path(args.elf).exists():
        initialized_memory = device_dispatch_resolver.InitializedMemory.from_elf(
            Path(args.elf)
        )
        has_callind = any(
            str(op.get("mnemonic", "")) == "CALLIND"
            for function in facts_functions(program_facts)
            for op in list(function.get("pcode_ops", []) or [])
        )
        if has_callind:
            program_facts["device_dispatch_resolution"] = (
                device_dispatch_resolver.resolve_device_dispatches(
                    program_facts,
                    initialized_memory=initialized_memory,
                )
            )
    if (
        program_facts
        and not args.hardware_metadata
        and args.elf
        and Path(args.elf).exists()
    ):
        apply_automatic_hardware_profile(
            program_facts,
            elf_path=Path(args.elf),
            registry_path=args.hardware_profile_registry,
            initialized_memory=initialized_memory,
        )
    lines = args.input.read_text(errors="replace").splitlines(keepends=True)
    functions = parse_functions(lines)
    # Body summaries are confirmed only by High P-code. Pseudo-C inference is
    # retained as code for candidate generation, not used as a proof source.
    confirmed_sources: list[dict[str, Any]] = []
    raw_mmio_observations: list[dict[str, Any]] = []
    next_source = 1

    rows, next_source = scan_direct_api_sources(functions, registry, start_source_index=next_source)
    confirmed_sources.extend(rows)
    rows, next_source = scan_return_api_sources(functions, registry, start_source_index=next_source)
    confirmed_sources.extend(rows)
    rows, next_source = scan_framework_parameter_sources(functions, registry, start_source_index=next_source)
    confirmed_sources.extend(rows)
    # Pseudo-C compatibility mode may nominate semantic candidates, but it
    # cannot directly prove MMIO def-use or instantiate a body summary.

    structured_candidates: list[dict[str, Any]] = []
    software_analysis: dict[str, Any] = {
        "schema_version": "ct-mini-software-source-analysis-v1",
        "confirmed_sources": [],
        "source_definitions": [],
        "function_summaries": [],
        "descriptor_provenance": {},
        "unresolved_indirect_calls": [],
        "counts": {},
    }
    next_candidate = 1
    if program_facts and mcu_source_recognition_enabled:
        rows, structured_candidates, raw_rows, next_source, next_candidate = structured_mmio_and_dma_scan(
            program_facts,
            registry,
            start_source_index=next_source,
            start_candidate_index=next_candidate,
            initialized_memory=initialized_memory,
        )
        confirmed_sources.extend(rows)
        raw_mmio_observations.extend(raw_rows)
        rows, next_candidate = scan_duplex_transfer_receive_candidates(
            program_facts,
            start_candidate_index=next_candidate,
        )
        structured_candidates.extend(rows)
        rows, next_candidate = scan_callback_output_copy_candidates(
            program_facts,
            initialized_memory,
            start_candidate_index=next_candidate,
        )
        structured_candidates.extend(rows)

    if program_facts and args.software_summary_pack.exists():
        software_analysis = software_source_engine.analyze(
            program_facts,
            read_json(args.software_summary_pack),
            seed_sources=confirmed_sources,
        )
        for raw in list(software_analysis.get("confirmed_sources", []) or []):
            confirmed_sources.append(confirmed_source_row(
                source_id=f"SO{next_source:04d}",
                detection_kind=str(raw.get("detection_kind", "software_summary_callsite")),
                confirmation_source=str(raw.get("confirmation_source", "trusted_api_contract")),
                label=str(raw.get("label", "BYTE_STREAM_INGRESS")),
                source_kind=str(raw.get("source_kind", "external_input")),
                function=str(raw.get("function", "")),
                plain_line=int(raw.get("plain_line", 0) or 0),
                source_site=str(raw.get("source_site", "")),
                source_buffer=str(raw.get("source_buffer", "")),
                callee=str(raw.get("callee", "")),
                site_id=str(raw.get("site_id", "")),
                source_object_id=str(raw.get("source_object_id", "")),
                source_value_id=str(raw.get("source_value_id", "")),
                source_outputs=list(raw.get("source_outputs", []) or []),
                proof=dict(raw.get("proof", {}) or {}),
                extra={"function_id": str(raw.get("function_id", ""))},
            ))
            next_source += 1

    before_dedupe = len(confirmed_sources)
    confirmed_sources = dedupe_rows(confirmed_sources, source_site_key)
    confirmed_deduped = before_dedupe - len(confirmed_sources)
    confirmed_keys = {str(row.get("site_key", "")) for row in confirmed_sources}

    if mcu_source_recognition_enabled:
        candidates, next_candidate = scan_semantic_callsite_source_candidates(
            functions,
            registry,
            confirmed_keys=confirmed_keys,
            start_candidate_index=next_candidate,
        )
        candidates = structured_candidates + candidates
    else:
        candidates = []
    confirmed_bindings = {
        (str(row.get("function", "")), str(row.get("source_buffer", "")))
        for row in confirmed_sources
    }
    if mcu_source_recognition_enabled:
        body_candidates, next_candidate = scan_complex_body_ingress_candidates(
            functions,
            registry,
            confirmed_functions=confirmed_bindings,
            start_candidate_index=next_candidate,
        )
        candidates.extend(body_candidates)
    if not program_facts and mcu_source_recognition_enabled:
        more_candidates, _ = scan_semantic_source_candidates(
            functions,
            registry,
            confirmed_keys=confirmed_keys,
            start_candidate_index=next_candidate,
        )
        candidates.extend(more_candidates)
    callsite_scopes = {
        (str(row.get("function", "")), normalize_expr_for_key(str(row.get("candidate_source_buffer", ""))))
        for row in candidates
        if row.get("candidate_kind") == "semantic_callsite_source_candidate"
    }
    candidates = [
        row for row in candidates
        if not (
            row.get("candidate_kind") == "semantic_ingress_candidate"
            and (
                str(row.get("function", "")),
                normalize_expr_for_key(str(row.get("candidate_source_buffer", ""))),
            ) in callsite_scopes
        )
    ]
    candidates = enrich_candidates_with_program_facts(candidates, program_facts)
    candidates_before_dedupe = len(candidates)
    candidates = dedupe_rows(candidates, candidate_site_key)
    candidates_deduped = candidates_before_dedupe - len(candidates)

    heuristic_sources: list[dict[str, Any]] = []
    dropped_candidates: list[dict[str, Any]] = []
    heuristic_index = len(confirmed_sources) + 1
    for candidate in candidates:
        row = heuristic_source_row(candidate, f"SO{heuristic_index:04d}")
        if row is None:
            dropped = dict(candidate)
            dropped["decision"] = "DROP_LOCAL_HEURISTIC"
            dropped["drop_reason"] = "insufficient_generalized_structural_source_evidence"
            dropped_candidates.append(dropped)
            continue
        heuristic_sources.append(row)
        heuristic_index += 1
    source_sites = dedupe_rows(confirmed_sources + heuristic_sources, source_site_key)
    # Deterministic and admitted heuristic Sources share one propagation
    # mechanism. Their original evidence level is retained on each definition
    # and every downstream path; unresolved candidates never become seeds.
    source_function_binding_blockers = bind_source_rows_to_program_functions(
        source_sites,
        program_facts,
    )
    source_definitions = software_source_engine.source_definitions(source_sites)

    direct_confirmed = [
        row for row in confirmed_sources
        if str(row.get("decision", "")) == "ACCEPT_DETERMINISTIC"
    ]

    sources_artifact = {
        "schema_version": "ct-mini-sources-v3",
        "scope": "sink_backward_dfa_source_endpoints",
        "input": {
            "decompiled_c": str(args.input),
            "elf": args.elf,
            "program_facts": str(args.program_facts) if args.program_facts else "",
            "hardware_metadata": str(args.hardware_metadata) if args.hardware_metadata else "",
            "hardware_profile_registry": str(args.hardware_profile_registry),
            "hardware_profile_mode": (
                "manual_debug_override"
                if args.hardware_metadata
                else "elf_automatic_register_first"
            ),
            "software_summary_pack": str(args.software_summary_pack),
            "analysis_mode": "ghidra_high_pcode" if program_facts else "decompiled_c_compatibility",
            "disabled_capabilities": (
                ["mcu-source-recognition"]
                if args.disable_mcu_source_recognition
                else []
            ),
        },
        "registry": {
            "schema_version": str(registry.get("schema_version", "")),
            "name": str(registry.get("name", "")),
            "path": str(args.registry),
        },
        "hardware_evidence": {
            "platform_id": str(
                ((program_facts or {}).get("hardware_profile", {}) or {}).get(
                    "platform_id", ""
                )
            ),
            "profile_identity": dict(
                (program_facts or {}).get("hardware_profile_identity", {}) or {}
            ),
            "resolution": dict(
                (program_facts or {}).get("hardware_resolution", {}) or {}
            ),
            "canonical_profile_selection": not bool(args.hardware_metadata),
            "dispatch_resolution_counts": dict(
                (
                    (program_facts or {}).get("device_dispatch_resolution", {}) or {}
                ).get("counts", {})
                or {}
            ),
        },
        "decision_policy": (
            "mango_compatible_software_interfaces_only_ablation"
            if args.disable_mcu_source_recognition
            else "deterministic_and_generalized_local_heuristics_no_front_llm"
        ),
        "next_stage_ready": True,
        "counts": {
            "functions": len(functions),
            "confirmed_sources": len(confirmed_sources),
            "direct_confirmed_sources": len(direct_confirmed),
            "deterministic_source_sites": len(confirmed_sources),
            "heuristic_source_sites": len(heuristic_sources),
            "source_sites": len(source_sites),
            "locally_dropped_candidates": len(dropped_candidates),
            "llm_confirmed_sources": 0,
            "confirmed_sources_deduped": confirmed_deduped,
            "unconfirmed_candidates": len(candidates),
            "unconfirmed_candidates_deduped": candidates_deduped,
            "raw_mmio_observations": len(raw_mmio_observations),
            "direct_api_sources": len([r for r in confirmed_sources if r.get("detection_kind") == "direct_api_callsite"]),
            "source_return_api_sources": len([r for r in confirmed_sources if r.get("detection_kind") == "source_return_api"]),
            "framework_parameter_sources": len([r for r in confirmed_sources if r.get("detection_kind") == "framework_parameter_summary"]),
            "body_derived_source_calls": len([
                r for r in confirmed_sources
                if r.get("detection_kind") in {
                    "body_derived_source_callsite",
                    "high_pcode_body_summary_callsite",
                }
            ]),
            "body_derived_source_summaries": len([
                row for row in list(software_analysis.get("function_summaries", []) or [])
                if str(row.get("proof_kind", "")).startswith("body_proved_")
            ]),
            "software_summary_sources": len([
                r for r in confirmed_sources if r.get("detection_kind") == "software_summary_callsite"
            ]),
            "source_definitions": len(source_definitions),
            "source_function_binding_blockers": len(source_function_binding_blockers),
            "unresolved_indirect_calls": len(
                list(software_analysis.get("unresolved_indirect_calls", []) or [])
            ),
            "mmio_data_register_sources": len([
                r for r in confirmed_sources
                if r.get("detection_kind") in {
                    "mmio_data_register_to_buffer",
                    "high_pcode_mmio_data_to_buffer",
                }
            ]),
            "high_pcode_sources": len([
                r for r in confirmed_sources if str(r.get("detection_kind", "")).startswith("high_pcode_")
            ]),
            "dma_backed_sources": len([r for r in confirmed_sources if r.get("label") == "DMA_BACKED_BUFFER"]),
        },
        "confirmed_sources": confirmed_sources,
        "source_definitions": source_definitions,
        "analysis_blockers": {
            "source_function_binding": source_function_binding_blockers,
        },
        "software_analysis": {
            "summary_pack": str(args.software_summary_pack),
            "counts": dict(software_analysis.get("counts", {}) or {}),
            "function_summaries": list(software_analysis.get("function_summaries", []) or []),
            "descriptor_provenance": dict(software_analysis.get("descriptor_provenance", {}) or {}),
            "unresolved_indirect_calls": list(
                software_analysis.get("unresolved_indirect_calls", []) or []
            ),
        },
        "heuristic_sources": heuristic_sources,
        "source_sites": source_sites,
        "dropped_candidates": dropped_candidates,
        "raw_observations": {
            "mmio": raw_mmio_observations[:200],
            "truncated": len(raw_mmio_observations) > 200,
        },
    }
    unconfirmed_artifact = {
        "schema_version": "ct-mini-source-unconfirmed-v3",
        "scope": "deprecated_compatibility_artifact_no_front_llm",
        "input": {
            "decompiled_c": str(args.input),
            "elf": args.elf,
            "program_facts": str(args.program_facts) if args.program_facts else "",
            "analysis_mode": "ghidra_high_pcode" if program_facts else "decompiled_c_compatibility",
        },
        "registry": {
            "schema_version": str(registry.get("schema_version", "")),
            "name": str(registry.get("name", "")),
            "path": str(args.registry),
        },
        "counts": {
            "functions": len(functions),
            "candidates": 0,
        },
        "candidates": [],
        "note": "All generalized structural decisions are recorded in sources.json.",
    }
    write_json(args.sources_json, sources_artifact)
    write_json(args.source_unconfirmed_json, unconfirmed_artifact)
    print(json.dumps(sources_artifact["counts"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
