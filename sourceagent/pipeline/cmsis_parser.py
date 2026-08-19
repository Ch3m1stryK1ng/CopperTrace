"""CMSIS header parser — extract peripheral struct offsets and base addresses.

Supports three MCU families:
  - STM32: ``typedef struct { __IO uint32_t SR; } USART_TypeDef;``
  - SAM3:  ``typedef struct { RwReg UART_CR; } Uart;``  (offsets in comments)
  - K64F:  ``typedef struct { __IO uint8_t BDH; } UART_Type;``  (offsets in comments)

The parser extracts two maps:
  1. Struct offsets: {TypeName: {field_name: byte_offset}}
  2. Base addresses: {instance_name: (type_name, base_addr)}
"""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple


# ── Type width map for computing offsets when not in comments ────────────

_SIZE_MAP: Dict[str, int] = {
    "uint32_t": 4, "int32_t": 4, "uint16_t": 2, "int16_t": 2,
    "uint8_t": 1, "int8_t": 1,
    # SAM3 register types (all 32-bit)
    "RoReg": 4, "RwReg": 4, "WoReg": 4,
}

# ── Comment offset regex ────────────────────────────────────────────────

# Matches "offset: 0x0004" or "Offset: 0x0000" in Doxygen comments
_RE_COMMENT_OFFSET = re.compile(
    r"[Oo]ffset:\s*0x([0-9a-fA-F]+)", re.IGNORECASE
)


# ── Public API ───────────────────────────────────────────────────────────


def parse_cmsis_header(header_path: str) -> Dict[str, Dict[str, int]]:
    """Parse a CMSIS header file into {TypeName: {field_name: byte_offset}}.

    Handles STM32, SAM3, and K64F struct styles.
    Field names that start with a known prefix (e.g. UART_) are stored both
    with and without the prefix for flexible matching.
    """
    with open(header_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    return _parse_structs(text)


def parse_base_addresses(header_path: str) -> Dict[str, Tuple[str, int]]:
    """Parse base address #defines from a CMSIS header.

    Returns {instance_name: (type_name, base_addr)}.
    Handles:
      - ``#define UART ((Uart *)0x400E0800U)``
      - ``#define UART0_BASE (0x4006A000u)`` + ``#define UART0 ((UART_Type *)UART0_BASE)``
    """
    with open(header_path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    return _parse_bases(text)


# ── Internal: struct parsing ──────────────────────────────────────────────


def _parse_structs(text: str) -> Dict[str, Dict[str, int]]:
    """Extract all typedef structs from header text."""
    result: Dict[str, Dict[str, int]] = {}

    # Match: typedef struct { ... } TypeName;
    # Use re.DOTALL to span multiple lines
    struct_re = re.compile(
        r"typedef\s+struct\s*\{(.*?)\}\s*(\w+)\s*;",
        re.DOTALL,
    )

    for m in struct_re.finditer(text):
        body = m.group(1)
        type_name = m.group(2)

        fields = _parse_struct_body(body)
        if fields:
            result[type_name] = fields

    return result


def _parse_struct_body(body: str) -> Dict[str, int]:
    """Parse struct body into {field_name: byte_offset}.

    Strategy:
      1. Try comment-based offsets first (SAM3/K64F style)
      2. Fall back to sequential accumulation (STM32 style)
    """
    lines = body.split("\n")
    fields: Dict[str, int] = {}
    has_comment_offsets = False

    # First pass: try comment-based offsets
    for line in lines:
        field_info = _parse_field_line(line)
        if field_info is None:
            continue

        field_name, field_size, comment_offset = field_info

        # Skip reserved/padding fields
        if field_name.startswith("RESERVED") or field_name.startswith("Reserved"):
            continue

        if comment_offset is not None:
            has_comment_offsets = True
            fields[field_name] = comment_offset

    if has_comment_offsets and fields:
        return fields

    # Second pass: sequential accumulation (no comment offsets)
    fields = {}
    offset = 0
    for line in lines:
        field_info = _parse_field_line(line)
        if field_info is None:
            continue

        field_name, field_size, _ = field_info
        array_count = _get_array_count(line)

        if not (field_name.startswith("RESERVED") or field_name.startswith("Reserved")):
            fields[field_name] = offset

        offset += field_size * array_count

    return fields


# Field line regex: matches type qualifiers + type + field_name (with optional array)
# Handles: __IO uint32_t SR;  /  RwReg UART_CR;  /  __I uint8_t S1;
_RE_FIELD = re.compile(
    r"^\s*(?:__IO|__I|__O|volatile\s+)?\s*(\w+)\s+(\w+)"
    r"(?:\s*\[(\d+)\])?\s*;",
    re.MULTILINE,
)

# Array count for padding: RESERVED[N] or Reserved1[55]
_RE_ARRAY = re.compile(r"\[(\d+)\]")


def _parse_field_line(line: str) -> Optional[Tuple[str, int, Optional[int]]]:
    """Parse a single struct field line.

    Returns (field_name, field_byte_size, comment_offset_or_None) or None.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
        # Check if it's a standalone comment line (skip)
        if not any(c in stripped for c in (";",)):
            return None

    # Try to match field declaration
    m = _RE_FIELD.search(line)
    if not m:
        return None

    type_name = m.group(1)
    field_name = m.group(2)

    # Determine size
    size = _SIZE_MAP.get(type_name, 4)  # default to 32-bit

    # Check for comment offset
    comment_offset = None
    offset_m = _RE_COMMENT_OFFSET.search(line)
    if offset_m:
        comment_offset = int(offset_m.group(1), 16)

    return field_name, size, comment_offset


def _get_array_count(line: str) -> int:
    """Extract array count from field declaration, default 1."""
    m = _RE_ARRAY.search(line)
    return int(m.group(1)) if m else 1


# ── Internal: base address parsing ─────────────────────────────────────────


def _parse_bases(text: str) -> Dict[str, Tuple[str, int]]:
    """Extract base address definitions."""
    result: Dict[str, Tuple[str, int]] = {}

    # First collect _BASE defines: #define UART0_BASE (0x4006A000u)
    base_defines: Dict[str, int] = {}
    re_base_const = re.compile(
        r"#define\s+(\w+_BASE)\s+\(?0x([0-9a-fA-F]+)[uUlL]*\)?",
    )
    for m in re_base_const.finditer(text):
        name = m.group(1)
        addr = int(m.group(2), 16)
        base_defines[name] = addr

    # Style 1: #define UART ((Uart *)0x400E0800U)
    re_typed_base = re.compile(
        r"#define\s+(\w+)\s+\(\s*\(\s*(\w+)\s*\*\s*\)\s*0x([0-9a-fA-F]+)[uUlL]*\s*\)",
    )
    for m in re_typed_base.finditer(text):
        instance = m.group(1)
        type_name = m.group(2)
        addr = int(m.group(3), 16)
        # Skip _BASE defines (already captured)
        if instance.endswith("_BASE"):
            continue
        result[instance] = (type_name, addr)

    # Style 2: #define UART0 ((UART_Type *)UART0_BASE)
    re_typed_ref = re.compile(
        r"#define\s+(\w+)\s+\(\s*\(\s*(\w+)\s*\*\s*\)\s*(\w+_BASE)\s*\)",
    )
    for m in re_typed_ref.finditer(text):
        instance = m.group(1)
        type_name = m.group(2)
        base_ref = m.group(3)
        if base_ref in base_defines:
            result[instance] = (type_name, base_defines[base_ref])

    return result
