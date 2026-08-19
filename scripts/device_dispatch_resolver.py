#!/usr/bin/env python3
"""Resolve ELF-proven device/API-table CALLIND targets from ProgramFacts.

The resolver is deliberately name-agnostic.  It accepts three proof shapes:

* a High P-code CALLIND target loaded from a constant table slot; or
* a device pointer stored from a constant-name lookup, followed by an
  initialized-data chain from that name to a config object, device object,
  API table, and function slot; or
* a CALLIND target loaded through a bounded access path whose base is returned
  by a uniquely resolved direct callee.

Formal-parameter dispatches have a stricter proof boundary.  Their target is
read directly from an ELF object-bounded API slot, and their actual/formal
identity must be visible either in High P-code or in preserved machine ABI
storage.  Recovered function signatures never select a target.

Every result retains the High P-code and initialized-memory evidence used to
reach it.  Non-unique candidates are reported as ambiguous rather than chosen.
Constant-table targets always use the cheap proof path.  More expensive
whole-object-domain fallbacks are bounded so a firmware with hundreds of
unrelated callbacks cannot stall Source Mining or Channelgraph construction;
budgeted callsites remain explicit unresolved results.
"""

from __future__ import annotations

import argparse
import json
import re
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "ct-mini-device-dispatch-resolution-v1"
DEFAULT_MAX_EXPENSIVE_FALLBACKS = 64
DEFAULT_MAX_FINITE_CALLIND_TARGETS = 32
TRANSPARENT_OPS = {
    "CAST",
    "COPY",
    "INDIRECT",
    "INT_SEXT",
    "INT_ZEXT",
    "SUBPIECE",
}
IDENTITY_OPS = {"CAST", "COPY"}
ADD_OPS = {"INT_ADD", "PTRADD", "PTRSUB"}


def parse_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


def hex_value(value: int | None) -> str:
    return "" if value is None else f"0x{value:x}"


def node_value_id(node: dict[str, Any] | None) -> str:
    return str((node or {}).get("value_id", ""))


def node_offset(node: dict[str, Any] | None) -> int | None:
    return parse_int((node or {}).get("offset"))


def node_parameter_slot(node: dict[str, Any] | None) -> int | None:
    slot = (node or {}).get("parameter_slot")
    if isinstance(slot, int):
        return slot
    object_id = str((node or {}).get("object_id", ""))
    if object_id.startswith("param:"):
        try:
            return int(object_id.rsplit(":", 1)[1])
        except ValueError:
            return None
    return None


@dataclass(frozen=True)
class MemoryRegion:
    start: int
    data: bytes
    source: str = "initialized_data"
    writable: bool = False
    executable: bool = False
    name: str = ""

    @property
    def end(self) -> int:
        return self.start + len(self.data)

    def contains(self, address: int, size: int = 1) -> bool:
        return self.start <= address and address + size <= self.end


@dataclass(frozen=True)
class MemorySymbol:
    address: int
    size: int
    kind: str
    name: str = ""
    source: str = "elf:symbol"
    section: str = ""
    writable: bool = False
    executable: bool = False

    @property
    def end(self) -> int:
        return self.address + self.size

    def contains(self, address: int, size: int = 1) -> bool:
        return self.size > 0 and self.address <= address and address + size <= self.end


class InitializedMemory:
    """Read-only view over bytes present in the firmware image."""

    def __init__(
        self,
        regions: Iterable[MemoryRegion] = (),
        *,
        symbols: Iterable[MemorySymbol] = (),
        pointer_size: int = 4,
        little_endian: bool = True,
        machine: str = "",
    ) -> None:
        self.regions = sorted(regions, key=lambda row: row.start)
        self.symbols = sorted(
            symbols,
            key=lambda row: (row.address, row.size, row.kind, row.name),
        )
        self.pointer_size = pointer_size
        self.byteorder = "little" if little_endian else "big"
        self.machine = machine
        self._sparse: dict[tuple[int, int], tuple[bytes, str]] = {}

    @classmethod
    def from_elf(cls, path: Path) -> "InitializedMemory":
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:  # pragma: no cover - environment failure
            raise RuntimeError("pyelftools is required for --elf") from exc

        regions: list[MemoryRegion] = []
        symbols: list[MemorySymbol] = []
        with path.open("rb") as stream:
            elf = ELFFile(stream)
            pointer_size = 8 if int(elf.elfclass) == 64 else 4
            little_endian = bool(elf.little_endian)
            machine = str(elf["e_machine"])
            for index, segment in enumerate(elf.iter_segments()):
                if segment["p_type"] != "PT_LOAD" or int(segment["p_filesz"]) <= 0:
                    continue
                flags = int(segment["p_flags"])
                regions.append(
                    MemoryRegion(
                        start=int(segment["p_vaddr"]),
                        data=bytes(segment.data()),
                        source=f"elf:PT_LOAD[{index}]",
                        writable=bool(flags & 0x2),
                        executable=bool(flags & 0x1),
                    )
                )
            try:
                from elftools.elf.sections import SymbolTableSection
            except ImportError:  # pragma: no cover - imported with ELFFile above
                SymbolTableSection = ()  # type: ignore[assignment]
            for section_index, section in enumerate(elf.iter_sections()):
                if not isinstance(section, SymbolTableSection):
                    continue
                for symbol in section.iter_symbols():
                    kind = str(symbol["st_info"]["type"])
                    size = int(symbol["st_size"])
                    address = int(symbol["st_value"])
                    if kind not in {"STT_OBJECT", "STT_FUNC"} or size <= 0 or address == 0:
                        continue
                    target_section = symbol["st_shndx"]
                    section_name = ""
                    section_writable = False
                    section_executable = False
                    if isinstance(target_section, int):
                        resolved_section = elf.get_section(target_section)
                        if resolved_section is not None:
                            section_name = str(resolved_section.name)
                            section_flags = int(resolved_section["sh_flags"])
                            section_writable = bool(section_flags & 0x1)
                            section_executable = bool(section_flags & 0x4)
                    symbols.append(
                        MemorySymbol(
                            address=address,
                            size=size,
                            kind=kind,
                            name=str(symbol.name),
                            source=f"elf:{section.name or f'symbols[{section_index}]'}",
                            section=section_name,
                            writable=section_writable,
                            executable=section_executable,
                        )
                    )
        return cls(
            regions,
            symbols=symbols,
            pointer_size=pointer_size,
            little_endian=little_endian,
            machine=machine,
        )

    @classmethod
    def from_regions(
        cls,
        regions: Iterable[MemoryRegion],
        *,
        symbols: Iterable[MemorySymbol] = (),
        pointer_size: int = 4,
        little_endian: bool = True,
        machine: str = "",
    ) -> "InitializedMemory":
        return cls(
            regions,
            symbols=symbols,
            pointer_size=pointer_size,
            little_endian=little_endian,
            machine=machine,
        )

    def add_program_facts_literals(self, facts: dict[str, Any]) -> None:
        for function in list(facts.get("functions", []) or []):
            for op in list(function.get("pcode_ops", []) or []):
                nodes = list(op.get("inputs", []) or [])
                if op.get("output"):
                    nodes.append(op["output"])
                for node in nodes:
                    address = parse_int(node.get("initial_memory_address"))
                    value = parse_int(node.get("initial_memory_value"))
                    size = int(node.get("size", 0) or 0)
                    if address is None or value is None or size not in {1, 2, 4, 8}:
                        continue
                    raw = int(value).to_bytes(size, self.byteorder, signed=False)
                    self._sparse[(address, size)] = (
                        raw,
                        str(node.get("initial_memory_source", "program_facts_literal")),
                    )

    def region_at(self, address: int, size: int = 1) -> MemoryRegion | None:
        for region in self.regions:
            if region.contains(address, size):
                return region
        return None

    def read(self, address: int, size: int) -> bytes | None:
        region = self.region_at(address, size)
        if region is not None:
            offset = address - region.start
            return region.data[offset : offset + size]
        sparse = self._sparse.get((address, size))
        return sparse[0] if sparse else None

    def read_uint(self, address: int, size: int) -> int | None:
        raw = self.read(address, size)
        return int.from_bytes(raw, self.byteorder) if raw is not None else None

    def read_ptr(self, address: int) -> int | None:
        return self.read_uint(address, self.pointer_size)

    def read_cstring(self, address: int, *, limit: int = 256) -> str | None:
        raw = bytearray()
        for index in range(limit):
            byte = self.read(address + index, 1)
            if byte is None:
                return None
            if byte == b"\x00":
                break
            raw.extend(byte)
        else:
            return None
        if not raw:
            return None
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return None
        allowed = set(string.printable) - {"\x0b", "\x0c", "\r", "\n", "\t"}
        return text if all(char in allowed for char in text) else None

    def pointer_references(self, value: int) -> list[dict[str, Any]]:
        needle = int(value).to_bytes(self.pointer_size, self.byteorder, signed=False)
        rows: list[dict[str, Any]] = []
        for region in self.regions:
            for offset in range(0, max(0, len(region.data) - self.pointer_size + 1), self.pointer_size):
                if region.data[offset : offset + self.pointer_size] != needle:
                    continue
                address = region.start + offset
                rows.append(
                    {
                        "address": address,
                        "source": region.source,
                        "region": region.name,
                        "writable": region.writable,
                        "executable": region.executable,
                    }
                )
        for (address, size), (raw, source) in self._sparse.items():
            if size == self.pointer_size and raw == needle:
                rows.append({"address": address, "source": source, "region": "sparse"})
        unique: dict[int, dict[str, Any]] = {int(row["address"]): row for row in rows}
        return [unique[key] for key in sorted(unique)]

    def evidence(self, address: int) -> dict[str, Any]:
        region = self.region_at(address)
        if region is not None:
            return {
                "address": hex_value(address),
                "source": region.source,
                "region": region.name,
                "writable": region.writable,
                "executable": region.executable,
            }
        for (candidate, _), (_, source) in self._sparse.items():
            if candidate == address:
                return {"address": hex_value(address), "source": source, "region": "sparse"}
        return {"address": hex_value(address), "source": "unavailable"}

    def symbol_extents(self, kind: str) -> list[dict[str, Any]]:
        """Return deduplicated, non-empty ELF symbol extents of one kind."""

        grouped: dict[tuple[int, int, str, bool, bool], dict[str, Any]] = {}
        for symbol in self.symbols:
            if symbol.kind != kind or symbol.size <= 0 or not symbol.source.startswith("elf:"):
                continue
            key = (
                symbol.address,
                symbol.size,
                symbol.section,
                symbol.writable,
                symbol.executable,
            )
            row = grouped.setdefault(
                key,
                {
                    "address": symbol.address,
                    "size": symbol.size,
                    "end": symbol.end,
                    "kind": symbol.kind,
                    "section": symbol.section,
                    "writable": symbol.writable,
                    "executable": symbol.executable,
                    "names": [],
                    "sources": [],
                },
            )
            if symbol.name:
                row["names"].append(symbol.name)
            row["sources"].append(symbol.source)
        for row in grouped.values():
            row["names"] = sorted(set(row["names"]))
            row["sources"] = sorted(set(row["sources"]))
        return [grouped[key] for key in sorted(grouped)]

    def exact_object_extents(self, address: int) -> list[dict[str, Any]]:
        return [
            row
            for row in self.symbol_extents("STT_OBJECT")
            if int(row["address"]) == address
        ]

    def function_extents(self, address: int) -> list[dict[str, Any]]:
        normalized = address & ~1
        return [
            row
            for row in self.symbol_extents("STT_FUNC")
            if (int(row["address"]) & ~1) == normalized
        ]

    def extent_contains(
        self,
        extent: dict[str, Any],
        address: int,
        size: int = 1,
    ) -> bool:
        return (
            int(extent.get("size", 0)) > 0
            and int(extent.get("address", 0)) <= address
            and address + size <= int(extent.get("end", 0))
        )

    def executable_bytes(self, start: int, through: int, *, trailer: int = 4) -> bytes | None:
        region = self.region_at(start)
        if region is None or not region.executable or not region.contains(through):
            return None
        end = min(region.end, through + trailer)
        return region.data[start - region.start : end - region.start]


@dataclass(frozen=True)
class AddressForm:
    base_value_id: str
    base_node: dict[str, Any] | None
    constant_base: int | None
    offset: int
    site_ids: tuple[str, ...]


@dataclass(frozen=True)
class ReturnedPointerValue:
    """One initialized pointer expression and the body-derived evidence for it."""

    value: int
    site_ids: tuple[str, ...] = ()
    return_edges: tuple[tuple[str, str, str, str], ...] = ()


@dataclass(frozen=True)
class ReturnedAccessPath:
    """A pointer returned from one formal through constant-offset LOADs."""

    parameter_slot: int
    dereference_offsets: tuple[int, ...]
    site_ids: tuple[str, ...] = ()
    return_edges: tuple[tuple[str, str, str, str], ...] = ()


@dataclass(frozen=True)
class FiniteTableAccess:
    """One High P-code indexed access into an immutable initialized object."""

    table_base: int
    first_entry_address: int
    stride: int
    selector_value_id: str
    selector_object_id: str
    address_site_ids: tuple[str, ...]
    table_extent: dict[str, Any]


class ProgramIndex:
    def __init__(self, facts: dict[str, Any], memory: InitializedMemory) -> None:
        self.facts = facts
        self.memory = memory
        self.functions = list(facts.get("functions", []) or [])
        self.by_function_id = {
            str(row.get("function_id")): row
            for row in self.functions
            if row.get("function_id")
        }
        self.functions_by_entry: dict[int, list[dict[str, Any]]] = {}
        self.defs: dict[str, dict[str, dict[str, Any]]] = {}
        for function in self.functions:
            entry = parse_int(function.get("entry"))
            if entry is not None:
                self.functions_by_entry.setdefault(entry, []).append(function)
            function_id = str(function.get("function_id", ""))
            self.defs[function_id] = {
                node_value_id(op.get("output")): op
                for op in list(function.get("pcode_ops", []) or [])
                if node_value_id(op.get("output"))
            }
        self.symbols: list[tuple[int, dict[str, Any]]] = []
        for symbol in list(facts.get("symbols", []) or []):
            address = parse_int(symbol.get("address"))
            if address is not None:
                self.symbols.append((address, symbol))
        self.symbols.sort(key=lambda item: item[0])

    def definition(self, function_id: str, node: dict[str, Any] | None) -> dict[str, Any] | None:
        return self.defs.get(function_id, {}).get(node_value_id(node))

    def function_candidates(self, address: int) -> list[dict[str, Any]]:
        exact = self.functions_by_entry.get(address, [])
        if exact:
            return exact
        if address & 1:
            return self.functions_by_entry.get(address & ~1, [])
        return []

    def symbol_names(self, address: int) -> list[str]:
        return sorted(
            {
                str(symbol.get("name", ""))
                for candidate, symbol in self.symbols
                if candidate == address and symbol.get("name")
            }
        )

    def object_bases(self, field_address: int, *, max_offset: int = 64) -> list[tuple[int, int]]:
        candidates = {(field_address, 0)}
        field_region = self.memory.region_at(field_address)
        for address, symbol in self.symbols:
            if address > field_address or field_address - address > max_offset:
                continue
            if str(symbol.get("type", "")).lower() == "function":
                continue
            if field_region is not None and not field_region.contains(address):
                continue
            candidates.add((address, field_address - address))
        return sorted(candidates)


class FunctionTrace:
    def __init__(self, index: ProgramIndex, function: dict[str, Any]) -> None:
        self.index = index
        self.function = function
        self.function_id = str(function.get("function_id", ""))

    def definition(self, node: dict[str, Any] | None) -> dict[str, Any] | None:
        return self.index.definition(self.function_id, node)

    def unwrap(self, node: dict[str, Any], *, limit: int = 32) -> tuple[dict[str, Any], list[str]]:
        current = node
        sites: list[str] = []
        seen: set[str] = set()
        for _ in range(limit):
            value_id = node_value_id(current)
            if not value_id or value_id in seen:
                break
            seen.add(value_id)
            op = self.definition(current)
            if op is None or str(op.get("mnemonic", "")) not in TRANSPARENT_OPS:
                break
            inputs = [item for item in list(op.get("inputs", []) or []) if not item.get("is_constant")]
            if len(inputs) != 1:
                break
            sites.append(str(op.get("site_id", "")))
            current = dict(inputs[0])
        return current, sites

    def identity_formal(
        self,
        node: dict[str, Any],
        *,
        limit: int = 32,
    ) -> tuple[int, list[str]] | None:
        """Trace only value-preserving High P-code to one caller formal."""

        current = node
        sites: list[str] = []
        seen: set[str] = set()
        for _ in range(limit):
            slot = node_parameter_slot(current)
            if slot is not None:
                return slot, sites
            value_id = node_value_id(current)
            if not value_id or value_id in seen:
                return None
            seen.add(value_id)
            definition = self.definition(current)
            if definition is None or str(definition.get("mnemonic", "")) not in IDENTITY_OPS:
                return None
            inputs = list(definition.get("inputs", []) or [])
            if len(inputs) != 1 or bool(inputs[0].get("is_constant")):
                return None
            sites.append(str(definition.get("site_id", "")))
            current = dict(inputs[0])
        return None

    def find_load(self, node: dict[str, Any]) -> tuple[dict[str, Any], list[str]] | None:
        unwrapped, sites = self.unwrap(node)
        op = self.definition(unwrapped)
        if op is not None and str(op.get("mnemonic", "")) == "LOAD":
            return op, sites
        return None

    def constant(self, node: dict[str, Any], *, limit: int = 32) -> int | None:
        seen: set[str] = set()

        def visit(current: dict[str, Any], depth: int) -> int | None:
            if depth > limit:
                return None
            value_id = node_value_id(current)
            if value_id and value_id in seen:
                return None
            if value_id:
                seen.add(value_id)
            if bool(current.get("is_constant")):
                return node_offset(current)
            initial = parse_int(current.get("initial_memory_value"))
            if initial is not None:
                return initial
            op = self.definition(current)
            if op is not None:
                mnemonic = str(op.get("mnemonic", ""))
                inputs = list(op.get("inputs", []) or [])
                if mnemonic in TRANSPARENT_OPS:
                    variable = [item for item in inputs if not item.get("is_constant")]
                    return visit(dict(variable[0]), depth + 1) if len(variable) == 1 else None
                if mnemonic == "LOAD" and len(inputs) >= 2:
                    address = visit(dict(inputs[-1]), depth + 1)
                    return self.index.memory.read_ptr(address) if address is not None else None
                if mnemonic in {"INT_ADD", "PTRSUB"} and len(inputs) >= 2:
                    values = [visit(dict(item), depth + 1) for item in inputs]
                    if all(value is not None for value in values):
                        return sum(int(value) for value in values if value is not None)
                if mnemonic == "PTRADD" and len(inputs) >= 3:
                    values = [visit(dict(item), depth + 1) for item in inputs[:3]]
                    if all(value is not None for value in values):
                        return int(values[0]) + int(values[1]) * int(values[2])
            if bool(current.get("is_address")):
                address = node_offset(current)
                if address is None:
                    return None
                loaded = self.index.memory.read_ptr(address)
                return loaded if loaded is not None else address
            return None

        return visit(node, 0)

    def split_address(self, node: dict[str, Any], *, limit: int = 20) -> AddressForm:
        sites: list[str] = []
        offset = 0
        current, transparent_sites = self.unwrap(node)
        sites.extend(transparent_sites)
        for _ in range(limit):
            op = self.definition(current)
            if op is None or str(op.get("mnemonic", "")) not in ADD_OPS:
                break
            mnemonic = str(op.get("mnemonic", ""))
            inputs = list(op.get("inputs", []) or [])
            sites.append(str(op.get("site_id", "")))
            if mnemonic == "PTRADD" and len(inputs) >= 3:
                index = self.constant(dict(inputs[1]))
                scale = self.constant(dict(inputs[2]))
                if index is None or scale is None:
                    break
                offset += index * scale
                current, extra = self.unwrap(dict(inputs[0]))
                sites.extend(extra)
                continue
            constants: list[tuple[int, int]] = []
            for position, item in enumerate(inputs):
                value = self.constant(dict(item))
                if value is not None and (item.get("is_constant") or self.definition(dict(item)) is None):
                    constants.append((position, value))
            if len(inputs) == 2 and len(constants) == 1:
                position, value = constants[0]
                offset += value
                current, extra = self.unwrap(dict(inputs[1 - position]))
                sites.extend(extra)
                continue
            break
        constant_base = None
        if bool(current.get("is_constant")):
            constant_base = node_offset(current)
        return AddressForm(
            base_value_id=node_value_id(current),
            base_node=None if constant_base is not None else current,
            constant_base=constant_base,
            offset=offset,
            site_ids=tuple(site for site in sites if site),
        )

    def defining_call(self, node: dict[str, Any]) -> dict[str, Any] | None:
        current, _ = self.unwrap(node)
        op = self.definition(current)
        return op if op is not None and str(op.get("mnemonic", "")) in {"CALL", "CALLIND"} else None


def _merge_returned_pointer_values(
    rows: Iterable[ReturnedPointerValue],
    *,
    limit: int = 64,
) -> list[ReturnedPointerValue]:
    """Merge equivalent values without discarding their proof paths."""

    grouped: dict[int, dict[str, set[Any]]] = {}
    for row in rows:
        bucket = grouped.setdefault(row.value, {"site_ids": set(), "return_edges": set()})
        bucket["site_ids"].update(site for site in row.site_ids if site)
        bucket["return_edges"].update(row.return_edges)
        if len(grouped) > limit:
            return []
    return [
        ReturnedPointerValue(
            value=value,
            site_ids=tuple(sorted(grouped[value]["site_ids"])),
            return_edges=tuple(sorted(grouped[value]["return_edges"])),
        )
        for value in sorted(grouped)
    ]


def _with_pointer_site(
    rows: Iterable[ReturnedPointerValue],
    site_id: str,
) -> list[ReturnedPointerValue]:
    return [
        ReturnedPointerValue(
            value=row.value,
            site_ids=tuple(sorted(set(row.site_ids) | ({site_id} if site_id else set()))),
            return_edges=row.return_edges,
        )
        for row in rows
    ]


def _returned_pointer_values(
    index: ProgramIndex,
    trace: FunctionTrace,
    node: dict[str, Any],
    *,
    formal_bindings: dict[int, tuple[FunctionTrace, dict[str, Any]]] | None = None,
    depth: int = 0,
    seen: frozenset[tuple[str, str]] = frozenset(),
    max_depth: int = 16,
) -> list[ReturnedPointerValue]:
    """Evaluate a bounded initialized-pointer expression from High P-code.

    This is intentionally smaller than a general symbolic executor.  It only
    follows value-preserving operations, constant address arithmetic,
    initialized LOADs, and uniquely resolved direct-call RETURN definitions.
    Function names, signatures, and recovered types never select a value.
    """

    if depth > max_depth:
        return []
    value_id = node_value_id(node)
    identity = (trace.function_id, value_id or str(node.get("object_id", "")))
    if identity[1] and identity in seen:
        return []
    next_seen = seen | ({identity} if identity[1] else set())

    parameter_slot = node_parameter_slot(node)
    if parameter_slot is not None and formal_bindings and parameter_slot in formal_bindings:
        caller_trace, actual = formal_bindings[parameter_slot]
        return _returned_pointer_values(
            index,
            caller_trace,
            actual,
            depth=depth + 1,
            seen=next_seen,
            max_depth=max_depth,
        )

    initial = parse_int(node.get("initial_memory_value"))
    if initial is not None:
        return [ReturnedPointerValue(initial)]
    if bool(node.get("is_constant")) or bool(node.get("is_address")):
        value = node_offset(node)
        return [ReturnedPointerValue(value)] if value is not None else []

    definition = trace.definition(node)
    if definition is None:
        return []
    mnemonic = str(definition.get("mnemonic", ""))
    inputs = [dict(item or {}) for item in list(definition.get("inputs", []) or [])]
    site_id = str(definition.get("site_id", ""))

    if mnemonic in TRANSPARENT_OPS | {"MULTIEQUAL"}:
        variable_inputs = [item for item in inputs if not bool(item.get("is_constant"))]
        rows: list[ReturnedPointerValue] = []
        for item in variable_inputs:
            rows.extend(
                _returned_pointer_values(
                    index,
                    trace,
                    item,
                    formal_bindings=formal_bindings,
                    depth=depth + 1,
                    seen=next_seen,
                    max_depth=max_depth,
                )
            )
        return _merge_returned_pointer_values(_with_pointer_site(rows, site_id))

    if mnemonic == "LOAD" and len(inputs) >= 2:
        addresses = _returned_pointer_values(
            index,
            trace,
            inputs[-1],
            formal_bindings=formal_bindings,
            depth=depth + 1,
            seen=next_seen,
            max_depth=max_depth,
        )
        rows = []
        for address in addresses:
            loaded = index.memory.read_ptr(address.value)
            if loaded is None:
                continue
            rows.append(
                ReturnedPointerValue(
                    loaded,
                    tuple(sorted(set(address.site_ids) | ({site_id} if site_id else set()))),
                    address.return_edges,
                )
            )
        return _merge_returned_pointer_values(rows)

    if mnemonic in {"INT_ADD", "PTRSUB"} and len(inputs) == 2:
        left = _returned_pointer_values(
            index,
            trace,
            inputs[0],
            formal_bindings=formal_bindings,
            depth=depth + 1,
            seen=next_seen,
            max_depth=max_depth,
        )
        right = _returned_pointer_values(
            index,
            trace,
            inputs[1],
            formal_bindings=formal_bindings,
            depth=depth + 1,
            seen=next_seen,
            max_depth=max_depth,
        )
        rows = [
            ReturnedPointerValue(
                lhs.value + rhs.value,
                tuple(sorted(set(lhs.site_ids) | set(rhs.site_ids) | ({site_id} if site_id else set()))),
                tuple(sorted(set(lhs.return_edges) | set(rhs.return_edges))),
            )
            for lhs in left
            for rhs in right
        ]
        return _merge_returned_pointer_values(rows)

    if mnemonic == "PTRADD" and len(inputs) >= 3:
        bases = _returned_pointer_values(
            index,
            trace,
            inputs[0],
            formal_bindings=formal_bindings,
            depth=depth + 1,
            seen=next_seen,
            max_depth=max_depth,
        )
        indexes = _returned_pointer_values(
            index,
            trace,
            inputs[1],
            formal_bindings=formal_bindings,
            depth=depth + 1,
            seen=next_seen,
            max_depth=max_depth,
        )
        scales = _returned_pointer_values(
            index,
            trace,
            inputs[2],
            formal_bindings=formal_bindings,
            depth=depth + 1,
            seen=next_seen,
            max_depth=max_depth,
        )
        rows = [
            ReturnedPointerValue(
                base.value + subscript.value * scale.value,
                tuple(
                    sorted(
                        set(base.site_ids)
                        | set(subscript.site_ids)
                        | set(scale.site_ids)
                        | ({site_id} if site_id else set())
                    )
                ),
                tuple(
                    sorted(
                        set(base.return_edges)
                        | set(subscript.return_edges)
                        | set(scale.return_edges)
                    )
                ),
            )
            for base in bases
            for subscript in indexes
            for scale in scales
        ]
        return _merge_returned_pointer_values(rows)

    if mnemonic != "CALL":
        return []
    call = dict(definition.get("call", {}) or {})
    target_function_id = str(call.get("target_function_id", ""))
    callee = index.by_function_id.get(target_function_id)
    if not target_function_id or callee is None:
        return []

    actuals = inputs[1:]
    callee_trace = FunctionTrace(index, callee)
    callee_bindings = {
        slot: (trace, actual)
        for slot, actual in enumerate(actuals)
    }
    rows = []
    for return_op in list(callee.get("pcode_ops", []) or []):
        if str(return_op.get("mnemonic", "")) != "RETURN":
            continue
        return_inputs = [dict(item or {}) for item in list(return_op.get("inputs", []) or [])]
        # High P-code RETURN input zero is the machine return target.  Any
        # following inputs are the returned values.
        returned_values = return_inputs[1:] if len(return_inputs) > 1 else []
        for returned in returned_values:
            resolved = _returned_pointer_values(
                index,
                callee_trace,
                returned,
                formal_bindings=callee_bindings,
                depth=depth + 1,
                seen=next_seen,
                max_depth=max_depth,
            )
            edge = (
                site_id,
                target_function_id,
                str(callee.get("name", "")),
                str(return_op.get("site_id", "")),
            )
            for row in resolved:
                rows.append(
                    ReturnedPointerValue(
                        row.value,
                        tuple(sorted(set(row.site_ids) | ({site_id} if site_id else set()))),
                        tuple(sorted(set(row.return_edges) | {edge})),
                    )
                )
    return _merge_returned_pointer_values(rows)


def _merge_returned_access_paths(
    rows: Iterable[ReturnedAccessPath],
    *,
    limit: int = 32,
) -> list[ReturnedAccessPath]:
    grouped: dict[tuple[int, tuple[int, ...]], dict[str, set[Any]]] = {}
    for row in rows:
        key = (row.parameter_slot, row.dereference_offsets)
        bucket = grouped.setdefault(key, {"site_ids": set(), "return_edges": set()})
        bucket["site_ids"].update(site for site in row.site_ids if site)
        bucket["return_edges"].update(row.return_edges)
        if len(grouped) > limit:
            return []
    return [
        ReturnedAccessPath(
            parameter_slot=key[0],
            dereference_offsets=key[1],
            site_ids=tuple(sorted(grouped[key]["site_ids"])),
            return_edges=tuple(sorted(grouped[key]["return_edges"])),
        )
        for key in sorted(grouped)
    ]


def _formal_access_paths(
    trace: FunctionTrace,
    node: dict[str, Any],
    *,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
    max_depth: int = 20,
) -> list[ReturnedAccessPath]:
    """Recover constant-offset pointer dereferences rooted at one formal.

    This is a structural High P-code query, not type inference.  It accepts
    only identity operations, phi nodes with one non-null structural result,
    constant pointer arithmetic, and LOADs.  Thus a result such as
    ``formal[0] -> LOAD(+0) -> LOAD(+4)`` is independently checkable against
    initialized ELF objects.
    """

    if depth > max_depth:
        return []
    slot = node_parameter_slot(node)
    if slot is not None:
        return [ReturnedAccessPath(slot, ())]
    value_id = node_value_id(node)
    if value_id and value_id in seen:
        return []
    next_seen = seen | ({value_id} if value_id else set())
    definition = trace.definition(node)
    if definition is None:
        return []
    mnemonic = str(definition.get("mnemonic", ""))
    inputs = [dict(item or {}) for item in list(definition.get("inputs", []) or [])]
    site_id = str(definition.get("site_id", ""))

    if mnemonic in TRANSPARENT_OPS | {"MULTIEQUAL"}:
        rows: list[ReturnedAccessPath] = []
        for item in inputs:
            if bool(item.get("is_constant")) and (node_offset(item) or 0) == 0:
                continue
            rows.extend(
                _formal_access_paths(
                    trace,
                    item,
                    depth=depth + 1,
                    seen=next_seen,
                    max_depth=max_depth,
                )
            )
        rows = _merge_returned_access_paths(rows)
        return [
            ReturnedAccessPath(
                row.parameter_slot,
                row.dereference_offsets,
                tuple(sorted(set(row.site_ids) | ({site_id} if site_id else set()))),
                row.return_edges,
            )
            for row in rows
        ]

    if mnemonic == "LOAD" and len(inputs) >= 2:
        form = trace.split_address(inputs[-1])
        if form.base_node is None:
            return []
        rows = _formal_access_paths(
            trace,
            form.base_node,
            depth=depth + 1,
            seen=next_seen,
            max_depth=max_depth,
        )
        return [
            ReturnedAccessPath(
                row.parameter_slot,
                row.dereference_offsets + (form.offset,),
                tuple(
                    sorted(
                        set(row.site_ids)
                        | set(form.site_ids)
                        | ({site_id} if site_id else set())
                    )
                ),
                row.return_edges,
            )
            for row in rows
        ]

    if mnemonic in ADD_OPS:
        form = trace.split_address(node)
        if form.base_node is None or form.base_value_id == value_id:
            return []
        rows = _formal_access_paths(
            trace,
            form.base_node,
            depth=depth + 1,
            seen=next_seen,
            max_depth=max_depth,
        )
        # Preserve a final address offset as a pending dereference.  Callers
        # consume it when the expression is used by LOAD.
        return [
            ReturnedAccessPath(
                row.parameter_slot,
                row.dereference_offsets[:-1] + (
                    (row.dereference_offsets[-1] + form.offset)
                    if row.dereference_offsets
                    else form.offset
                ,),
                tuple(sorted(set(row.site_ids) | set(form.site_ids))),
                row.return_edges,
            )
            for row in rows
        ]
    return []


def _direct_return_access_paths(
    index: ProgramIndex,
    trace: FunctionTrace,
    call_result: dict[str, Any],
) -> list[ReturnedAccessPath]:
    definition = trace.defining_call(call_result)
    if definition is None or str(definition.get("mnemonic", "")) != "CALL":
        return []
    call = dict(definition.get("call", {}) or {})
    callee_id = str(call.get("target_function_id", ""))
    callee = index.by_function_id.get(callee_id)
    if callee is None:
        return []
    callee_trace = FunctionTrace(index, callee)
    rows: list[ReturnedAccessPath] = []
    for return_op in list(callee.get("pcode_ops", []) or []):
        if str(return_op.get("mnemonic", "")) != "RETURN":
            continue
        return_inputs = [dict(item or {}) for item in list(return_op.get("inputs", []) or [])]
        for returned in return_inputs[1:]:
            for path in _formal_access_paths(callee_trace, returned):
                edge = (
                    str(definition.get("site_id", "")),
                    callee_id,
                    str(callee.get("name", "")),
                    str(return_op.get("site_id", "")),
                )
                rows.append(
                    ReturnedAccessPath(
                        path.parameter_slot,
                        path.dereference_offsets,
                        tuple(
                            sorted(
                                set(path.site_ids)
                                | ({str(definition.get('site_id', ''))} if definition.get("site_id") else set())
                            )
                        ),
                        tuple(sorted(set(path.return_edges) | {edge})),
                    )
                )
    return _merge_returned_access_paths(rows)


def callsite_row(function: dict[str, Any], op: dict[str, Any]) -> dict[str, Any]:
    return {
        "site_id": str(op.get("site_id", "")),
        "instruction_address": str(op.get("instruction_address", "")),
        "caller_function_id": str(function.get("function_id", "")),
        "caller_function": str(function.get("name", "")),
        "caller_entry": str(function.get("entry", "")),
    }


def target_row(index: ProgramIndex, raw_address: int) -> dict[str, Any] | None:
    candidates = index.function_candidates(raw_address)
    if len(candidates) != 1:
        return None
    function = candidates[0]
    return {
        "raw_address": hex_value(raw_address),
        "address": str(function.get("entry", hex_value(raw_address & ~1))),
        "function_id": str(function.get("function_id", "")),
        "function": str(function.get("name", "")),
        "thumb_bit_cleared": bool(raw_address & 1 and parse_int(function.get("entry")) == (raw_address & ~1)),
    }


def indexed_parameters(function: dict[str, Any]) -> list[dict[str, Any]] | None:
    parameters = list(function.get("parameters", []) or [])
    if not parameters:
        return None
    by_slot = {
        int(parameter["index"]): dict(parameter)
        for parameter in parameters
        if isinstance(parameter.get("index"), int)
    }
    if len(by_slot) != len(parameters) or sorted(by_slot) != list(range(len(parameters))):
        return None
    return [by_slot[slot] for slot in range(len(parameters))]


def verified_elf_target(
    index: ProgramIndex,
    raw_address: int,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]] | None:
    target = target_row(index, raw_address)
    if target is None:
        return None
    functions = index.function_candidates(raw_address)
    extents = index.memory.function_extents(raw_address)
    region = index.memory.region_at(raw_address & ~1)
    if len(functions) != 1 or len(extents) != 1 or region is None or not region.executable:
        return None
    return target, functions[0], extents[0]


def high_pcode_actual_formal_identity(
    trace: FunctionTrace,
    call: dict[str, Any],
    target_function: dict[str, Any],
) -> tuple[list[dict[str, int]], dict[str, Any]] | None:
    target_parameters = indexed_parameters(target_function)
    actuals = [dict(item) for item in list(call.get("inputs", []) or [])[1:]]
    if target_parameters is None or not actuals or len(actuals) != len(target_parameters):
        return None

    bindings: list[dict[str, int]] = []
    details: list[dict[str, Any]] = []
    for target_slot, actual in enumerate(actuals):
        origin = trace.identity_formal(actual)
        if origin is None:
            return None
        caller_slot, identity_sites = origin
        bindings.append(
            {
                "caller_parameter_slot": caller_slot,
                "target_parameter_slot": target_slot,
            }
        )
        details.append(
            {
                "caller_parameter_slot": caller_slot,
                "target_parameter_slot": target_slot,
                "actual_object_id": str(actual.get("object_id", "")),
                "actual_value_id": node_value_id(actual),
                "identity_sites": identity_sites,
            }
        )
    return bindings, {
        "kind": "high_pcode_actual_formal_identity",
        "callsite": str(call.get("site_id", "")),
        "bindings": details,
    }


def register_storage(parameter: dict[str, Any]) -> tuple[str, int] | None:
    match = re.fullmatch(r"\s*(r(?:1[0-5]|[0-9])|sp|lr|pc)\s*:\s*(\d+)\s*", str(parameter.get("storage", "")), re.I)
    if match is None:
        return None
    return match.group(1).lower(), int(match.group(2))


def machine_actual_formal_identity(
    index: ProgramIndex,
    function: dict[str, Any],
    call: dict[str, Any],
    target_function: dict[str, Any],
) -> tuple[list[dict[str, int]], dict[str, Any]] | None:
    """Prove unchanged ARM ABI register values at an indirect transfer."""

    if index.memory.machine != "EM_ARM":
        return None
    caller_parameters = indexed_parameters(function)
    target_parameters = indexed_parameters(target_function)
    if caller_parameters is None or target_parameters is None:
        return None
    if len(caller_parameters) != len(target_parameters):
        return None

    caller_by_storage: dict[tuple[str, int], int] = {}
    for slot, parameter in enumerate(caller_parameters):
        storage = register_storage(parameter)
        if storage is None or storage in caller_by_storage:
            return None
        caller_by_storage[storage] = slot

    bindings: list[dict[str, int]] = []
    preserved_registers: set[str] = set()
    binding_details: list[dict[str, Any]] = []
    for target_slot, parameter in enumerate(target_parameters):
        storage = register_storage(parameter)
        if storage is None or storage not in caller_by_storage:
            return None
        caller_slot = caller_by_storage[storage]
        register, size = storage
        bindings.append(
            {
                "caller_parameter_slot": caller_slot,
                "target_parameter_slot": target_slot,
            }
        )
        binding_details.append(
            {
                "caller_parameter_slot": caller_slot,
                "target_parameter_slot": target_slot,
                "storage": f"{register}:{size}",
            }
        )
        preserved_registers.add(register)

    entry = parse_int(function.get("entry"))
    call_address = parse_int(call.get("instruction_address"))
    if entry is None or call_address is None or call_address < entry:
        return None
    caller_extents = index.memory.function_extents(entry)
    if len(caller_extents) != 1:
        return None
    thumb_mode = bool(int(caller_extents[0]["address"]) & 1)
    code = index.memory.executable_bytes(entry, call_address)
    if code is None:
        return None

    try:
        from capstone import (
            CS_ARCH_ARM,
            CS_GRP_CALL,
            CS_MODE_ARM,
            CS_MODE_BIG_ENDIAN,
            CS_MODE_LITTLE_ENDIAN,
            CS_MODE_THUMB,
            Cs,
        )
        from capstone.arm import ARM_OP_REG
    except ImportError:
        return None

    mode = CS_MODE_THUMB if thumb_mode else CS_MODE_ARM
    mode |= CS_MODE_LITTLE_ENDIAN if index.memory.byteorder == "little" else CS_MODE_BIG_ENDIAN
    disassembler = Cs(CS_ARCH_ARM, mode)
    disassembler.detail = True
    instructions = []
    expected_address = entry
    dispatch_instruction = None
    for instruction in disassembler.disasm(code, entry):
        if instruction.address != expected_address or instruction.address > call_address:
            return None
        instructions.append(instruction)
        expected_address = instruction.address + instruction.size
        if instruction.address == call_address:
            dispatch_instruction = instruction
            break
    if dispatch_instruction is None:
        return None
    if dispatch_instruction.mnemonic.lower() not in {"bx", "blx"}:
        return None
    if not any(operand.type == ARM_OP_REG for operand in dispatch_instruction.operands):
        return None

    for instruction in instructions[:-1]:
        if instruction.group(CS_GRP_CALL) or instruction.mnemonic.lower() in {"bl", "blx"}:
            return None
        _, written = instruction.regs_access()
        written_names = {instruction.reg_name(register).lower() for register in written}
        if written_names & preserved_registers:
            return None

    return bindings, {
        "kind": "machine_abi_actual_formal_identity",
        "architecture": index.memory.machine,
        "mode": "thumb" if thumb_mode else "arm",
        "analyzed_range": [hex_value(entry), hex_value(call_address)],
        "dispatch_instruction": {
            "address": hex_value(call_address),
            "mnemonic": dispatch_instruction.mnemonic,
            "operands": dispatch_instruction.op_str,
        },
        "preserved_registers": sorted(preserved_registers),
        "bindings": binding_details,
    }


def machine_register_provenance_identity(
    index: ProgramIndex,
    function: dict[str, Any],
    call: dict[str, Any],
    target_function: dict[str, Any],
) -> tuple[list[dict[str, int]], dict[str, Any]] | None:
    """Recover ARM actual/formal identity with bounded register provenance.

    High P-code may model registers preserved across a direct call as
    ``INDIRECT extraout`` values.  For a monolithic image we can check the
    concrete instructions instead: propagate only register-to-register moves,
    and at a direct call kill exactly the registers written by a leaf callee.
    Any nested/indirect callee or unsupported target makes the proof fail.
    """

    if index.memory.machine != "EM_ARM":
        return None
    caller_parameters = indexed_parameters(function)
    target_parameters = indexed_parameters(target_function)
    if caller_parameters is None or target_parameters is None:
        return None

    try:
        from capstone import (
            CS_ARCH_ARM,
            CS_GRP_CALL,
            CS_MODE_ARM,
            CS_MODE_BIG_ENDIAN,
            CS_MODE_LITTLE_ENDIAN,
            CS_MODE_THUMB,
            Cs,
        )
        from capstone.arm import ARM_OP_IMM, ARM_OP_REG
    except ImportError:
        return None

    def disassemble_extent(address: int) -> tuple[list[Any], str] | None:
        extents = index.memory.function_extents(address)
        if len(extents) != 1:
            return None
        extent = extents[0]
        start = int(extent["address"]) & ~1
        size = int(extent["size"])
        if size <= 0:
            return None
        raw = index.memory.executable_bytes(start, start + size - 1, trailer=1)
        if raw is None or len(raw) != size:
            return None
        mode_name = "thumb" if int(extent["address"]) & 1 else "arm"
        mode = CS_MODE_THUMB if mode_name == "thumb" else CS_MODE_ARM
        mode |= CS_MODE_LITTLE_ENDIAN if index.memory.byteorder == "little" else CS_MODE_BIG_ENDIAN
        decoder = Cs(CS_ARCH_ARM, mode)
        decoder.detail = True
        instructions = list(decoder.disasm(raw, start))
        if not instructions or sum(insn.size for insn in instructions) != size:
            return None
        return instructions, mode_name

    callee_writes_cache: dict[int, set[str] | None] = {}

    def leaf_callee_writes(address: int) -> set[str] | None:
        normalized = address & ~1
        if normalized in callee_writes_cache:
            return callee_writes_cache[normalized]
        decoded = disassemble_extent(address)
        if decoded is None:
            callee_writes_cache[normalized] = None
            return None
        instructions, _ = decoded
        writes: set[str] = set()
        for insn in instructions:
            if insn.group(CS_GRP_CALL) or insn.mnemonic.lower() in {"bl", "blx"}:
                callee_writes_cache[normalized] = None
                return None
            _, written = insn.regs_access()
            writes.update(insn.reg_name(register).lower() for register in written)
        callee_writes_cache[normalized] = writes
        return writes

    entry = parse_int(function.get("entry"))
    call_address = parse_int(call.get("instruction_address"))
    if entry is None or call_address is None:
        return None
    decoded = disassemble_extent(entry)
    if decoded is None:
        return None
    instructions, mode_name = decoded

    provenance: dict[str, int] = {}
    for slot, parameter in enumerate(caller_parameters):
        storage = register_storage(parameter)
        if storage is None:
            continue
        provenance[storage[0]] = slot
    evidence_steps: list[dict[str, Any]] = []
    dispatch_instruction = None
    for insn in instructions:
        if insn.address > call_address:
            break
        if insn.address == call_address:
            dispatch_instruction = insn
            break

        is_direct_call = insn.mnemonic.lower() == "bl" and any(
            operand.type == ARM_OP_IMM for operand in insn.operands
        )
        if is_direct_call:
            target = next(int(operand.imm) for operand in insn.operands if operand.type == ARM_OP_IMM)
            writes = leaf_callee_writes(target)
            if writes is None:
                return None
            killed = sorted(register for register in provenance if register in writes)
            for register in killed:
                provenance.pop(register, None)
            evidence_steps.append(
                {
                    "instruction": hex_value(insn.address),
                    "operation": "DIRECT_LEAF_CALL_CLOBBER",
                    "target": hex_value(target),
                    "killed_provenance": killed,
                }
            )
            continue

        _, written = insn.regs_access()
        written_names = {insn.reg_name(register).lower() for register in written}
        source_slot = None
        destination_register = None
        if (
            insn.mnemonic.lower().startswith("mov")
            and len(insn.operands) >= 2
            and insn.operands[0].type == ARM_OP_REG
            and insn.operands[1].type == ARM_OP_REG
        ):
            destination_register = insn.reg_name(insn.operands[0].reg).lower()
            source_register = insn.reg_name(insn.operands[1].reg).lower()
            source_slot = provenance.get(source_register)
        for register in written_names:
            provenance.pop(register, None)
        if destination_register is not None and source_slot is not None:
            provenance[destination_register] = source_slot
            evidence_steps.append(
                {
                    "instruction": hex_value(insn.address),
                    "operation": "REGISTER_IDENTITY_MOVE",
                    "destination": destination_register,
                    "caller_parameter_slot": source_slot,
                }
            )

    if dispatch_instruction is None or dispatch_instruction.mnemonic.lower() not in {"bx", "blx"}:
        return None
    bindings: list[dict[str, int]] = []
    details: list[dict[str, Any]] = []
    for target_slot, parameter in enumerate(target_parameters):
        storage = register_storage(parameter)
        if storage is None or storage[0] not in provenance:
            return None
        caller_slot = provenance[storage[0]]
        bindings.append(
            {"caller_parameter_slot": caller_slot, "target_parameter_slot": target_slot}
        )
        details.append(
            {
                "caller_parameter_slot": caller_slot,
                "target_parameter_slot": target_slot,
                "storage": f"{storage[0]}:{storage[1]}",
            }
        )
    return bindings, {
        "kind": "machine_register_provenance_actual_formal_identity",
        "architecture": index.memory.machine,
        "mode": mode_name,
        "dispatch_instruction": {
            "address": hex_value(call_address),
            "mnemonic": dispatch_instruction.mnemonic,
            "operands": dispatch_instruction.op_str,
        },
        "steps": evidence_steps,
        "bindings": details,
    }


def actual_formal_identity(
    index: ProgramIndex,
    function: dict[str, Any],
    trace: FunctionTrace,
    call: dict[str, Any],
    target_function: dict[str, Any],
) -> tuple[list[dict[str, int]], dict[str, Any]] | None:
    high_identity = high_pcode_actual_formal_identity(trace, call, target_function)
    if high_identity is not None:
        return high_identity
    if len(list(call.get("inputs", []) or [])) <= 1:
        machine_identity = machine_actual_formal_identity(
            index, function, call, target_function
        )
        if machine_identity is not None:
            return machine_identity
    machine_provenance = machine_register_provenance_identity(
        index,
        function,
        call,
        target_function,
    )
    if machine_provenance is not None:
        return machine_provenance
    return None


def _scaled_selector(
    trace: FunctionTrace,
    node: dict[str, Any],
) -> tuple[dict[str, Any], int, list[str]] | None:
    """Return ``(selector, scale, sites)`` for a non-constant scaled value."""

    current, sites = trace.unwrap(node)
    definition = trace.definition(current)
    if definition is None or str(definition.get("mnemonic", "")) != "INT_MULT":
        return None
    inputs = [dict(item or {}) for item in list(definition.get("inputs", []) or [])]
    if len(inputs) != 2:
        return None
    constants = [
        (position, trace.constant(item))
        for position, item in enumerate(inputs)
        if trace.constant(item) is not None
    ]
    if len(constants) != 1:
        return None
    constant_position, scale = constants[0]
    selector = inputs[1 - constant_position]
    if trace.constant(selector) is not None or scale is None:
        return None
    return selector, int(scale), sites + [str(definition.get("site_id", ""))]


def finite_initialized_table_access(
    index: ProgramIndex,
    trace: FunctionTrace,
    outer_load: dict[str, Any],
) -> tuple[FiniteTableAccess | None, str, bool]:
    """Recognize one finite initialized ``table[selector]`` target load.

    This evaluator is intentionally not a points-to analysis.  It accepts only
    a single immutable ELF object and an address in one of these equivalent
    High P-code forms::

        PTRADD(table_base, selector, constant_stride)
        INT_ADD(table_base, INT_MULT(selector, constant_stride))

    Constant pointer adjustments may wrap either form.  The ELF object extent,
    rather than a guessed selector range, supplies the finite enumeration
    boundary.  Function, table, and CVE names are never consulted.
    """

    load_inputs = [dict(item or {}) for item in list(outer_load.get("inputs", []) or [])]
    if len(load_inputs) < 2:
        return None, "target_load_has_no_address", False

    current, unwrap_sites = trace.unwrap(load_inputs[-1])
    address_sites = list(unwrap_sites)
    constant_offset = 0
    table_base_node: dict[str, Any] | None = None
    selector: dict[str, Any] | None = None
    stride: int | None = None
    indexed_shape_seen = False

    for _ in range(16):
        definition = trace.definition(current)
        if definition is None:
            break
        mnemonic = str(definition.get("mnemonic", ""))
        inputs = [dict(item or {}) for item in list(definition.get("inputs", []) or [])]
        site_id = str(definition.get("site_id", ""))

        if mnemonic == "PTRADD" and len(inputs) >= 3:
            scale = trace.constant(inputs[2])
            selector_constant = trace.constant(inputs[1])
            if scale is None:
                return None, "finite_table_stride_unresolved", True
            address_sites.append(site_id)
            if selector_constant is not None:
                constant_offset += int(selector_constant) * int(scale)
                current, extra = trace.unwrap(inputs[0])
                address_sites.extend(extra)
                continue
            indexed_shape_seen = True
            table_base_node = inputs[0]
            selector = inputs[1]
            stride = int(scale)
            break

        if mnemonic in {"INT_ADD", "PTRSUB"} and len(inputs) == 2:
            scaled = [
                (position, _scaled_selector(trace, item))
                for position, item in enumerate(inputs)
            ]
            scaled = [(position, row) for position, row in scaled if row is not None]
            if len(scaled) == 1:
                position, row = scaled[0]
                assert row is not None
                indexed_shape_seen = True
                selector, stride, scale_sites = row
                table_base_node = inputs[1 - position]
                address_sites.extend([site_id, *scale_sites])
                break

            constants = [
                (position, trace.constant(item))
                for position, item in enumerate(inputs)
                if trace.constant(item) is not None
            ]
            if len(constants) == 1:
                position, value = constants[0]
                constant_offset += int(value)
                address_sites.append(site_id)
                current, extra = trace.unwrap(inputs[1 - position])
                address_sites.extend(extra)
                continue
        break

    if not indexed_shape_seen or table_base_node is None or selector is None or stride is None:
        return None, "target_is_not_finite_indexed_table_load", False
    pointer_size = index.memory.pointer_size
    if stride < pointer_size or stride % pointer_size != 0:
        return None, "finite_table_stride_is_not_pointer_aligned", True

    # Address-tied High P-code nodes often denote a literal-pool slot rather
    # than the pointer value stored in that slot.  FunctionTrace.constant()
    # reads that initialized word; use it before the general pointer evaluator.
    constant_base = trace.constant(table_base_node)
    base_values = (
        [ReturnedPointerValue(int(constant_base))]
        if constant_base is not None
        else _merge_returned_pointer_values(
            _returned_pointer_values(index, trace, table_base_node)
        )
    )
    if len(base_values) != 1:
        return None, "finite_table_base_not_unique", True
    table_base = int(base_values[0].value)
    first_entry = table_base + constant_offset

    extents = [
        extent
        for extent in index.memory.symbol_extents("STT_OBJECT")
        if not bool(extent.get("writable"))
        and index.memory.extent_contains(extent, first_entry, pointer_size)
    ]
    region = index.memory.region_at(first_entry, pointer_size)
    # Section/symbol flags provide the object-level immutability proof.  MCU
    # linker scripts commonly place .text/.rodata in one RWX PT_LOAD segment,
    # so segment writability alone cannot reject an otherwise read-only object.
    if len(extents) != 1 or region is None:
        return None, "finite_table_immutable_object_not_unique", True

    selector_id = node_value_id(selector)
    selector_object_id = str(selector.get("object_id", ""))
    if not selector_id and not selector_object_id:
        return None, "finite_table_selector_identity_missing", True

    return (
        FiniteTableAccess(
            table_base=table_base,
            first_entry_address=first_entry,
            stride=stride,
            selector_value_id=selector_id,
            selector_object_id=selector_object_id,
            address_site_ids=tuple(
                sorted(
                    {
                        site
                        for site in [
                            str(outer_load.get("site_id", "")),
                            *address_sites,
                            *base_values[0].site_ids,
                        ]
                        if site
                    }
                )
            ),
            table_extent=dict(extents[0]),
        ),
        "",
        True,
    )


def _positional_argument_bindings(
    target_function: dict[str, Any] | None,
    actual_arguments: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Preserve CALLIND actuals and bind recovered formals by ABI position."""

    parameters = {
        int(parameter["index"]): dict(parameter)
        for parameter in list((target_function or {}).get("parameters", []) or [])
        if isinstance(parameter.get("index"), int)
    }
    rows: list[dict[str, Any]] = []
    for argument_index, actual in enumerate(actual_arguments):
        formal = parameters.get(argument_index, {})
        rows.append(
            {
                "argument_index": argument_index,
                "actual_value_id": node_value_id(actual),
                "actual_object_id": str(actual.get("object_id", "")),
                "target_parameter_slot": argument_index,
                "target_formal_object_id": str(formal.get("object_id", "")),
            }
        )
    return rows


def finite_initialized_function_table_resolution(
    index: ProgramIndex,
    trace: FunctionTrace,
    call: dict[str, Any],
    outer_load: dict[str, Any],
    *,
    max_targets: int = DEFAULT_MAX_FINITE_CALLIND_TARGETS,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, bool]:
    """Enumerate all executable targets of one immutable function table.

    One unique executable target is exact even when several slots alias that
    target.  Two through ``max_targets`` unique targets are emitted in full as
    MAY relations.  An over-budget set is never truncated or partially
    materialized; the returned blocker retains the complete target set.
    """

    access, reason, shape_seen = finite_initialized_table_access(
        index, trace, outer_load
    )
    if access is None:
        blocker = {"reason": reason} if shape_seen else None
        return [], blocker, shape_seen

    extent = access.table_extent
    extent_end = int(extent.get("end", 0))
    pointer_size = index.memory.pointer_size
    entries: list[dict[str, Any]] = []
    targets: dict[str, dict[str, Any]] = {}
    for entry_address in range(
        access.first_entry_address,
        extent_end - pointer_size + 1,
        access.stride,
    ):
        raw_target = index.memory.read_ptr(entry_address)
        if raw_target is None:
            continue
        verified = verified_elf_target(index, raw_target)
        entry = {
            "entry_address": hex_value(entry_address),
            "offset": entry_address - int(extent["address"]),
            "index": (
                (entry_address - access.first_entry_address) // access.stride
            ),
            "raw_target": hex_value(raw_target),
            "executable_target": verified is not None,
        }
        entries.append(entry)
        if verified is None:
            continue
        target, target_function, target_extent = verified
        target_id = str(target.get("function_id", ""))
        bucket = targets.setdefault(
            target_id,
            {
                "target": target,
                "target_function": target_function,
                "target_extent": target_extent,
                "slots": [],
            },
        )
        bucket["slots"].append(entry)

    ordered_targets = [targets[key] for key in sorted(targets)]
    candidate_count = len(ordered_targets)
    table_evidence = {
        "kind": "finite_initialized_function_table",
        "target_load_site_id": str(outer_load.get("site_id", "")),
        "address_site_ids": list(access.address_site_ids),
        "selector": {
            "value_id": access.selector_value_id,
            "object_id": access.selector_object_id,
        },
        "table_object": {
            "address": hex_value(int(extent["address"])),
            "size": int(extent["size"]),
            "section": str(extent.get("section", "")),
            "sources": list(extent.get("sources", []) or []),
            "writable": bool(extent.get("writable")),
        },
        "first_entry_address": hex_value(access.first_entry_address),
        "stride": access.stride,
        "scanned_entry_count": len(entries),
        "executable_target_count": candidate_count,
        "entries": entries,
    }

    if candidate_count == 0:
        return (
            [],
            {
                "reason": "finite_function_table_has_no_executable_targets",
                "evidence": table_evidence,
            },
            True,
        )
    if candidate_count > max(0, int(max_targets)):
        complete_candidates = [
            {
                "target": dict(row["target"]),
                "slots": list(row["slots"]),
            }
            for row in ordered_targets
        ]
        return (
            [],
            {
                "reason": "function_table_candidate_budget_exceeded",
                "budget": {
                    "kind": "finite_function_table_targets",
                    "limit": max(0, int(max_targets)),
                    "candidate_count": candidate_count,
                    "truncated": False,
                },
                "candidates": complete_candidates,
                "evidence": table_evidence,
            },
            True,
        )

    actual_arguments = [
        dict(item or {}) for item in list(call.get("inputs", []) or [])[1:]
    ]
    exact = candidate_count == 1
    rows: list[dict[str, Any]] = []
    for ordinal, candidate in enumerate(ordered_targets):
        target = dict(candidate["target"])
        target_function = dict(candidate["target_function"])
        rows.append(
            {
                "status": "resolved",
                "resolution": (
                    "EXACT_INDIRECT_TARGET"
                    if exact
                    else "FINITE_TABLE_MAY_TARGET"
                ),
                "resolution_kind": "finite_initialized_function_table",
                "recognition": "deterministic" if exact else "heuristic",
                "analysis_precision": "EXACT" if exact else "MAY",
                "candidate_set_id": (
                    f"finite-callind:{str(call.get('site_id', ''))}"
                ),
                "candidate_ordinal": ordinal,
                "candidate_count": candidate_count,
                "target": target,
                "table": {
                    "address": hex_value(int(extent["address"])),
                    "first_entry_address": hex_value(access.first_entry_address),
                    "stride": access.stride,
                    "symbols": list(extent.get("names", []) or []),
                    "elf_object": {
                        "size": int(extent["size"]),
                        "section": str(extent.get("section", "")),
                        "sources": list(extent.get("sources", []) or []),
                    },
                },
                "slots": list(candidate["slots"]),
                "original_actual_arguments": actual_arguments,
                "argument_bindings": _positional_argument_bindings(
                    target_function, actual_arguments
                ),
                "evidence": [table_evidence],
            }
        )
    return rows, None, True


def direct_table_candidate(
    index: ProgramIndex,
    trace: FunctionTrace,
    outer_load: dict[str, Any],
) -> dict[str, Any] | None:
    inputs = list(outer_load.get("inputs", []) or [])
    if len(inputs) < 2:
        return None
    entry_address = trace.constant(dict(inputs[-1]))
    if entry_address is None:
        return None
    raw_target = index.memory.read_ptr(entry_address)
    if raw_target is None:
        return None
    target = target_row(index, raw_target)
    if target is None:
        return None
    return {
        "target": target,
        "table": {
            "address": "",
            "source": "constant_slot_address",
        },
        "slot": {
            "entry_address": hex_value(entry_address),
            "offset": None,
            "index": None,
            "raw_target": hex_value(raw_target),
        },
        "device": None,
        "evidence": [
            {
                "kind": "high_pcode_target_load",
                "site_id": str(outer_load.get("site_id", "")),
                "entry_address": hex_value(entry_address),
            },
            {"kind": "initialized_table_slot", **index.memory.evidence(entry_address)},
        ],
    }


def direct_callee_return_access_candidates(
    index: ProgramIndex,
    trace: FunctionTrace,
    outer_load: dict[str, Any],
) -> tuple[list[dict[str, Any]], str, bool]:
    """Resolve initialized function slots reached through a direct return.

    The final LOAD address is evaluated through High P-code.  A candidate is
    admitted only when that proof includes a direct callee RETURN, the entry is
    contained by one immutable ELF object, and the initialized pointer names a
    unique executable ELF function.
    """

    inputs = [dict(item or {}) for item in list(outer_load.get("inputs", []) or [])]
    if len(inputs) < 2:
        return [], "target_load_has_no_address", False
    pointer_values = _returned_pointer_values(index, trace, inputs[-1])
    return_backed = [row for row in pointer_values if row.return_edges]
    if not return_backed:
        return [], "target_address_has_no_direct_callee_return", False

    rows: list[dict[str, Any]] = []
    for candidate in return_backed:
        entry_address = candidate.value
        table_extents = [
            extent
            for extent in index.memory.symbol_extents("STT_OBJECT")
            if not bool(extent.get("writable"))
            and index.memory.extent_contains(
                extent,
                entry_address,
                index.memory.pointer_size,
            )
        ]
        if len(table_extents) != 1:
            continue
        table_extent = table_extents[0]
        raw_target = index.memory.read_ptr(entry_address)
        if raw_target is None:
            continue
        verified_target = verified_elf_target(index, raw_target)
        if verified_target is None:
            continue
        target, _, target_extent = verified_target
        table_address = int(table_extent["address"])
        slot_offset = entry_address - table_address
        return_evidence = [
            {
                "callsite": callsite,
                "callee_function_id": callee_id,
                "callee_function": callee_name,
                "return_site_id": return_site,
            }
            for callsite, callee_id, callee_name, return_site in candidate.return_edges
        ]
        rows.append(
            {
                "target": target,
                "proof_scope": "callsite_context",
                "binding_scope": "context_only",
                "table": {
                    "address": hex_value(table_address),
                    "symbols": list(table_extent["names"]),
                    "elf_object": {
                        "size": int(table_extent["size"]),
                        "section": str(table_extent["section"]),
                        "sources": list(table_extent["sources"]),
                    },
                    "evidence": index.memory.evidence(entry_address),
                },
                "slot": {
                    "entry_address": hex_value(entry_address),
                    "offset": slot_offset,
                    "index": (
                        slot_offset // index.memory.pointer_size
                        if slot_offset % index.memory.pointer_size == 0
                        else None
                    ),
                    "raw_target": hex_value(raw_target),
                    "evidence": index.memory.evidence(entry_address),
                },
                "device": None,
                "evidence": [
                    {
                        "kind": "high_pcode_direct_callee_return_access_path",
                        "target_load_site_id": str(outer_load.get("site_id", "")),
                        "access_site_ids": list(candidate.site_ids),
                        "return_edges": return_evidence,
                    },
                    {
                        "kind": "initialized_elf_function_table_slot",
                        "table_object": {
                            "address": hex_value(table_address),
                            "size": int(table_extent["size"]),
                        },
                        "entry_address": hex_value(entry_address),
                        "raw_target": hex_value(raw_target),
                        "target_function_object": {
                            "address": hex_value(int(target_extent["address"])),
                            "size": int(target_extent["size"]),
                            "sources": list(target_extent["sources"]),
                        },
                    },
                ],
            }
        )

    unique: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            str((row.get("table") or {}).get("address", "")),
            str((row.get("slot") or {}).get("entry_address", "")),
            str((row.get("target") or {}).get("function_id", "")),
        )
        unique[key] = row
    return (
        [unique[key] for key in sorted(unique)],
        "initialized_return_access_target_not_uniquely_proven",
        True,
    )


def initialized_object_domain_return_candidates(
    index: ProgramIndex,
    function: dict[str, Any],
    trace: FunctionTrace,
    call: dict[str, Any],
    outer_load: dict[str, Any],
) -> tuple[list[dict[str, Any]], str, bool]:
    """Resolve a dynamic receiver from a unique initialized object domain.

    Some monolithic frameworks select an initialized protocol object through
    a runtime instance.  The direct callee still exposes an exact structural
    path, for example ``formal -> LOAD(+0) -> LOAD(+4)``, and CALLIND performs
    the final ``LOAD(+slot)``.  We evaluate that same path over every bounded
    initialized ELF object.  A target is admitted only when all matching roots
    agree on one executable function and High P-code proves actual/formal
    identity for that function.
    """

    inputs = [dict(item or {}) for item in list(outer_load.get("inputs", []) or [])]
    if len(inputs) < 2:
        return [], "target_load_has_no_address", False
    slot_form = trace.split_address(inputs[-1])
    if slot_form.base_node is None:
        return [], "target_slot_has_no_dynamic_receiver", False
    access_paths = _direct_return_access_paths(index, trace, slot_form.base_node)
    if not access_paths:
        return [], "target_address_has_no_symbolic_direct_return_path", False

    actual_call = trace.defining_call(slot_form.base_node)
    if actual_call is None:
        return [], "symbolic_return_call_not_recovered", True
    actual_inputs = [dict(item or {}) for item in list(actual_call.get("inputs", []) or [])][1:]
    rows: list[dict[str, Any]] = []
    for path in access_paths:
        if path.parameter_slot >= len(actual_inputs):
            continue
        offsets = path.dereference_offsets + (slot_form.offset,)
        if (
            not offsets
            or any(offset < 0 or offset % index.memory.pointer_size for offset in offsets)
        ):
            continue
        for root_extent in index.memory.symbol_extents("STT_OBJECT"):
            root_address = int(root_extent["address"])
            if not index.memory.extent_contains(
                root_extent,
                root_address + offsets[0],
                index.memory.pointer_size,
            ):
                continue
            current = root_address
            walk: list[dict[str, Any]] = []
            valid = True
            for position, offset in enumerate(offsets):
                field_address = current + offset
                value = index.memory.read_ptr(field_address)
                if value is None:
                    valid = False
                    break
                walk.append(
                    {
                        "position": position,
                        "base": hex_value(current),
                        "offset": offset,
                        "field_address": hex_value(field_address),
                        "loaded_value": hex_value(value),
                        "evidence": index.memory.evidence(field_address),
                    }
                )
                current = value
            if not valid:
                continue
            verified_target = verified_elf_target(index, current)
            if verified_target is None:
                continue
            target, target_function, target_extent = verified_target
            identity = actual_formal_identity(index, function, trace, call, target_function)
            if identity is None:
                continue
            formal_bindings, identity_evidence = identity
            rows.append(
                {
                    "target": target,
                    "proof_scope": "initialized_object_domain",
                    "binding_scope": "callsite_context",
                    "table": {
                        "address": walk[-1]["base"],
                        "symbols": index.symbol_names(parse_int(walk[-1]["base"]) or 0),
                        "source": "initialized_object_access_path",
                    },
                    "slot": {
                        "entry_address": walk[-1]["field_address"],
                        "offset": slot_form.offset,
                        "index": slot_form.offset // index.memory.pointer_size,
                        "raw_target": hex_value(current),
                        "evidence": walk[-1]["evidence"],
                    },
                    "device": {
                        "address": hex_value(root_address),
                        "symbols": list(root_extent["names"]),
                        "elf_object": {
                            "size": int(root_extent["size"]),
                            "section": str(root_extent["section"]),
                            "sources": list(root_extent["sources"]),
                        },
                    },
                    "formal_identity_bindings": formal_bindings,
                    "evidence": [
                        {
                            "kind": "high_pcode_symbolic_direct_return_access_path",
                            "target_load_site_id": str(outer_load.get("site_id", "")),
                            "return_parameter_slot": path.parameter_slot,
                            "dereference_offsets": list(offsets),
                            "access_site_ids": list(path.site_ids),
                            "return_edges": [
                                {
                                    "callsite": edge[0],
                                    "callee_function_id": edge[1],
                                    "callee_function": edge[2],
                                    "return_site_id": edge[3],
                                }
                                for edge in path.return_edges
                            ],
                        },
                        {
                            "kind": "initialized_object_pointer_walk",
                            "root_object": {
                                "address": hex_value(root_address),
                                "size": int(root_extent["size"]),
                                "section": str(root_extent["section"]),
                            },
                            "walk": walk,
                            "target_function_object": {
                                "address": hex_value(int(target_extent["address"])),
                                "size": int(target_extent["size"]),
                                "sources": list(target_extent["sources"]),
                            },
                        },
                        identity_evidence,
                    ],
                }
            )

    # Multiple runtime objects that select the same function do not make the
    # CALL target ambiguous.  Keep every root as evidence on one target row.
    by_target: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_target.setdefault(str((row.get("target") or {}).get("function_id", "")), []).append(row)
    merged: list[dict[str, Any]] = []
    for target_id in sorted(by_target):
        target_rows = by_target[target_id]
        representative = dict(target_rows[0])
        representative["initialized_object_domain"] = [
            {
                "device": row.get("device"),
                "table": row.get("table"),
                "slot": row.get("slot"),
            }
            for row in target_rows
        ]
        merged.append(representative)
    return merged, "initialized_object_domain_target_not_unique", True


def stored_lookup_bindings(
    index: ProgramIndex,
    storage_address: int,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for function in index.functions:
        trace = FunctionTrace(index, function)
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "STORE":
                continue
            inputs = list(op.get("inputs", []) or [])
            if len(inputs) < 3 or trace.constant(dict(inputs[-2])) != storage_address:
                continue
            call = trace.defining_call(dict(inputs[-1]))
            if call is None:
                continue
            string_arguments: list[dict[str, Any]] = []
            for slot, argument in enumerate(list(call.get("inputs", []) or [])[1:]):
                address = trace.constant(dict(argument))
                if address is None:
                    continue
                text = index.memory.read_cstring(address)
                if text is not None:
                    string_arguments.append(
                        {
                            "parameter_slot": slot,
                            "address": address,
                            "value": text,
                            "object_id": str(argument.get("object_id", "")),
                            "value_id": node_value_id(dict(argument)),
                        }
                    )
            for string_argument in string_arguments:
                rows.append(
                    {
                        "function": function,
                        "store": op,
                        "call": call,
                        "name": string_argument,
                    }
                )
    return rows


def candidate_device_objects(
    index: ProgramIndex,
    *,
    name_address: int,
    name_value: str,
    api_field_offset: int,
    slot_offset: int,
    binding: dict[str, Any],
) -> list[dict[str, Any]]:
    def object_bases(field_address: int) -> list[tuple[int, int]]:
        # An exact ELF data symbol is a stronger object boundary than nearby
        # pointer-shaped bytes.  Prefer that boundary to avoid cross-products
        # between adjacent linker-generated device/config objects.
        if index.symbol_names(field_address):
            return [(field_address, 0)]
        return index.object_bases(field_address)

    rows: list[dict[str, Any]] = []
    for name_ref in index.memory.pointer_references(name_address):
        for config_address, name_field_offset in object_bases(int(name_ref["address"])):
            for config_ref in index.memory.pointer_references(config_address):
                for device_address, config_field_offset in object_bases(int(config_ref["address"])):
                    table_address = index.memory.read_ptr(device_address + api_field_offset)
                    if table_address is None:
                        continue
                    entry_address = table_address + slot_offset
                    raw_target = index.memory.read_ptr(entry_address)
                    if raw_target is None:
                        continue
                    target = target_row(index, raw_target)
                    if target is None:
                        continue
                    rows.append(
                        {
                            "target": target,
                            "table": {
                                "address": hex_value(table_address),
                                "api_field_offset": api_field_offset,
                                "symbols": index.symbol_names(table_address),
                                "evidence": index.memory.evidence(device_address + api_field_offset),
                            },
                            "slot": {
                                "entry_address": hex_value(entry_address),
                                "offset": slot_offset,
                                "index": (
                                    slot_offset // index.memory.pointer_size
                                    if slot_offset % index.memory.pointer_size == 0
                                    else None
                                ),
                                "raw_target": hex_value(raw_target),
                                "evidence": index.memory.evidence(entry_address),
                            },
                            "device": {
                                "address": hex_value(device_address),
                                "symbols": index.symbol_names(device_address),
                                "config_address": hex_value(config_address),
                                "config_symbols": index.symbol_names(config_address),
                                "config_field_offset": config_field_offset,
                                "name_field_offset": name_field_offset,
                                "name_address": hex_value(name_address),
                                "name": name_value,
                            },
                            "evidence": [
                                {
                                    "kind": "named_device_binding_store",
                                    "store_site_id": str(binding["store"].get("site_id", "")),
                                    "lookup_callsite": str(binding["call"].get("site_id", "")),
                                    "lookup_target_function_id": str(
                                        (binding["call"].get("call") or {}).get("target_function_id", "")
                                    ),
                                    "name_argument_slot": binding["name"]["parameter_slot"],
                                },
                                {
                                    "kind": "initialized_config_name_reference",
                                    "reference_address": hex_value(int(name_ref["address"])),
                                    "name_address": hex_value(name_address),
                                    "name": name_value,
                                    "source": name_ref.get("source", ""),
                                },
                                {
                                    "kind": "initialized_device_config_reference",
                                    "reference_address": hex_value(int(config_ref["address"])),
                                    "config_address": hex_value(config_address),
                                    "source": config_ref.get("source", ""),
                                },
                                {
                                    "kind": "initialized_api_table_slot",
                                    "table_address": hex_value(table_address),
                                    "slot_offset": slot_offset,
                                    "entry_address": hex_value(entry_address),
                                    "raw_target": hex_value(raw_target),
                                },
                            ],
                        }
                    )
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            str((row.get("device") or {}).get("address", "")),
            str((row.get("device") or {}).get("config_address", "")),
            str((row.get("table") or {}).get("address", "")),
            str((row.get("target") or {}).get("function_id", "")),
        )
        unique[key] = row
    return [unique[key] for key in sorted(unique)]


def device_dispatch_candidates(
    index: ProgramIndex,
    trace: FunctionTrace,
    outer_load: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    outer_inputs = list(outer_load.get("inputs", []) or [])
    if len(outer_inputs) < 2:
        return [], "target_load_has_no_address"
    slot_form = trace.split_address(dict(outer_inputs[-1]))
    if slot_form.base_node is None:
        return [], "target_slot_has_no_api_pointer"
    api_load_result = trace.find_load(slot_form.base_node)
    if api_load_result is None:
        return [], "api_pointer_is_not_loaded_from_device"
    api_load, api_unwrap_sites = api_load_result
    api_inputs = list(api_load.get("inputs", []) or [])
    if len(api_inputs) < 2:
        return [], "api_pointer_load_has_no_address"
    api_form = trace.split_address(dict(api_inputs[-1]))
    if api_form.base_node is None:
        return [], "device_expression_has_no_base"
    device_load_result = trace.find_load(api_form.base_node)
    if device_load_result is None:
        return [], "device_pointer_is_not_loaded_from_storage"
    device_load, device_unwrap_sites = device_load_result
    device_inputs = list(device_load.get("inputs", []) or [])
    if len(device_inputs) < 2:
        return [], "device_pointer_load_has_no_address"
    storage_address = trace.constant(dict(device_inputs[-1]))
    if storage_address is None:
        return [], "device_storage_address_unresolved"

    bindings = stored_lookup_bindings(index, storage_address)
    if not bindings:
        return [], "device_storage_has_no_constant_name_binding"
    candidates: list[dict[str, Any]] = []
    for binding in bindings:
        name_address = int(binding["name"]["address"])
        name_value = str(binding["name"]["value"])
        for row in candidate_device_objects(
            index,
            name_address=name_address,
            name_value=name_value,
            api_field_offset=api_form.offset,
            slot_offset=slot_form.offset,
            binding=binding,
        ):
            row["device"]["storage_address"] = hex_value(storage_address)
            row["device"]["storage_symbols"] = index.symbol_names(storage_address)
            row["evidence"].insert(
                0,
                {
                    "kind": "high_pcode_device_dispatch_load_chain",
                    "target_load_site_id": str(outer_load.get("site_id", "")),
                    "api_load_site_id": str(api_load.get("site_id", "")),
                    "device_load_site_id": str(device_load.get("site_id", "")),
                    "slot_address_sites": list(slot_form.site_ids),
                    "api_address_sites": list(api_form.site_ids),
                    "api_unwrap_sites": api_unwrap_sites,
                    "device_unwrap_sites": device_unwrap_sites,
                    "api_field_offset": api_form.offset,
                    "slot_offset": slot_form.offset,
                    "storage_address": hex_value(storage_address),
                },
            )
            candidates.append(row)
    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in candidates:
        key = (
            str((row.get("device") or {}).get("address", "")),
            str((row.get("device") or {}).get("config_address", "")),
            str((row.get("table") or {}).get("address", "")),
            str((row.get("target") or {}).get("function_id", "")),
        )
        unique[key] = row
    return [unique[key] for key in sorted(unique)], "device_candidates_not_unique_or_missing"


def elf_pointer_references(memory: InitializedMemory, value: int) -> list[dict[str, Any]]:
    return [
        row
        for row in memory.pointer_references(value)
        if str(row.get("source", "")).startswith("elf:")
    ]


def function_pointer_references(
    memory: InitializedMemory,
    raw_target: int,
) -> list[dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    for value in {raw_target, raw_target & ~1, (raw_target & ~1) | 1}:
        for row in elf_pointer_references(memory, value):
            rows[int(row["address"])] = {**row, "value": value}
    return [rows[address] for address in sorted(rows)]


def target_binding_scope(
    index: ProgramIndex,
    *,
    raw_target: int,
    device_address: int,
    api_field_offset: int,
    table_extent: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    """Decide whether one receiver constant is valid for the whole target."""

    table_address = int(table_extent["address"])
    target_refs = function_pointer_references(index.memory, raw_target)
    explained_target_refs = [
        row
        for row in target_refs
        if index.memory.extent_contains(
            table_extent,
            int(row["address"]),
            index.memory.pointer_size,
        )
    ]
    table_refs = elf_pointer_references(index.memory, table_address)
    receiver_field = device_address + api_field_offset
    explained_table_refs = [
        row for row in table_refs if int(row["address"]) == receiver_field
    ]
    function_scope = (
        bool(target_refs)
        and len(explained_target_refs) == len(target_refs)
        and bool(table_refs)
        and len(explained_table_refs) == len(table_refs)
    )
    return function_scope, {
        "kind": "elf_target_reference_scope",
        "receiver_configuration": {
            "device_address": hex_value(device_address),
            "api_field_offset": api_field_offset,
            "table_address": hex_value(table_address),
        },
        "target_references": [hex_value(int(row["address"])) for row in target_refs],
        "explained_target_references": [
            hex_value(int(row["address"])) for row in explained_target_refs
        ],
        "table_references": [hex_value(int(row["address"])) for row in table_refs],
        "explained_table_references": [
            hex_value(int(row["address"])) for row in explained_table_refs
        ],
        "all_references_same_receiver_configuration": function_scope,
    }


def formal_dispatch_candidates(
    index: ProgramIndex,
    function: dict[str, Any],
    trace: FunctionTrace,
    call: dict[str, Any],
    outer_load: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    """Resolve a formal receiver only from ELF objects and value identity."""

    outer_inputs = list(outer_load.get("inputs", []) or [])
    if len(outer_inputs) < 2:
        return [], "target_load_has_no_address"
    slot_form = trace.split_address(dict(outer_inputs[-1]))
    if slot_form.base_node is None:
        return [], "target_slot_has_no_api_pointer"
    api_load_result = trace.find_load(slot_form.base_node)
    if api_load_result is None:
        return [], "api_pointer_is_not_loaded_from_device"
    api_load, api_unwrap_sites = api_load_result
    api_inputs = list(api_load.get("inputs", []) or [])
    if len(api_inputs) < 2:
        return [], "api_pointer_load_has_no_address"
    api_form = trace.split_address(dict(api_inputs[-1]))
    if api_form.base_node is None:
        return [], "api_pointer_has_no_device_base"
    wrapper_parameter_slot = node_parameter_slot(api_form.base_node)
    if wrapper_parameter_slot is None:
        return [], "device_base_is_not_a_formal_parameter"
    if (
        api_form.offset < 0
        or slot_form.offset < 0
        or api_form.offset % index.memory.pointer_size
        or slot_form.offset % index.memory.pointer_size
    ):
        return [], "device_or_slot_offset_is_not_pointer_aligned"

    candidates: list[dict[str, Any]] = []
    structural_candidate_seen = False
    for device_extent in index.memory.symbol_extents("STT_OBJECT"):
        if bool(device_extent.get("writable")):
            continue
        device_address = int(device_extent["address"])
        api_field_address = device_address + api_form.offset
        if not index.memory.extent_contains(
            device_extent,
            api_field_address,
            index.memory.pointer_size,
        ):
            continue
        table_address = index.memory.read_ptr(api_field_address)
        if table_address is None:
            continue
        for table_extent in index.memory.exact_object_extents(table_address):
            if bool(table_extent.get("writable")):
                continue
            entry_address = table_address + slot_form.offset
            if not index.memory.extent_contains(
                table_extent,
                entry_address,
                index.memory.pointer_size,
            ):
                continue
            raw_target = index.memory.read_ptr(entry_address)
            if raw_target is None:
                continue
            verified_target = verified_elf_target(index, raw_target)
            if verified_target is None:
                continue
            structural_candidate_seen = True
            target, target_function, target_extent = verified_target
            identity = actual_formal_identity(
                index,
                function,
                trace,
                call,
                target_function,
            )
            if identity is None:
                continue
            formal_identity_bindings, identity_evidence = identity
            receiver_target_slots = [
                int(binding["target_parameter_slot"])
                for binding in formal_identity_bindings
                if int(binding["caller_parameter_slot"]) == wrapper_parameter_slot
            ]
            if len(receiver_target_slots) != 1:
                continue
            receiver_target_slot = receiver_target_slots[0]

            initialized_fields = []
            field_limit = min(int(device_extent["size"]), 64)
            for offset in range(0, field_limit, index.memory.pointer_size):
                value = index.memory.read_ptr(device_address + offset)
                if value is None:
                    continue
                initialized_fields.append(
                    {
                        "offset": offset,
                        "address": hex_value(device_address + offset),
                        "value": hex_value(value),
                        "symbols": index.symbol_names(value),
                    }
                )

            function_scope, scope_evidence = target_binding_scope(
                index,
                raw_target=raw_target,
                device_address=device_address,
                api_field_offset=api_form.offset,
                table_extent=table_extent,
            )
            row: dict[str, Any] = {
                "target": target,
                "proof_scope": (
                    "all_elf_function_pointer_references"
                    if function_scope
                    else "callsite_context"
                ),
                "binding_scope": "target_function" if function_scope else "context_only",
                "table": {
                    "address": hex_value(table_address),
                    "api_field_offset": api_form.offset,
                    "symbols": list(table_extent["names"]),
                    "elf_object": {
                        "size": int(table_extent["size"]),
                        "section": str(table_extent["section"]),
                        "sources": list(table_extent["sources"]),
                    },
                    "evidence": index.memory.evidence(api_field_address),
                },
                "slot": {
                    "entry_address": hex_value(entry_address),
                    "offset": slot_form.offset,
                    "index": slot_form.offset // index.memory.pointer_size,
                    "raw_target": hex_value(raw_target),
                    "evidence": index.memory.evidence(entry_address),
                },
                "device": {
                    "address": hex_value(device_address),
                    "symbols": list(device_extent["names"]),
                    "elf_object": {
                        "size": int(device_extent["size"]),
                        "section": str(device_extent["section"]),
                        "sources": list(device_extent["sources"]),
                    },
                    "initialized_pointer_fields": initialized_fields,
                },
                "formal_identity_bindings": formal_identity_bindings,
                "evidence": [
                    {
                        "kind": "high_pcode_formal_device_dispatch_load_chain",
                        "target_load_site_id": str(outer_load.get("site_id", "")),
                        "api_load_site_id": str(api_load.get("site_id", "")),
                        "slot_address_sites": list(slot_form.site_ids),
                        "api_address_sites": list(api_form.site_ids),
                        "api_unwrap_sites": api_unwrap_sites,
                        "api_field_offset": api_form.offset,
                        "slot_offset": slot_form.offset,
                        "device_parameter_slot": wrapper_parameter_slot,
                    },
                    {
                        "kind": "elf_device_object_api_table_slot",
                        "device_object": {
                            "address": hex_value(device_address),
                            "size": int(device_extent["size"]),
                        },
                        "api_table_object": {
                            "address": hex_value(table_address),
                            "size": int(table_extent["size"]),
                        },
                        "slot_address": hex_value(entry_address),
                        "raw_target": hex_value(raw_target),
                        "target_function_object": {
                            "address": hex_value(int(target_extent["address"])),
                            "size": int(target_extent["size"]),
                            "sources": list(target_extent["sources"]),
                        },
                    },
                    identity_evidence,
                    scope_evidence,
                ],
            }
            if function_scope:
                row["target_formal_constant_bindings"] = [
                    {
                        "target_parameter_slot": receiver_target_slot,
                        "value": hex_value(device_address),
                        "source": "all_elf_target_references_same_receiver_configuration",
                        "binding_scope": "target_function",
                    }
                ]
            candidates.append(row)

    unique: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in candidates:
        key = (
            str((row.get("device") or {}).get("address", "")),
            str((row.get("table") or {}).get("address", "")),
            str((row.get("slot") or {}).get("entry_address", "")),
            str((row.get("target") or {}).get("function_id", "")),
        )
        unique[key] = row
    reason = (
        "actual_formal_identity_not_proven"
        if structural_candidate_seen
        else "elf_device_api_slot_target_not_proven"
    )
    return [unique[key] for key in sorted(unique)], reason


def resolve_device_dispatches(
    program_facts: dict[str, Any],
    *,
    initialized_memory: InitializedMemory | None = None,
    max_expensive_fallbacks: int | None = DEFAULT_MAX_EXPENSIVE_FALLBACKS,
    max_finite_callind_targets: int = DEFAULT_MAX_FINITE_CALLIND_TARGETS,
) -> dict[str, Any]:
    memory = initialized_memory or InitializedMemory()
    memory.add_program_facts_literals(program_facts)
    index = ProgramIndex(program_facts, memory)
    dispatches: list[dict[str, Any]] = []
    expensive_fallbacks = 0
    callind_sites = 0

    def narrow_formal_dispatch_by_abi(
        wrapper: dict[str, Any], rows: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Discard initialized-table targets incompatible with a thin wrapper ABI.

        Formal device dispatch scans deliberately start from every initialized
        device object because the receiver itself is a parameter.  That domain
        can contain unrelated API tables whose slot zero happens to hold an
        executable pointer.  When the wrapper forwards every recovered formal
        unchanged, the target must expose the same fixed-arity interface.  This
        is a type/ABI constraint, not a function-name or device-name rule.
        """

        wrapper_parameters = list(wrapper.get("parameters", []) or [])
        wrapper_arity = len(wrapper_parameters)
        if wrapper_arity == 0:
            return rows
        expected_slots = set(range(wrapper_arity))
        compatible: list[dict[str, Any]] = []
        for row in rows:
            target_id = str((row.get("target") or {}).get("function_id", ""))
            target = index.by_function_id.get(target_id)
            target_parameters = list((target or {}).get("parameters", []) or [])
            if len(target_parameters) != wrapper_arity:
                continue
            bindings = list(row.get("formal_identity_bindings", []) or [])
            caller_slots = {
                int(binding["caller_parameter_slot"])
                for binding in bindings
                if isinstance(binding.get("caller_parameter_slot"), int)
            }
            target_slots = {
                int(binding["target_parameter_slot"])
                for binding in bindings
                if isinstance(binding.get("target_parameter_slot"), int)
            }
            if caller_slots != expected_slots or target_slots != expected_slots:
                continue
            narrowed = dict(row)
            narrowed["evidence"] = list(row.get("evidence", []) or []) + [{
                "kind": "fixed_arity_actual_formal_abi_compatibility",
                "wrapper_parameter_count": wrapper_arity,
                "target_parameter_count": len(target_parameters),
                "forwarded_caller_slots": sorted(caller_slots),
                "forwarded_target_slots": sorted(target_slots),
            }]
            compatible.append(narrowed)
        return compatible or rows

    for function in index.functions:
        trace = FunctionTrace(index, function)
        for op in list(function.get("pcode_ops", []) or []):
            if str(op.get("mnemonic", "")) != "CALLIND":
                continue
            callind_sites += 1
            base = {"callsite": callsite_row(function, op)}
            inputs = list(op.get("inputs", []) or [])
            if not inputs:
                dispatches.append({**base, "status": "unresolved", "reason": "callind_has_no_target"})
                continue
            load_result = trace.find_load(dict(inputs[0]))
            if load_result is None:
                dispatches.append(
                    {**base, "status": "unresolved", "reason": "target_is_not_a_table_load"}
                )
                continue
            outer_load, unwrap_sites = load_result

            direct = direct_table_candidate(index, trace, outer_load)
            if direct is not None:
                direct["evidence"].insert(
                    0,
                    {
                        "kind": "high_pcode_callind",
                        "site_id": str(op.get("site_id", "")),
                        "target_unwrap_sites": unwrap_sites,
                    },
                )
                dispatches.append({**base, "status": "resolved", "resolution_kind": "constant_api_table", **direct})
                continue

            finite_rows, finite_blocker, finite_shape_seen = (
                finite_initialized_function_table_resolution(
                    index,
                    trace,
                    op,
                    outer_load,
                    max_targets=max_finite_callind_targets,
                )
            )

            if (
                max_expensive_fallbacks is not None
                and expensive_fallbacks >= max(0, int(max_expensive_fallbacks))
            ):
                if finite_rows:
                    dispatches.extend({**base, **row} for row in finite_rows)
                    continue
                if finite_shape_seen and finite_blocker is not None:
                    dispatches.append(
                        {
                            **base,
                            "status": "unresolved",
                            **finite_blocker,
                            "blocker": finite_blocker,
                        }
                    )
                    continue
                dispatches.append({
                    **base,
                    "status": "unresolved",
                    "reason": "expensive_resolution_budget_exhausted",
                    "budget": {
                        "kind": "whole_object_domain_fallbacks",
                        "limit": max(0, int(max_expensive_fallbacks)),
                    },
                })
                continue
            expensive_fallbacks += 1

            candidates, reason = device_dispatch_candidates(index, trace, outer_load)
            resolution_kind = "named_device_initialized_api_table"
            ambiguity_reason = "multiple_initialized_device_candidates"
            if not candidates:
                formal_candidates, formal_reason = formal_dispatch_candidates(
                    index, function, trace, op, outer_load
                )
                if formal_candidates:
                    candidates = narrow_formal_dispatch_by_abi(
                        function, formal_candidates
                    )
                    reason = formal_reason
                    resolution_kind = "elf_formal_device_api_table"
                elif formal_reason != "device_base_is_not_a_formal_parameter":
                    reason = formal_reason
            if not candidates:
                return_candidates, return_reason, return_path_seen = (
                    direct_callee_return_access_candidates(index, trace, outer_load)
                )
                if return_candidates:
                    candidates = return_candidates
                    reason = return_reason
                    resolution_kind = "direct_callee_return_initialized_table"
                    ambiguity_reason = "multiple_initialized_return_access_candidates"
                elif return_path_seen:
                    reason = return_reason
            if not candidates:
                domain_candidates, domain_reason, domain_path_seen = (
                    initialized_object_domain_return_candidates(
                        index,
                        function,
                        trace,
                        op,
                        outer_load,
                    )
                )
                if domain_candidates:
                    candidates = domain_candidates
                    reason = domain_reason
                    resolution_kind = "initialized_object_domain_return_table"
                    ambiguity_reason = "multiple_initialized_object_domain_targets"
                elif domain_path_seen:
                    reason = domain_reason
            if len(candidates) == 1:
                dispatches.append(
                    {
                        **base,
                        "status": "resolved",
                        "resolution_kind": resolution_kind,
                        **candidates[0],
                    }
                )
            elif len(candidates) > 1:
                dispatches.append(
                    {
                        **base,
                        "status": "ambiguous",
                        "reason": ambiguity_reason,
                        "candidates": candidates,
                    }
                )
            elif finite_rows:
                dispatches.extend({**base, **row} for row in finite_rows)
            elif finite_shape_seen and finite_blocker is not None:
                dispatches.append(
                    {
                        **base,
                        "status": "unresolved",
                        **finite_blocker,
                        "blocker": finite_blocker,
                    }
                )
            else:
                dispatches.append({**base, "status": "unresolved", "reason": reason})

    resolved = [row for row in dispatches if row["status"] == "resolved"]
    ambiguous = [row for row in dispatches if row["status"] == "ambiguous"]
    unresolved = [row for row in dispatches if row["status"] == "unresolved"]
    return {
        "schema_version": SCHEMA_VERSION,
        "binary": program_facts.get("binary", ""),
        "binary_sha256": program_facts.get("binary_sha256", ""),
        "analysis_budget": {
            "max_expensive_fallbacks": max_expensive_fallbacks,
            "expensive_fallbacks_attempted": expensive_fallbacks,
        },
        "counts": {
            "callind": callind_sites,
            "resolved": len(resolved),
            "ambiguous": len(ambiguous),
            "unresolved": len(unresolved),
        },
        "resolved": resolved,
        "ambiguous": ambiguous,
        "unresolved": unresolved,
        "dispatches": dispatches,
    }


def load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("ProgramFacts must be a JSON object")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program-facts", type=Path, required=True)
    parser.add_argument("--elf", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--max-expensive-fallbacks",
        type=int,
        default=DEFAULT_MAX_EXPENSIVE_FALLBACKS,
        help=(
            "Maximum non-constant-table CALLIND sites that may use the "
            "whole-object-domain fallback; negative means unlimited."
        ),
    )
    parser.add_argument(
        "--max-finite-callind-targets",
        type=int,
        default=DEFAULT_MAX_FINITE_CALLIND_TARGETS,
        help=(
            "Maximum complete executable target set materialized for one "
            "finite initialized function-table CALLIND (default: 32)."
        ),
    )
    args = parser.parse_args(argv)

    facts = load_json(args.program_facts)
    elf_path = args.elf
    if elf_path is None:
        candidate = Path(str(facts.get("binary", "")))
        elf_path = candidate if str(candidate) and candidate.is_file() else None
    memory = InitializedMemory.from_elf(elf_path) if elf_path is not None else InitializedMemory()
    budget = (
        None
        if args.max_expensive_fallbacks < 0
        else args.max_expensive_fallbacks
    )
    result = resolve_device_dispatches(
        facts,
        initialized_memory=memory,
        max_expensive_fallbacks=budget,
        max_finite_callind_targets=max(0, args.max_finite_callind_targets),
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
