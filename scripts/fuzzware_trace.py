#!/usr/bin/env python3
"""Parse standard Fuzzware traces and classify repeated validation runs.

This module consumes Fuzzware's existing MMIO and basic-block trace formats. It
does not instrument or otherwise modify Fuzzware.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Literal, Mapping, Sequence, TextIO, TypeAlias, overload


POC = "POC"
INCONCLUSIVE = "INCONCLUSIVE"


class TraceParseError(ValueError):
    """Raised when a nonempty trace line does not match the Fuzzware format."""


@dataclass(frozen=True, slots=True)
class MMIOEvent:
    event_id: int
    pc: int
    lr: int
    mode: Literal["r", "w"]
    access_size: int
    fuzz_index: int
    consumed_bytes: int
    address: int
    value: int


@dataclass(frozen=True, slots=True)
class BBEvent:
    event_id: int
    bb_addr: int
    count: int

    @property
    def address(self) -> int:
        """Return the basic-block entry address."""
        return self.bb_addr


@dataclass(frozen=True, slots=True)
class RAMEvent:
    event_id: int
    pc: int
    lr: int
    mode: Literal["r", "w"]
    access_size: int
    address: int
    value: int


@dataclass(frozen=True, slots=True)
class FaultEvidence:
    kind: str
    pc: int
    address: int
    signature: str


@dataclass(frozen=True, slots=True)
class TraceRun:
    mmio_events: tuple[MMIOEvent, ...]
    bb_events: tuple[BBEvent, ...]
    runtime_fault_signature: str | None = None


@dataclass(frozen=True, slots=True)
class ReplayEvidence:
    source_observed: bool
    sink_observed: bool
    fault_signature: str | None


TraceEvent: TypeAlias = MMIOEvent | BBEvent | RAMEvent
TraceSource: TypeAlias = str | os.PathLike[str] | TextIO | Iterable[str]
BlockInterval: TypeAlias = int | tuple[int, int] | range
BlockIntervals: TypeAlias = Mapping[int, BlockInterval]
ReplayRow: TypeAlias = ReplayEvidence | Mapping[str, object]


_MMIO_LINE = re.compile(
    r"^(?P<event_id>[0-9a-fA-F]+):\s+"
    r"(?P<pc>(?:0x)?[0-9a-fA-F]+)\s+"
    r"(?P<lr>(?:0x)?[0-9a-fA-F]+)\s+"
    r"(?P<mode>[rw])\s+"
    r"(?P<access_size>[0-9]+)\s+"
    r"(?P<fuzz_index>[0-9]+)\s+"
    r"(?P<consumed_bytes>[0-9]+)\s+"
    r"(?P<address>0x[0-9a-fA-F]+):(?P<value>(?:0x)?[0-9a-fA-F]+)$"
)
_BB_LINE = re.compile(
    r"^(?P<event_id>[0-9a-fA-F]+)\s+"
    r"(?P<bb_addr>(?:0x)?[0-9a-fA-F]+)\s+"
    r"(?P<count>[0-9]+)$"
)
_RAM_LINE = re.compile(
    r"^(?P<event_id>[0-9a-fA-F]+):\s+"
    r"(?P<pc>(?:0x)?[0-9a-fA-F]+)\s+"
    r"(?P<lr>(?:0x)?[0-9a-fA-F]+)\s+"
    r"(?P<mode>[rw])\s+"
    r"(?P<access_size>[0-9]+)\s+"
    r"(?P<address>0x[0-9a-fA-F]+):(?P<value>(?:0x)?[0-9a-fA-F]+)"
    r"(?:\s+(?:0x)?[0-9a-fA-F]+)?$"
)
_INVALID_ACCESS = re.compile(
    r"\[\s*(?P<pc>0x[0-9a-f]+)\s*\]\s+INVALID\s+"
    r"(?P<kind>WRITE|READ|FETCH):\s+addr=\s*(?P<address>0x[0-9a-f]+)",
    re.IGNORECASE,
)
_UNICORN_ERROR = re.compile(r"\b(UC_ERR_[A-Z0-9_]+)\b")
_CRASH_SIGNAL = re.compile(r"\bEmulation crashed with signal\s+([0-9]+)\b", re.IGNORECASE)
_CRASH_DETECTED = re.compile(r"\bCRASH DETECTED\b", re.IGNORECASE)
_STACK_POINTER = re.compile(
    r"^(?:sp|other_sp):\s*(?P<address>0x[0-9a-fA-F]+)\s*$",
    re.MULTILINE,
)


def _hex(text: str) -> int:
    return int(text, 16)


def parse_mmio_line(line: str) -> MMIOEvent:
    """Parse one standard Fuzzware MMIO trace line."""
    match = _MMIO_LINE.fullmatch(line.strip())
    if match is None:
        raise TraceParseError(f"malformed MMIO trace line: {line.rstrip()!r}")
    fields = match.groupdict()
    return MMIOEvent(
        event_id=_hex(fields["event_id"]),
        pc=_hex(fields["pc"]),
        lr=_hex(fields["lr"]),
        mode=fields["mode"],  # type: ignore[arg-type]
        access_size=int(fields["access_size"], 10),
        fuzz_index=int(fields["fuzz_index"], 10),
        consumed_bytes=int(fields["consumed_bytes"], 10),
        address=_hex(fields["address"]),
        value=_hex(fields["value"]),
    )


def parse_bb_line(line: str) -> BBEvent:
    """Parse one standard Fuzzware basic-block trace line."""
    match = _BB_LINE.fullmatch(line.strip())
    if match is None:
        raise TraceParseError(f"malformed BB trace line: {line.rstrip()!r}")
    fields = match.groupdict()
    return BBEvent(
        event_id=_hex(fields["event_id"]),
        bb_addr=_hex(fields["bb_addr"]),
        count=int(fields["count"], 10),
    )


def parse_ram_line(line: str) -> RAMEvent:
    """Parse one standard Fuzzware RAM trace line."""
    match = _RAM_LINE.fullmatch(line.strip())
    if match is None:
        raise TraceParseError(f"malformed RAM trace line: {line.rstrip()!r}")
    fields = match.groupdict()
    return RAMEvent(
        event_id=_hex(fields["event_id"]),
        pc=_hex(fields["pc"]),
        lr=_hex(fields["lr"]),
        mode=fields["mode"],  # type: ignore[arg-type]
        access_size=int(fields["access_size"], 10),
        address=_hex(fields["address"]),
        value=_hex(fields["value"]),
    )


def _read_lines(source: TraceSource) -> tuple[Iterable[str], str, TextIO | None]:
    if isinstance(source, (str, os.PathLike)):
        path = Path(source)
        handle = path.open("r", encoding="utf-8")
        return handle, str(path), handle
    if hasattr(source, "read"):
        return source, getattr(source, "name", "<stream>"), None
    return source, "<iterable>", None


@overload
def load_events(source: TraceSource, *, kind: Literal["mmio"]) -> tuple[MMIOEvent, ...]: ...


@overload
def load_events(source: TraceSource, *, kind: Literal["bb"]) -> tuple[BBEvent, ...]: ...


@overload
def load_events(source: TraceSource, *, kind: Literal["ram"]) -> tuple[RAMEvent, ...]: ...


def load_events(
    source: TraceSource, *, kind: Literal["mmio", "bb", "ram"]
) -> tuple[TraceEvent, ...]:
    """Load nonempty trace lines from a path, text stream, or line iterable."""
    parser = {
        "mmio": parse_mmio_line,
        "bb": parse_bb_line,
        "ram": parse_ram_line,
    }[kind]
    lines, source_name, owned_handle = _read_lines(source)
    events: list[TraceEvent] = []
    try:
        for line_number, line in enumerate(lines, start=1):
            if not line.strip():
                continue
            try:
                events.append(parser(line))
            except TraceParseError as exc:
                raise TraceParseError(
                    f"{source_name}:{line_number}: {exc}"
                ) from exc
    finally:
        if owned_handle is not None:
            owned_handle.close()
    return tuple(events)


def load_mmio_events(source: TraceSource) -> tuple[MMIOEvent, ...]:
    """Load MMIO events from a trace source."""
    return load_events(source, kind="mmio")


def load_bb_events(source: TraceSource) -> tuple[BBEvent, ...]:
    """Load basic-block events from a trace source."""
    return load_events(source, kind="bb")


def parse_mmio_trace(path: Path) -> list[MMIOEvent]:
    """Parse a Fuzzware MMIO trace file using the stable integration API."""
    return list(load_events(path, kind="mmio"))


def parse_bb_trace(path: Path) -> list[BBEvent]:
    """Parse a Fuzzware basic-block trace file using the stable integration API."""
    return list(load_events(path, kind="bb"))


def parse_ram_trace(path: Path) -> list[RAMEvent]:
    """Parse a Fuzzware RAM trace file using the stable integration API."""
    return list(load_events(path, kind="ram"))


def parse_fault_signature(signature: str | None) -> FaultEvidence | None:
    """Parse a normalized invalid-access signature into typed evidence."""
    if not signature:
        return None
    match = re.fullmatch(
        r"INVALID_(?P<kind>WRITE|READ|FETCH):pc=(?P<pc>0x[0-9a-f]+):"
        r"addr=(?P<address>0x[0-9a-f]+)",
        signature,
        re.IGNORECASE,
    )
    if match is None:
        return None
    return FaultEvidence(
        kind=match.group("kind").upper(),
        pc=int(match.group("pc"), 16),
        address=int(match.group("address"), 16),
        signature=signature,
    )


def causal_sink_fault(
    events: Sequence[RAMEvent],
    *,
    fault_signature: str | None,
    sink_effect_intervals: Sequence[tuple[int, int]],
    fault_function_interval: tuple[int, int] | None,
    max_fault_predecessor_distance: int = 8,
) -> dict[str, object] | None:
    """Bind a runtime fault to a preceding memory write by a Sink effect.

    A downstream fault is accepted only when a Sink implementation writes a
    RAM location, the faulting function later reads the same location, and no
    intervening write replaces it. The read must be instruction-local to the
    invalid access. This is stricter than mere Sink reachability plus crash.
    """
    fault = parse_fault_signature(fault_signature)
    if fault is None or fault_function_interval is None:
        return None

    fault_start, fault_end = fault_function_interval
    reads = [
        event
        for event in events
        if event.mode == "r"
        and fault_start <= _code_address(event.pc) < fault_end
        and 0 <= _code_address(fault.pc) - _code_address(event.pc)
        <= max_fault_predecessor_distance
    ]
    for read in reversed(reads):
        writes = [
            event
            for event in events
            if event.mode == "w"
            and event.event_id < read.event_id
            and event.address == read.address
        ]
        if not writes:
            continue
        reaching_write = writes[-1]
        effect_interval = next(
            (
                (start, end)
                for start, end in sink_effect_intervals
                if start <= _code_address(reaching_write.pc) < end
            ),
            None,
        )
        if effect_interval is None:
            continue
        return {
            "mode": "SINK_WRITE_TO_FAULT_PREDECESSOR",
            "sink_write": {
                "event_id": reaching_write.event_id,
                "pc": f"0x{_code_address(reaching_write.pc):x}",
                "address": f"0x{reaching_write.address:x}",
                "value": reaching_write.value,
                "access_size": reaching_write.access_size,
                "effect_interval": [
                    f"0x{effect_interval[0]:x}",
                    f"0x{effect_interval[1]:x}",
                ],
            },
            "fault_predecessor_read": {
                "event_id": read.event_id,
                "pc": f"0x{_code_address(read.pc):x}",
                "address": f"0x{read.address:x}",
                "value": read.value,
                "access_size": read.access_size,
            },
            "fault": {
                "kind": fault.kind,
                "pc": f"0x{_code_address(fault.pc):x}",
                "address": f"0x{fault.address:x}",
                "signature": fault.signature,
            },
        }
    return None


def runtime_stack_pointers(log_text: str) -> set[int]:
    """Return stack pointers printed by Fuzzware at a runtime fault."""
    return {
        int(match.group("address"), 16)
        for match in _STACK_POINTER.finditer(log_text)
    }


def causal_nonreturning_sink_stack_fault(
    ram_events: Sequence[RAMEvent],
    bb_events: Sequence[BBEvent],
    *,
    fault_signature: str | None,
    sink_block_interval: tuple[int, int],
    sink_return_address: int,
    sink_effect_intervals: Sequence[tuple[int, int]],
    stack_pointers: set[int],
) -> dict[str, object] | None:
    """Bind a fault to a non-returning Sink effect that overwrites a live stack.

    This covers large invalid copies whose corruption is observed before a
    later interrupt faults. Mere Sink/crash co-occurrence is insufficient: the
    exact Sink block must enter its primitive effect, the effect must not
    return, and a write by that effect must overlap a stack pointer reported at
    the fault.
    """
    fault = parse_fault_signature(fault_signature)
    if fault is None or not stack_pointers:
        return None

    sink_start, sink_end = sink_block_interval
    sink_entries = [
        event
        for event in bb_events
        if sink_start <= _code_address(event.address) < sink_end
    ]
    if not sink_entries:
        return None
    sink_entry = sink_entries[-1]

    effect_entry = next(
        (
            event
            for event in bb_events
            if event.event_id > sink_entry.event_id
            and any(
                start <= _code_address(event.address) < end
                for start, end in sink_effect_intervals
            )
        ),
        None,
    )
    if effect_entry is None:
        return None
    if any(
        event.event_id > effect_entry.event_id
        and _code_address(event.address) == _code_address(sink_return_address)
        for event in bb_events
    ):
        return None

    effect_writes = [
        event
        for event in ram_events
        if event.mode == "w"
        and event.event_id >= effect_entry.event_id
        and any(
            start <= _code_address(event.pc) < end
            for start, end in sink_effect_intervals
        )
    ]
    if not effect_writes:
        return None

    overlapping: tuple[RAMEvent, int] | None = None
    for write in effect_writes:
        write_end = write.address + write.access_size
        for stack_pointer in stack_pointers:
            if write.address < stack_pointer + 4 and stack_pointer < write_end:
                overlapping = (write, stack_pointer)
                break
        if overlapping is not None:
            break
    if overlapping is None:
        return None

    stack_write, stack_pointer = overlapping
    return {
        "mode": "SINK_EFFECT_OVERWROTE_ACTIVE_STACK",
        "sink_block_event": {
            "event_id": sink_entry.event_id,
            "address": f"0x{_code_address(sink_entry.address):x}",
            "interval": [f"0x{sink_start:x}", f"0x{sink_end:x}"],
        },
        "effect_entry": {
            "event_id": effect_entry.event_id,
            "address": f"0x{_code_address(effect_entry.address):x}",
        },
        "stack_write": {
            "event_id": stack_write.event_id,
            "pc": f"0x{_code_address(stack_write.pc):x}",
            "address": f"0x{stack_write.address:x}",
            "value": stack_write.value,
            "access_size": stack_write.access_size,
            "stack_pointer": f"0x{stack_pointer:x}",
        },
        "effect_write_summary": {
            "count": len(effect_writes),
            "minimum_address": f"0x{min(row.address for row in effect_writes):x}",
            "maximum_address": f"0x{max(row.address for row in effect_writes):x}",
            "returned_to": f"0x{_code_address(sink_return_address):x}",
            "return_observed": False,
        },
        "fault": {
            "kind": fault.kind,
            "pc": f"0x{_code_address(fault.pc):x}",
            "address": f"0x{fault.address:x}",
            "signature": fault.signature,
        },
    }


def detect_fault(log_text: str, returncode: int) -> str | None:
    """Extract a reproducible runtime-fault signature from Fuzzware output.

    Explicit invalid accesses take precedence over generic Unicorn errors and
    crash markers. A process terminated by a signal is also a runtime fault;
    an ordinary positive exit code alone is not.
    """
    invalid_accesses = list(_INVALID_ACCESS.finditer(log_text))
    if invalid_accesses:
        match = invalid_accesses[-1]
        kind = match.group("kind").upper()
        pc = int(match.group("pc"), 16)
        address = int(match.group("address"), 16)
        return f"INVALID_{kind}:pc={pc:#x}:addr={address:#x}"

    unicorn_errors = [
        error
        for error in _UNICORN_ERROR.findall(log_text.upper())
        if error != "UC_ERR_OK"
    ]
    if unicorn_errors:
        return unicorn_errors[-1]

    crash_signals = _CRASH_SIGNAL.findall(log_text)
    if crash_signals:
        return f"SIGNAL:{int(crash_signals[-1], 10)}"

    if returncode < 0:
        return f"SIGNAL:{-returncode}"
    if 128 <= returncode <= 192:
        return f"SIGNAL:{returncode - 128}"
    if _CRASH_DETECTED.search(log_text):
        return "CRASH_DETECTED"
    return None


def _code_address(address: int) -> int:
    """Canonicalize ARM/Thumb code pointers to instruction addresses."""
    return address & ~1


def source_address_observed(
    events: Iterable[MMIOEvent],
    source_address: int,
    *,
    allowed_pcs: Iterable[int] | None = None,
) -> bool:
    """Return whether an MMIO address was accessed from an allowed PC, if any."""
    allowed = (
        None
        if allowed_pcs is None
        else {_code_address(address) for address in allowed_pcs}
    )
    return any(
        event.address == source_address
        and (allowed is None or _code_address(event.pc) in allowed)
        for event in events
    )


def _interval_for_entry(
    entry: int, block_intervals: BlockIntervals
) -> tuple[int, int] | None:
    interval = block_intervals.get(entry)
    if interval is None:
        interval = block_intervals.get(entry | 1)
    if interval is None:
        return None
    if isinstance(interval, range):
        start, end = interval.start, interval.stop
    elif isinstance(interval, int):
        start, end = entry, interval
    else:
        try:
            start, end = interval
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid block interval for {entry:#x}: {interval!r}") from exc
    start, end = _code_address(start), _code_address(end)
    if start > entry or end <= start:
        raise ValueError(
            f"invalid half-open block interval for {entry:#x}: [{start:#x}, {end:#x})"
        )
    return start, end


def sink_address_observed(
    events: Iterable[BBEvent],
    sink_address: int,
    *,
    block_intervals: BlockIntervals | None = None,
) -> bool:
    """Return whether an executed block covers the sink instruction.

    Without ``block_intervals``, only an exact basic-block entry is evidence.
    Mapping values may be a half-open ``(start, end)`` tuple, a ``range``, or an
    integer end address (with the mapping key used as the start).
    """
    sink = _code_address(sink_address)
    for event in events:
        entry = _code_address(event.bb_addr)
        if entry == sink:
            return True
        if block_intervals is None:
            continue
        interval = _interval_for_entry(entry, block_intervals)
        if interval is not None and interval[0] <= sink < interval[1]:
            return True
    return False


def classify_repeated_runs(
    runs: Sequence[TraceRun],
    *,
    source_address: int,
    sink_address: int,
    allowed_source_pcs: Iterable[int] | None = None,
    block_intervals: BlockIntervals | None = None,
) -> Literal["POC", "INCONCLUSIVE"]:
    """Classify repeated runs, failing closed to ``INCONCLUSIVE``.

    A POC needs at least two runs. Every run must observe the source and sink,
    and every run must carry the same nonempty runtime-fault signature.
    """
    if len(runs) < 2:
        return INCONCLUSIVE

    allowed_pcs = None if allowed_source_pcs is None else tuple(allowed_source_pcs)
    evidence: list[ReplayEvidence] = []
    for run in runs:
        evidence.append(
            ReplayEvidence(
                source_observed=source_address_observed(
                    run.mmio_events, source_address, allowed_pcs=allowed_pcs
                ),
                sink_observed=sink_address_observed(
                    run.bb_events, sink_address, block_intervals=block_intervals
                ),
                fault_signature=run.runtime_fault_signature,
            )
        )

    return classify_replays(evidence)


def _replay_field(row: ReplayRow, field: str) -> object:
    if isinstance(row, ReplayEvidence):
        return getattr(row, field)
    return row.get(field)


def classify_replays(
    rows: Sequence[ReplayRow],
) -> Literal["POC", "INCONCLUSIVE"]:
    """Classify normalized replay evidence without ever returning ``NON_POC``.

    At least two rows are required. Each row must report source and sink
    evidence, and all rows must have the same nonempty fault signature.
    """
    if len(rows) < 2:
        return INCONCLUSIVE

    signatures: list[str] = []
    for row in rows:
        if _replay_field(row, "source_observed") is not True:
            return INCONCLUSIVE
        if _replay_field(row, "sink_observed") is not True:
            return INCONCLUSIVE
        raw_signature = _replay_field(row, "fault_signature")
        if not isinstance(raw_signature, str) or not raw_signature.strip():
            return INCONCLUSIVE
        signatures.append(raw_signature.strip())

    return POC if len(set(signatures)) == 1 else INCONCLUSIVE


# Short aliases for callers that use evidence terminology.
source_observed = source_address_observed
sink_observed = sink_address_observed
classify_alert = classify_repeated_runs
