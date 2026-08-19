#!/usr/bin/env python3
"""Execute a verified plan with unmodified Fuzzware and classify its evidence."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
from pathlib import Path
from typing import Any

import yaml
from capstone import (
    CS_ARCH_ARM,
    CS_GRP_CALL,
    CS_GRP_IRET,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    Cs,
)
from capstone.arm import ARM_OP_IMM
from elftools.elf.elffile import ELFFile

from calibrate_fuzzware_input import (
    SourceCallNotObserved,
    SourceTransactionSizeMismatch,
    eligible_source_reads,
    next_call_boundary,
    patch_semantic_stream,
    select_transaction_window,
    source_call_specs,
    source_contexts,
    symbol_address,
    transaction_windows,
)
from fuzzware_trace import (
    INCONCLUSIVE,
    POC,
    causal_sink_fault,
    causal_nonreturning_sink_stack_fault,
    detect_fault,
    parse_bb_trace,
    parse_fault_signature,
    parse_mmio_trace,
    parse_ram_trace,
    runtime_stack_pointers,
    sink_address_observed,
)
from validation_common import load_json, parse_address, sha256_file, write_json


def container_path(path: Path, target_root: Path) -> str:
    relative = path.resolve().relative_to(target_root.resolve())
    return f"/home/user/fuzzware/targets/{relative.as_posix()}"


def run_emu(
    *,
    fuzzware_root: Path,
    target_root: Path,
    config: Path,
    input_path: Path,
    output_dir: Path,
    instruction_limit: int,
    consumption_timeout: int,
    timeout_seconds: int,
    ram_trace_enabled: bool = False,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    mmio_trace = output_dir / "mmio.txt"
    bb_trace = output_dir / "bb.txt"
    ram_trace = output_dir / "ram.txt"
    log_path = output_dir / "run.log"
    mmio_trace.unlink(missing_ok=True)
    bb_trace.unlink(missing_ok=True)
    ram_trace.unlink(missing_ok=True)
    command = [
        str(fuzzware_root / "run_docker.sh"),
        str(target_root),
        "fuzzware",
        "emu",
        "-v",
        "-l",
        str(instruction_limit),
        "--fuzz-consumption-timeout",
        str(consumption_timeout),
        "-c",
        container_path(config, target_root),
        "--mmio-trace-out",
        container_path(mmio_trace, target_root),
        "--bb-trace-out",
        container_path(bb_trace, target_root),
    ]
    if ram_trace_enabled:
        command.extend(
            ["--ram-trace-out", container_path(ram_trace, target_root)]
        )
    command.append(container_path(input_path, target_root))
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
        returncode = completed.returncode
        log_text = completed.stdout + completed.stderr
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        returncode = 124
        log_text = (exc.stdout or "") + (exc.stderr or "")
        if isinstance(log_text, bytes):
            log_text = log_text.decode("utf-8", errors="replace")
        log_text += f"\nCopperTrace runner timeout after {timeout_seconds}s\n"
        timed_out = True
    log_path.write_text(log_text, encoding="utf-8")
    return {
        "command": command,
        "returncode": returncode,
        "timed_out": timed_out,
        "log_path": str(log_path),
        "mmio_trace": str(mmio_trace),
        "bb_trace": str(bb_trace),
        "ram_trace": str(ram_trace) if ram_trace_enabled else None,
        "fault_signature": detect_fault(log_text, returncode),
        "trace_complete": mmio_trace.exists() and bb_trace.exists(),
    }


def function_interval(binary: Path, address: int) -> tuple[int, int]:
    """Return the containing ELF function interval for a checkpoint address."""
    candidates: list[tuple[int, int]] = []
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            if section["sh_type"] not in {"SHT_SYMTAB", "SHT_DYNSYM"}:
                continue
            for symbol in section.iter_symbols():
                if symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                start = int(symbol["st_value"]) & ~1
                size = int(symbol["st_size"])
                if start and size and start <= address < start + size:
                    candidates.append((start, start + size))
    if not candidates:
        raise ValueError(f"no ELF function contains Sink address {address:#x}")
    return min(candidates, key=lambda interval: interval[1] - interval[0])


def basic_block_interval(binary: Path, address: int) -> tuple[int, int]:
    """Recover the Thumb basic block containing one instruction address."""
    function_start, function_end = function_interval(binary, address)
    function_bytes = None
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            start = int(section["sh_addr"])
            end = start + int(section["sh_size"])
            if start <= function_start and function_end <= end:
                offset = function_start - start
                function_bytes = section.data()[
                    offset : offset + (function_end - function_start)
                ]
                break
    if function_bytes is None:
        raise ValueError("ELF function bytes are not backed by one section")

    disassembler = Cs(
        CS_ARCH_ARM,
        CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN,
    )
    disassembler.detail = True
    instructions = list(disassembler.disasm(function_bytes, function_start))
    if not instructions:
        raise ValueError("Capstone produced no instructions for Sink function")
    by_address = {instruction.address: instruction for instruction in instructions}
    starts: set[int] = set()
    pending = [function_start]
    while pending:
        block_start = pending.pop()
        if block_start in starts or block_start not in by_address:
            continue
        starts.add(block_start)
        cursor = block_start
        while cursor in by_address:
            instruction = by_address[cursor]
            next_address = instruction.address + instruction.size
            if instruction.group(CS_GRP_CALL):
                if next_address < function_end:
                    pending.append(next_address)
                break
            if instruction.group(CS_GRP_JUMP):
                for operand in instruction.operands:
                    if operand.type == ARM_OP_IMM:
                        target = int(operand.imm) & ~1
                        if function_start <= target < function_end:
                            pending.append(target)
                unconditional = instruction.mnemonic.lower() in {
                    "b",
                    "b.w",
                    "bx",
                    "bxj",
                }
                if not unconditional and next_address < function_end:
                    pending.append(next_address)
                break
            if instruction.group(CS_GRP_RET) or instruction.group(CS_GRP_IRET):
                break
            cursor = next_address

    ordered = sorted(starts | {function_end})
    for start, end in zip(ordered, ordered[1:]):
        if start <= address < end:
            return start, end
    raise ValueError(f"no recovered basic block contains Sink address {address:#x}")


def named_function_intervals(binary: Path, names: set[str]) -> list[tuple[int, int]]:
    """Return canonical ELF intervals for named Sink implementations."""
    intervals: set[tuple[int, int]] = set()
    with binary.open("rb") as handle:
        elf = ELFFile(handle)
        for section in elf.iter_sections():
            if section["sh_type"] not in {"SHT_SYMTAB", "SHT_DYNSYM"}:
                continue
            for symbol in section.iter_symbols():
                if symbol.name not in names or symbol["st_info"]["type"] != "STT_FUNC":
                    continue
                start = int(symbol["st_value"]) & ~1
                size = int(symbol["st_size"])
                if start and size:
                    intervals.add((start, start + size))
    return sorted(intervals)


def mapping_observed(
    events: list[Any], mapping: list[dict[str, Any]]
) -> bool:
    """Require every injected byte to be consumed at its reported Source site."""
    for row in mapping:
        expected_pc = parse_address(row.get("pc"))
        expected_address = parse_address(row.get("register_address"))
        expected_offset = int(row["fuzz_offset"])
        expected_byte = int(row["semantic_byte"])
        if not any(
            (event.pc & ~1) == expected_pc
            and event.address == expected_address
            and event.fuzz_index == expected_offset
            and (event.value & 0xFF) == expected_byte
            for event in events
        ):
            return False
    return True


def patch_event(
    base_input: bytes,
    payload: bytes,
    window: Any,
) -> tuple[bytes, list[dict[str, Any]]]:
    return patch_semantic_stream(base_input, payload, list(window.source_reads))


def finite_set_models(config: Path) -> dict[tuple[int, int], list[int]]:
    """Index Fuzzware's learned finite-set peripheral models by PC and address."""
    document = yaml.safe_load(config.read_text(encoding="utf-8")) or {}
    result: dict[tuple[int, int], list[int]] = {}
    for model in (
        document.get("mmio_models", {}).get("set", {}) or {}
    ).values():
        if not isinstance(model, dict):
            continue
        pc = parse_address(model.get("pc"))
        address = parse_address(model.get("addr"))
        values = model.get("vals", []) or []
        if pc is not None and address is not None and values:
            result[(pc & ~1, address)] = [int(value) for value in values]
    return result


def candidate_transaction_window(
    windows: list[Any],
    *,
    call_index: int,
    after_event_id: int,
    before_event_id: int | None,
) -> Any | None:
    return next(
        (
            window
            for window in windows
            if window.call_index == call_index
            and window.entry_event_id > after_event_id
            and (
                before_event_id is None
                or window.entry_event_id < before_event_id
            )
        ),
        None,
    )


def status_selector_repairs(
    *,
    mmio_events: list[Any],
    window: Any,
    models: dict[tuple[int, int], list[int]],
    already_patched: set[int],
    allowed_peripheral_pages: set[int],
) -> list[dict[str, Any]]:
    """Choose normal-operation alternatives in learned finite status models.

    The bounded repair is restricted to the failed receive-call window. It
    prefers clearing a nonzero status when zero is already one of Fuzzware's
    learned alternatives. It never changes Source payload reads.
    """
    rows: list[dict[str, Any]] = []
    for event in mmio_events:
        if not window.entry_event_id < event.event_id < window.return_event_id:
            continue
        if event.mode != "r" or event.consumed_bytes <= 0:
            continue
        if event.fuzz_index in already_patched:
            continue
        if (event.address & ~0xFFF) not in allowed_peripheral_pages:
            continue
        values = models.get((event.pc & ~1, event.address))
        if not values or 0 not in values or event.value == 0:
            continue
        rows.append(
            {
                "fuzz_offset": event.fuzz_index,
                "selector_byte": values.index(0),
                "pc": f"0x{event.pc & ~1:x}",
                "register_address": f"0x{event.address:x}",
                "observed_value": event.value,
                "selected_value": 0,
                "model_values": values,
                "event_id": event.event_id,
            }
        )
    return rows


def interrupt_schedule_windows(
    *,
    plan: dict[str, Any],
    binary: Path,
    bb_events: list[Any],
    max_schedule_order: int | None = None,
) -> list[dict[str, Any]]:
    """Bind planned one-shot IRQ triggers to concrete basic-block events."""
    rows: list[dict[str, Any]] = []
    previous_event_id = -1
    schedules = sorted(
        plan.get("interrupt_schedule", []) or [],
        key=lambda row: int(row["order"]),
    )
    if max_schedule_order is not None:
        schedules = [
            row for row in schedules if int(row["order"]) <= max_schedule_order
        ]
    for schedule in schedules:
        symbol = str(schedule.get("trigger_symbol", ""))
        base = symbol_address(binary, symbol)
        if base is None:
            raise ValueError(f"cannot resolve IRQ trigger symbol {symbol!r}")
        trigger_address = base + int(schedule.get("trigger_offset", 0))
        trigger = next(
            (
                event
                for event in bb_events
                if event.event_id > previous_event_id
                and (event.address & ~1) == (trigger_address & ~1)
            ),
            None,
        )
        if trigger is None:
            raise ValueError(
                f"planned IRQ trigger {schedule.get('event_id')!r} "
                f"was not observed at {trigger_address:#x}"
            )
        rows.append(
            {
                "schedule": schedule,
                "trigger_address": trigger_address & ~1,
                "trigger_event_id": trigger.event_id,
                "end_event_id": None,
            }
        )
        previous_event_id = trigger.event_id
    for index, row in enumerate(rows[:-1]):
        row["end_event_id"] = rows[index + 1]["trigger_event_id"]
    return rows


def match_control_response(
    *,
    mmio_events: list[Any],
    requirement: dict[str, Any],
    after_event_id: int,
    before_event_id: int | None,
) -> Any | None:
    """Find one dynamic SPI register response following its command write."""
    command_address = int(requirement["command_address"])
    command_value = int(requirement["command_value"])
    command_ordinal = int(requirement.get("command_ordinal", 0))
    response_address = int(requirement["response_address"])
    response_ordinal = int(requirement.get("response_ordinal", 0))
    commands = [
        event
        for event in mmio_events
        if event.event_id > after_event_id
        and (before_event_id is None or event.event_id < before_event_id)
        and event.mode == "w"
        and event.address == command_address
        and event.value == command_value
    ]
    if command_ordinal >= len(commands):
        return None
    command = commands[command_ordinal]
    responses = [
        event
        for event in mmio_events
        if event.event_id > command.event_id
        and (before_event_id is None or event.event_id < before_event_id)
        and event.mode == "r"
        and event.address == response_address
        and event.consumed_bytes > 0
    ]
    return responses[response_ordinal] if response_ordinal < len(responses) else None


def apply_control_requirements(
    *,
    current_input: bytes,
    trace_mmio: Path,
    trace_bb: Path,
    plan: dict[str, Any],
    binary: Path,
    config: Path,
    fuzzware_root: Path,
    target_root: Path,
    output_dir: Path,
    instruction_limit: int,
    consumption_timeout: int,
    timeout_seconds: int,
    max_schedule_order: int,
) -> tuple[bytes, Path, Path, list[dict[str, Any]], list[dict[str, Any]]]:
    """Satisfy bounded peripheral event preconditions before payload mapping."""
    repairs: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    requirement_count = sum(
        len(row.get("control_requirements", []) or [])
        for row in plan.get("interrupt_schedule", []) or []
        if int(row["order"]) <= max_schedule_order
    )
    if requirement_count > 32:
        raise ValueError("Execution Plan exceeds 32 control requirements")
    if requirement_count == 0:
        return current_input, trace_mmio, trace_bb, repairs, runs

    for repair_index in range(requirement_count + 1):
        mmio_events = parse_mmio_trace(trace_mmio)
        bb_events = parse_bb_trace(trace_bb)
        windows = interrupt_schedule_windows(
            plan=plan,
            binary=binary,
            bb_events=bb_events,
            max_schedule_order=max_schedule_order,
        )
        pending: tuple[dict[str, Any], dict[str, Any], Any] | None = None
        for window in windows:
            schedule = window["schedule"]
            for requirement in schedule.get("control_requirements", []) or []:
                response = match_control_response(
                    mmio_events=mmio_events,
                    requirement=requirement,
                    after_event_id=int(window["trigger_event_id"]),
                    before_event_id=window["end_event_id"],
                )
                if response is None:
                    raise ValueError(
                        f"control requirement {requirement.get('requirement_id')!r} "
                        f"has no matching peripheral response"
                    )
                required_value = int(requirement["required_value"])
                identity = (
                    str(schedule["event_id"]),
                    str(requirement["requirement_id"]),
                )
                if any(
                    (row["interrupt_event_id"], row["requirement_id"]) == identity
                    for row in repairs
                ):
                    continue
                if response.value == required_value:
                    repairs.append(
                        {
                            "interrupt_event_id": identity[0],
                            "requirement_id": identity[1],
                            "status": "already_satisfied",
                            "fuzz_offset": response.fuzz_index,
                            "observed_value": response.value,
                            "required_value": required_value,
                            "response_event_id": response.event_id,
                            "evidence_ref": requirement["evidence_ref"],
                        }
                    )
                    continue
                pending = (schedule, requirement, response)
                break
            if pending is not None:
                break
        if pending is None:
            return current_input, trace_mmio, trace_bb, repairs, runs
        if repair_index == requirement_count:
            break

        schedule, requirement, response = pending
        if response.consumed_bytes != 1:
            raise ValueError(
                f"control requirement {requirement.get('requirement_id')!r} "
                "does not bind to one fuzz byte"
            )
        required_value = int(requirement["required_value"])
        if not 0 <= required_value <= 0xFF:
            raise ValueError("one-byte control response exceeds 0xff")
        mutable = bytearray(current_input)
        if not 0 <= response.fuzz_index < len(mutable):
            raise ValueError("control response fuzz offset is outside input")
        previous_byte = mutable[response.fuzz_index]
        mutable[response.fuzz_index] = required_value
        current_input = bytes(mutable)
        repair_input = output_dir / f"control-{repair_index:02d}.bin"
        repair_input.parent.mkdir(parents=True, exist_ok=True)
        repair_input.write_bytes(current_input)
        run = run_emu(
            fuzzware_root=fuzzware_root,
            target_root=target_root,
            config=config,
            input_path=repair_input,
            output_dir=output_dir / f"control-{repair_index:02d}-trace",
            instruction_limit=instruction_limit,
            consumption_timeout=consumption_timeout,
            timeout_seconds=timeout_seconds,
        )
        runs.append(run)
        if not run["trace_complete"]:
            raise ValueError("control requirement replay produced no traces")
        trace_mmio = Path(run["mmio_trace"])
        trace_bb = Path(run["bb_trace"])
        verified_mmio = parse_mmio_trace(trace_mmio)
        verified_windows = interrupt_schedule_windows(
            plan=plan,
            binary=binary,
            bb_events=parse_bb_trace(trace_bb),
            max_schedule_order=max_schedule_order,
        )
        verified_window = next(
            (
                row
                for row in verified_windows
                if row["schedule"]["event_id"] == schedule["event_id"]
            ),
            None,
        )
        if verified_window is None:
            raise ValueError("patched control event has no replay window")
        verified_response = match_control_response(
            mmio_events=verified_mmio,
            requirement=requirement,
            after_event_id=int(verified_window["trigger_event_id"]),
            before_event_id=verified_window["end_event_id"],
        )
        if verified_response is None or verified_response.value != required_value:
            observed = None if verified_response is None else verified_response.value
            raise ValueError(
                f"control requirement {requirement.get('requirement_id')!r} "
                f"replay produced {observed!r}, expected {required_value}"
            )
        repairs.append(
            {
                "interrupt_event_id": str(schedule["event_id"]),
                "requirement_id": str(requirement["requirement_id"]),
                "status": "patched",
                "fuzz_offset": response.fuzz_index,
                "previous_byte": previous_byte,
                "selected_byte": required_value,
                "observed_value": response.value,
                "required_value": required_value,
                "response_event_id": verified_response.event_id,
                "evidence_ref": requirement["evidence_ref"],
            }
        )
    raise ValueError("control requirements did not converge within the bounded budget")


def calibrate_variant(
    *,
    variant: dict[str, Any],
    plan: dict[str, Any],
    base_input: Path,
    baseline_mmio: Path,
    baseline_bb: Path,
    binary: Path,
    evidence: dict[str, Any],
    config: Path,
    fuzzware_root: Path,
    target_root: Path,
    output_dir: Path,
    instruction_limit: int,
    consumption_timeout: int,
    timeout_seconds: int,
) -> tuple[Path, list[dict[str, Any]], list[dict[str, Any]]]:
    """Calibrate ordered plan events without searching for crashing values."""
    call_specs = source_call_specs(evidence, binary)
    contexts = source_contexts(evidence)
    source_peripheral_pages = {address & ~0xFFF for _, address in contexts}
    current_input = base_input.read_bytes()
    trace_mmio = baseline_mmio
    trace_bb = baseline_bb
    event_mappings: list[dict[str, Any]] = []
    calibration_runs: list[dict[str, Any]] = []
    previous_mapping: list[dict[str, Any]] | None = None
    previous_call_index: int | None = None
    status_repairs: list[dict[str, Any]] = []
    repaired_offsets: set[int] = set()
    set_models = finite_set_models(config)
    control_repairs: list[dict[str, Any]] = []

    events = sorted(variant.get("events", []) or [], key=lambda row: row["order"])

    for event_index, event in enumerate(events):
        (
            current_input,
            trace_mmio,
            trace_bb,
            current_control_repairs,
            control_runs,
        ) = apply_control_requirements(
            current_input=current_input,
            trace_mmio=trace_mmio,
            trace_bb=trace_bb,
            plan=plan,
            binary=binary,
            config=config,
            fuzzware_root=fuzzware_root,
            target_root=target_root,
            output_dir=output_dir / f"event-{event_index:02d}-control",
            instruction_limit=instruction_limit,
            consumption_timeout=consumption_timeout,
            timeout_seconds=timeout_seconds,
            max_schedule_order=int(event.get("transaction_group", 0)),
        )
        calibration_runs.extend(control_runs)
        for repair in current_control_repairs:
            identity = (
                repair["interrupt_event_id"],
                repair["requirement_id"],
            )
            control_repairs = [
                row
                for row in control_repairs
                if (row["interrupt_event_id"], row["requirement_id"]) != identity
            ]
            control_repairs.append(repair)

        call_index = int(event.get("call_index", event_index))
        if not 0 <= call_index < len(call_specs):
            raise ValueError(
                f"event {event.get('event_id', event_index)!r} references "
                f"unknown Source call index {call_index}"
            )
        mmio_events = parse_mmio_trace(trace_mmio)
        bb_events = parse_bb_trace(trace_bb)
        source_reads = eligible_source_reads(mmio_events, contexts)
        windows = transaction_windows(bb_events, source_reads, call_specs)

        after_event_id = -1
        before_event_id = None
        if previous_mapping is not None:
            assert previous_call_index is not None
            anchor = select_transaction_window(
                windows,
                call_index=previous_call_index,
                byte_length=len(previous_mapping),
                required_fuzz_offsets=[
                    int(row["fuzz_offset"]) for row in previous_mapping
                ],
            )
            after_event_id = anchor.return_event_id
            before_event_id = next_call_boundary(windows, anchor)

        payload = bytes.fromhex(str(event["payload_hex"]))
        try:
            window = select_transaction_window(
                windows,
                call_index=call_index,
                byte_length=len(payload),
                after_event_id=after_event_id,
                before_event_id=before_event_id,
            )
        except ValueError as original_error:
            # The payload call exists, but a learned status choice may have
            # completed it before data-register reads. Try a bounded number of
            # normal-operation status alternatives, then fail closed.
            repaired = False
            for repair_index in range(12):
                candidate = candidate_transaction_window(
                    windows,
                    call_index=call_index,
                    after_event_id=after_event_id,
                    before_event_id=before_event_id,
                )
                if candidate is None:
                    break
                repairs = status_selector_repairs(
                    mmio_events=mmio_events,
                    window=candidate,
                    models=set_models,
                    already_patched=repaired_offsets,
                    allowed_peripheral_pages=source_peripheral_pages,
                )
                if not repairs:
                    break
                repair = repairs[0]
                mutable = bytearray(current_input)
                offset = int(repair["fuzz_offset"])
                if not 0 <= offset < len(mutable):
                    break
                mutable[offset] = int(repair["selector_byte"])
                current_input = bytes(mutable)
                repaired_offsets.add(offset)
                status_repairs.append(repair)
                repair_input = output_dir / (
                    f"event-{event_index:02d}-status-{repair_index:02d}.bin"
                )
                repair_input.parent.mkdir(parents=True, exist_ok=True)
                repair_input.write_bytes(current_input)
                run = run_emu(
                    fuzzware_root=fuzzware_root,
                    target_root=target_root,
                    config=config,
                    input_path=repair_input,
                    output_dir=output_dir
                    / f"event-{event_index:02d}-status-{repair_index:02d}-trace",
                    instruction_limit=instruction_limit,
                    consumption_timeout=consumption_timeout,
                    timeout_seconds=timeout_seconds,
                )
                calibration_runs.append(run)
                if not run["trace_complete"]:
                    break
                trace_mmio = Path(run["mmio_trace"])
                trace_bb = Path(run["bb_trace"])
                mmio_events = parse_mmio_trace(trace_mmio)
                bb_events = parse_bb_trace(trace_bb)
                source_reads = eligible_source_reads(mmio_events, contexts)
                windows = transaction_windows(bb_events, source_reads, call_specs)
                if previous_mapping is not None:
                    assert previous_call_index is not None
                    anchor = select_transaction_window(
                        windows,
                        call_index=previous_call_index,
                        byte_length=len(previous_mapping),
                        required_fuzz_offsets=[
                            int(row["fuzz_offset"]) for row in previous_mapping
                        ],
                    )
                    after_event_id = anchor.return_event_id
                    before_event_id = next_call_boundary(windows, anchor)
                try:
                    window = select_transaction_window(
                        windows,
                        call_index=call_index,
                        byte_length=len(payload),
                        after_event_id=after_event_id,
                        before_event_id=before_event_id,
                    )
                    repaired = True
                    break
                except ValueError:
                    continue
            if not repaired:
                raise original_error

        # A receive transaction is not complete merely because N data bytes
        # were read. Clear learned nonzero error-status alternatives observed
        # after the final Source read so the driver can return normally.
        for completion_index in range(4):
            last_source_event = window.source_reads[-1].event_id
            completion_repairs = [
                repair
                for repair in status_selector_repairs(
                    mmio_events=mmio_events,
                    window=window,
                    models=set_models,
                    already_patched=repaired_offsets,
                    allowed_peripheral_pages=source_peripheral_pages,
                )
                if int(repair["event_id"]) > last_source_event
            ]
            if not completion_repairs:
                break
            repair = completion_repairs[0]
            mutable = bytearray(current_input)
            offset = int(repair["fuzz_offset"])
            if not 0 <= offset < len(mutable):
                break
            mutable[offset] = int(repair["selector_byte"])
            current_input = bytes(mutable)
            repaired_offsets.add(offset)
            status_repairs.append(repair)
            completion_input = output_dir / (
                f"event-{event_index:02d}-completion-{completion_index:02d}.bin"
            )
            completion_input.parent.mkdir(parents=True, exist_ok=True)
            completion_input.write_bytes(current_input)
            run = run_emu(
                fuzzware_root=fuzzware_root,
                target_root=target_root,
                config=config,
                input_path=completion_input,
                output_dir=output_dir
                / f"event-{event_index:02d}-completion-{completion_index:02d}-trace",
                instruction_limit=instruction_limit,
                consumption_timeout=consumption_timeout,
                timeout_seconds=timeout_seconds,
            )
            calibration_runs.append(run)
            if not run["trace_complete"]:
                break
            trace_mmio = Path(run["mmio_trace"])
            trace_bb = Path(run["bb_trace"])
            mmio_events = parse_mmio_trace(trace_mmio)
            bb_events = parse_bb_trace(trace_bb)
            source_reads = eligible_source_reads(mmio_events, contexts)
            windows = transaction_windows(bb_events, source_reads, call_specs)
            if previous_mapping is not None:
                assert previous_call_index is not None
                anchor = select_transaction_window(
                    windows,
                    call_index=previous_call_index,
                    byte_length=len(previous_mapping),
                    required_fuzz_offsets=[
                        int(row["fuzz_offset"]) for row in previous_mapping
                    ],
                )
                after_event_id = anchor.return_event_id
                before_event_id = next_call_boundary(windows, anchor)
            window = select_transaction_window(
                windows,
                call_index=call_index,
                byte_length=len(payload),
                after_event_id=after_event_id,
                before_event_id=before_event_id,
            )
        current_input, mapping = patch_event(current_input, payload, window)
        for row in mapping:
            row["plan_event_id"] = event["event_id"]
            row["call_site_id"] = window.call_site_id
        event_mappings.append(
            {
                "event_id": event["event_id"],
                "call_index": call_index,
                "transaction_group": int(event.get("transaction_group", 0)),
                "call_site_id": window.call_site_id,
                "entry_event_id": window.entry_event_id,
                "return_event_id": window.return_event_id,
                "mapping": mapping,
                "status_repairs": list(status_repairs),
                "control_repairs": [
                    row
                    for row in control_repairs
                    if row["interrupt_event_id"]
                    == f"rf2xx-frame-{int(event.get('transaction_group', 0)):02d}-irq"
                ],
            }
        )
        previous_mapping = mapping
        previous_call_index = call_index

        stage_input = output_dir / f"stage-{event_index:02d}.bin"
        stage_input.parent.mkdir(parents=True, exist_ok=True)
        stage_input.write_bytes(current_input)
        if event_index + 1 < len(events):
            run = run_emu(
                fuzzware_root=fuzzware_root,
                target_root=target_root,
                config=config,
                input_path=stage_input,
                output_dir=output_dir / f"stage-{event_index:02d}-trace",
                instruction_limit=instruction_limit,
                consumption_timeout=consumption_timeout,
                timeout_seconds=timeout_seconds,
            )
            calibration_runs.append(run)
            if not run["trace_complete"]:
                raise ValueError(
                    f"calibration replay for event {event['event_id']} produced no traces"
                )
            trace_mmio = Path(run["mmio_trace"])
            trace_bb = Path(run["bb_trace"])

    final_input = output_dir / "validation_input.bin"
    final_input.write_bytes(current_input)
    return final_input, event_mappings, calibration_runs


def classify_variant_runs(
    *,
    runs: list[dict[str, Any]],
    mappings: list[dict[str, Any]],
    sink_address: int,
    sink_block_interval: tuple[int, int],
    sink_effect_intervals: list[tuple[int, int]],
    binary: Path,
) -> tuple[str, str, list[dict[str, Any]]]:
    flattened_mapping = [
        row
        for event in mappings
        for row in event.get("mapping", []) or []
    ]
    evidence_rows: list[dict[str, Any]] = []
    for run in runs:
        if not run["trace_complete"]:
            evidence_rows.append(
                {
                    "source_observed": False,
                    "sink_observed": False,
                    "fault_signature": run["fault_signature"],
                    "execution_failed": True,
                }
            )
            continue
        mmio_events = parse_mmio_trace(Path(run["mmio_trace"]))
        bb_events = parse_bb_trace(Path(run["bb_trace"]))
        fault_signature = run["fault_signature"]
        causal_evidence = None
        ram_trace = run.get("ram_trace")
        parsed_fault = None
        if fault_signature:
            parsed_fault = parse_fault_signature(fault_signature)
        if parsed_fault is not None and ram_trace and Path(ram_trace).exists():
            ram_events = parse_ram_trace(Path(ram_trace))
            try:
                fault_interval = function_interval(binary, parsed_fault.pc)
            except ValueError:
                fault_interval = None
            causal_evidence = causal_sink_fault(
                ram_events,
                fault_signature=fault_signature,
                sink_effect_intervals=sink_effect_intervals,
                fault_function_interval=fault_interval,
            )
            if causal_evidence is None:
                log_text = Path(run["log_path"]).read_text(
                    encoding="utf-8", errors="replace"
                )
                causal_evidence = causal_nonreturning_sink_stack_fault(
                    ram_events,
                    bb_events,
                    fault_signature=fault_signature,
                    sink_block_interval=sink_block_interval,
                    sink_return_address=sink_block_interval[1],
                    sink_effect_intervals=sink_effect_intervals,
                    stack_pointers=runtime_stack_pointers(log_text),
                )
        evidence_rows.append(
            {
                "source_observed": mapping_observed(mmio_events, flattened_mapping),
                "sink_observed": sink_address_observed(
                    bb_events,
                    sink_address,
                    block_intervals={
                        sink_block_interval[0]: sink_block_interval
                    },
                ),
                "fault_signature": fault_signature,
                "causal_fault_evidence": causal_evidence,
                "execution_failed": run["timed_out"] or not run["trace_complete"],
            }
        )

    if len(evidence_rows) >= 2 and all(
        row["source_observed"]
        and row["sink_observed"]
        and row["fault_signature"]
        and row["causal_fault_evidence"]
        for row in evidence_rows
    ):
        signatures = {row["fault_signature"] for row in evidence_rows}
        if len(signatures) == 1:
            return POC, "REPRODUCIBLE_CAUSAL_SOURCE_BOUND_SINK_FAULT", evidence_rows
        return INCONCLUSIVE, "FAULT_NOT_REPRODUCIBLE", evidence_rows
    if any(row["execution_failed"] for row in evidence_rows):
        return INCONCLUSIVE, "REHOSTING_EXECUTION_FAILED", evidence_rows
    if not all(row["source_observed"] for row in evidence_rows):
        return INCONCLUSIVE, "SOURCE_BOUNDARY_NOT_OBSERVED", evidence_rows
    if not all(row["sink_observed"] for row in evidence_rows):
        return INCONCLUSIVE, "SINK_NOT_REACHED", evidence_rows
    return INCONCLUSIVE, "NO_RUNTIME_FAULT", evidence_rows


def input_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def append_replay_tail(path: Path, byte_count: int, repeat_bytes: int = 128) -> None:
    """Append deterministic control-plane bytes after calibrated Source input."""
    if byte_count <= 0:
        return
    payload = path.read_bytes()
    if not payload:
        raise ValueError("cannot extend an empty calibrated input")
    tail = payload[-min(len(payload), max(1, repeat_bytes)) :]
    repeats = (byte_count + len(tail) - 1) // len(tail)
    path.write_bytes(payload + (tail * repeats)[:byte_count])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fuzzware-root", required=True, type=Path)
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--semantic-manifest", required=True, type=Path)
    parser.add_argument("--base-input", required=True, type=Path)
    parser.add_argument("--baseline-mmio", required=True, type=Path)
    parser.add_argument("--baseline-bb", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--instruction-limit", type=int, default=3_000_000)
    parser.add_argument("--consumption-timeout", type=int, default=1_000_000)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--replay-tail-bytes", type=int, default=0)
    args = parser.parse_args()

    evidence = load_json(args.evidence)
    plan = load_json(args.plan)
    manifest = load_json(args.semantic_manifest)
    sink_address = parse_address(plan.get("sink_checkpoint", {}).get("effect_address"))
    if sink_address is None:
        raise ValueError("Execution Plan has no executable Sink checkpoint")
    sink_function_interval = function_interval(args.binary, sink_address)
    sink_block = basic_block_interval(args.binary, sink_address)
    primitive_identity = str(
        evidence.get("sink_definition", {}).get("proof", {}).get(
            "primitive_identity", ""
        )
    ).strip()
    sink_definition = evidence.get("sink_definition", {}) or {}
    body_effect_identity = str(sink_definition.get("callee", "")).strip()
    effect_identity = primitive_identity or body_effect_identity
    sink_effect_intervals = named_function_intervals(
        args.binary,
        {effect_identity} if effect_identity else set(),
    )
    if not sink_effect_intervals:
        raise ValueError("ELF has no function interval for the primitive Sink effect")

    variant_results: list[dict[str, Any]] = []
    for variant in manifest.get("variants", []) or []:
        variant_id = str(variant["variant_id"])
        variant_dir = args.output_dir / variant_id
        try:
            final_input, mappings, calibration_runs = calibrate_variant(
                variant=variant,
                plan=plan,
                base_input=args.base_input,
                baseline_mmio=args.baseline_mmio,
                baseline_bb=args.baseline_bb,
                binary=args.binary,
                evidence=evidence,
                config=args.config,
                fuzzware_root=args.fuzzware_root,
                target_root=args.target_root,
                output_dir=variant_dir,
                instruction_limit=args.instruction_limit,
                consumption_timeout=args.consumption_timeout,
                timeout_seconds=args.timeout_seconds,
            )
        except (OSError, ValueError) as exc:
            if isinstance(exc, SourceCallNotObserved):
                reason_code = "TARGET_RECEIVE_CALL_NOT_REACHED"
            elif isinstance(exc, SourceTransactionSizeMismatch):
                reason_code = "SOURCE_TRANSACTION_SIZE_MISMATCH"
            else:
                reason_code = "PERIPHERAL_TRANSACTION_CALIBRATION_FAILED"
            variant_results.append(
                {
                    "variant_id": variant_id,
                    "result_class": INCONCLUSIVE,
                    "reason_code": reason_code,
                    "detail": str(exc),
                }
            )
            continue

        append_replay_tail(final_input, args.replay_tail_bytes)
        replay_runs = [
            run_emu(
                fuzzware_root=args.fuzzware_root,
                target_root=args.target_root,
                config=args.config,
                input_path=final_input,
                output_dir=variant_dir / f"replay-{index:02d}",
                instruction_limit=args.instruction_limit,
                consumption_timeout=args.consumption_timeout,
                timeout_seconds=args.timeout_seconds,
                ram_trace_enabled=True,
            )
            for index in range(max(2, int(plan.get("replay_count", 2))))
        ]
        result_class, reason, replay_evidence = classify_variant_runs(
            runs=replay_runs,
            mappings=mappings,
            sink_address=sink_address,
            sink_block_interval=sink_block,
            sink_effect_intervals=sink_effect_intervals,
            binary=args.binary,
        )
        variant_results.append(
            {
                "variant_id": variant_id,
                "result_class": result_class,
                "reason_code": reason,
                "input_file": str(final_input),
                "input_sha256": input_sha256(final_input),
                "event_mappings": mappings,
                "replay_tail_bytes": args.replay_tail_bytes,
                "calibration_runs": calibration_runs,
                "replay_runs": replay_runs,
                "replay_evidence": replay_evidence,
            }
        )

    successful = next(
        (row for row in variant_results if row["result_class"] == POC), None
    )
    if successful is not None:
        result_class = POC
        reason_code = str(successful["reason_code"])
    else:
        result_class = INCONCLUSIVE
        reason_code = (
            str(variant_results[0]["reason_code"])
            if variant_results
            else "NO_VALIDATION_INPUTS"
        )
    result = {
        "schema_version": "ct-mini-validation-result-v1",
        "alert_id": plan.get("alert_id", ""),
        "plan_id": plan.get("plan_id", ""),
        "result_class": result_class,
        "reason_code": reason_code,
        "policy": {
            "known_cve_input_used": False,
            "source_boundary_injection_required": True,
            "sink_hit_without_fault_is_inconclusive": True,
            "fuzzware_modified": False,
        },
        "inputs": {
            "binary_sha256": sha256_file(args.binary),
            "config_sha256": sha256_file(args.config),
            "plan_sha256": sha256_file(args.plan),
        },
        "sink_checkpoint": {
            "effect_address": f"0x{sink_address:x}",
            "function_interval": [
                f"0x{sink_function_interval[0]:x}",
                f"0x{sink_function_interval[1]:x}",
            ],
            "basic_block_interval": [
                f"0x{sink_block[0]:x}",
                f"0x{sink_block[1]:x}",
            ],
            "effect_intervals": [
                [f"0x{start:x}", f"0x{end:x}"]
                for start, end in sink_effect_intervals
            ],
        },
        "variants": variant_results,
    }
    write_json(args.result, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
