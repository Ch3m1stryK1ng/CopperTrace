#!/usr/bin/env python3
"""Calibrate control-plane peripheral transactions before Source injection.

The calibrator is deliberately protocol-neutral.  A contract names a resolved
callsite, the dynamic invocation to adjust, candidate return bytes, and the
basic-block checkpoint that proves the firmware accepted that value.  The
tool then uses ordinary Fuzzware replays to discover which consumed MMIO byte
actually controls the call's return value.

This stage never patches firmware memory or program control flow.  Its output
is a longer/fixed Fuzzware input prefix that makes a normal receive path ready;
Alert-specific payload bytes are still installed later by Source calibration.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Callable

from calibrate_fuzzware_input import (
    eligible_source_reads,
    source_contexts,
    transaction_windows,
)
from fuzzware_trace import parse_bb_trace, parse_mmio_trace
from run_fuzzware_validation import run_emu
from validation_common import load_json, parse_address, sha256_file, write_json


RunFunction = Callable[..., dict[str, Any]]


def extend_input(data: bytes, *, extra_bytes: int, tail_bytes: int) -> bytes:
    """Extend a finite Fuzzware seed without inventing a semantic payload."""
    if extra_bytes <= 0:
        return data
    if not data:
        raise ValueError("cannot extend an empty readiness seed")
    width = min(max(1, tail_bytes), len(data))
    tail = data[-width:]
    repeats = (extra_bytes + len(tail) - 1) // len(tail)
    return data + (tail * repeats)[:extra_bytes]


def checkpoint_observed(bb_path: Path, address: int) -> bool:
    return any(
        (event.bb_addr & ~1) == (address & ~1)
        for event in parse_bb_trace(bb_path)
    )


def observed_source_contexts(window: Any) -> list[dict[str, str]]:
    """Return the exact MMIO contexts consumed by one accepted transaction."""
    return [
        {"pc": f"0x{pc:x}", "register_address": f"0x{address:x}"}
        for pc, address in sorted(
            {(event.pc & ~1, event.address) for event in window.source_reads}
        )
    ]


def _call_spec(step: dict[str, Any]) -> dict[str, Any]:
    entry = parse_address(step.get("callee_entry"))
    returned = parse_address(step.get("return_address"))
    if entry is None or returned is None:
        raise ValueError(
            f"readiness step {step.get('step_id', '')!r} has no call interval"
        )
    return {
        "call_index": 0,
        "call_site_id": str(step.get("call_site_id", "")),
        "callee_entry": entry & ~1,
        "return_address": returned & ~1,
    }


def invocation_window(
    *,
    step: dict[str, Any],
    evidence: dict[str, Any],
    mmio_path: Path,
    bb_path: Path,
) -> Any:
    """Return the requested dynamic invocation of a control call."""
    contexts = source_contexts(evidence)
    mmio_events = parse_mmio_trace(mmio_path)
    bb_events = parse_bb_trace(bb_path)
    reads = eligible_source_reads(mmio_events, contexts)
    windows = transaction_windows(bb_events, reads, [_call_spec(step)])
    invocation = int(step.get("invocation_index", 0))
    if invocation < 0 or invocation >= len(windows):
        raise ValueError(
            f"step {step.get('step_id', '')!r} requested invocation {invocation}, "
            f"but only {len(windows)} completed calls were observed"
        )
    return windows[invocation]


def checkpoint_after_invocation(
    *,
    step: dict[str, Any],
    evidence: dict[str, Any],
    mmio_path: Path,
    bb_path: Path,
    checkpoint: int,
) -> bool:
    """Bind a checkpoint to one dynamic call, not the whole repeated trace."""
    contexts = source_contexts(evidence)
    mmio_events = parse_mmio_trace(mmio_path)
    bb_events = parse_bb_trace(bb_path)
    reads = eligible_source_reads(mmio_events, contexts)
    windows = transaction_windows(bb_events, reads, [_call_spec(step)])
    invocation = int(step.get("invocation_index", 0))
    if invocation < 0 or invocation >= len(windows):
        return False
    window = windows[invocation]
    next_entry = (
        windows[invocation + 1].entry_event_id
        if invocation + 1 < len(windows)
        else 1 << 63
    )
    return any(
        window.return_event_id <= event.event_id < next_entry
        and (event.bb_addr & ~1) == (checkpoint & ~1)
        for event in bb_events
    )


def calibrate_readiness(
    *,
    contract: dict[str, Any],
    evidence: dict[str, Any],
    base_input: Path,
    config: Path,
    fuzzware_root: Path,
    target_root: Path,
    output_dir: Path,
    instruction_limit: int,
    consumption_timeout: int,
    timeout_seconds: int,
    runner: RunFunction = run_emu,
) -> dict[str, Any]:
    """Satisfy ordered peripheral readiness checkpoints by bounded replay."""
    output_dir.mkdir(parents=True, exist_ok=True)
    policy = contract.get("seed_extension", {}) or {}
    current = extend_input(
        base_input.read_bytes(),
        extra_bytes=int(policy.get("extra_bytes", 0)),
        tail_bytes=int(policy.get("repeat_tail_bytes", 128)),
    )
    working_input = output_dir / "stage-initial.bin"
    working_input.write_bytes(current)
    initial = runner(
        fuzzware_root=fuzzware_root,
        target_root=target_root,
        config=config,
        input_path=working_input,
        output_dir=output_dir / "stage-initial-trace",
        instruction_limit=instruction_limit,
        consumption_timeout=consumption_timeout,
        timeout_seconds=timeout_seconds,
    )
    if not initial.get("trace_complete"):
        raise ValueError("initial readiness replay produced no complete traces")

    current_run = initial
    patches: list[dict[str, Any]] = []
    stages: list[dict[str, Any]] = []
    max_trials = int(contract.get("max_trials_per_step", 32))

    for step_index, step in enumerate(contract.get("steps", []) or []):
        checkpoint = parse_address(step.get("checkpoint"))
        if checkpoint is None:
            raise ValueError(f"readiness step {step_index} has no checkpoint")
        bb_path = Path(str(current_run["bb_trace"]))
        if checkpoint_observed(bb_path, checkpoint) and not step.get(
            "force_recalibration", False
        ):
            stages.append(
                {
                    "step_id": step.get("step_id", f"step-{step_index}"),
                    "status": "already_satisfied",
                    "checkpoint": f"0x{checkpoint:x}",
                }
            )
            continue

        window = invocation_window(
            step=step,
            evidence=evidence,
            mmio_path=Path(str(current_run["mmio_trace"])),
            bb_path=bb_path,
        )
        desired_values = [int(value) & 0xFF for value in step.get("values", [])]
        if not desired_values:
            raise ValueError(
                f"readiness step {step.get('step_id', '')!r} has no candidate values"
            )

        # Return/output bytes are usually later in an SPI receive transaction.
        # Trying reads in reverse order is only a search order; every accepted
        # patch must independently reach the contract checkpoint.
        candidates = list(reversed(window.source_reads))
        reject_values = [int(value) & 0xFF for value in step.get("reject_values", [])]
        require_causal = bool(step.get("require_causal", False))
        if require_causal and not reject_values:
            raise ValueError(
                f"readiness step {step.get('step_id', '')!r} requires a reject value"
            )
        accepted: tuple[dict[str, Any], bytes] | None = None
        trial_count = 0
        for event in candidates:
            rejection_proved = not require_causal
            rejection_runs: list[dict[str, Any]] = []
            if require_causal:
                for reject_index, reject_value in enumerate(reject_values):
                    rejected_trial = bytearray(current)
                    offset = int(event.fuzz_index)
                    if not 0 <= offset < len(rejected_trial):
                        continue
                    rejected_trial[offset] = reject_value
                    rejected_input = output_dir / (
                        f"step-{step_index:02d}-reject-"
                        f"{int(event.fuzz_index):08d}-{reject_index:02d}.bin"
                    )
                    rejected_input.write_bytes(rejected_trial)
                    rejected_run = runner(
                        fuzzware_root=fuzzware_root,
                        target_root=target_root,
                        config=config,
                        input_path=rejected_input,
                        output_dir=output_dir
                        / (
                            f"step-{step_index:02d}-reject-"
                            f"{int(event.fuzz_index):08d}-{reject_index:02d}-trace"
                        ),
                        instruction_limit=instruction_limit,
                        consumption_timeout=consumption_timeout,
                        timeout_seconds=timeout_seconds,
                    )
                    rejection_runs.append(
                        {
                            "fuzz_offset": offset,
                            "reject_byte": reject_value,
                            "checkpoint_absent": bool(
                                rejected_run.get("trace_complete")
                                and not checkpoint_after_invocation(
                                    step=step,
                                    evidence=evidence,
                                    mmio_path=Path(str(rejected_run["mmio_trace"])),
                                    bb_path=Path(str(rejected_run["bb_trace"])),
                                    checkpoint=checkpoint,
                                )
                            ),
                        }
                    )
                    if rejection_runs[-1]["checkpoint_absent"]:
                        rejection_proved = True
                        break
            if not rejection_proved:
                continue
            for value in desired_values:
                if trial_count >= max_trials:
                    break
                trial_count += 1
                offset = int(event.fuzz_index)
                if not 0 <= offset < len(current):
                    continue
                trial = bytearray(current)
                previous = trial[offset]
                trial[offset] = value
                trial_input = output_dir / (
                    f"step-{step_index:02d}-trial-{trial_count:02d}.bin"
                )
                trial_input.write_bytes(trial)
                trial_run = runner(
                    fuzzware_root=fuzzware_root,
                    target_root=target_root,
                    config=config,
                    input_path=trial_input,
                    output_dir=output_dir
                    / f"step-{step_index:02d}-trial-{trial_count:02d}-trace",
                    instruction_limit=instruction_limit,
                    consumption_timeout=consumption_timeout,
                    timeout_seconds=timeout_seconds,
                )
                if not trial_run.get("trace_complete"):
                    continue
                if checkpoint_after_invocation(
                    step=step,
                    evidence=evidence,
                    mmio_path=Path(str(trial_run["mmio_trace"])),
                    bb_path=Path(str(trial_run["bb_trace"])),
                    checkpoint=checkpoint,
                ):
                    accepted = (
                        {
                            "step_id": step.get("step_id", f"step-{step_index}"),
                            "call_site_id": window.call_site_id,
                            "invocation_index": int(step.get("invocation_index", 0)),
                            "fuzz_offset": offset,
                            "previous_byte": previous,
                            "selected_byte": value,
                            "source_pc": f"0x{event.pc & ~1:x}",
                            "register_address": f"0x{event.address:x}",
                            "checkpoint": f"0x{checkpoint:x}",
                            "trial_count": trial_count,
                            "causal_rejection_proved": require_causal,
                            "rejection_trials": rejection_runs,
                        },
                        bytes(trial),
                    )
                    current_run = trial_run
                    break
            if accepted is not None or trial_count >= max_trials:
                break
        if accepted is None:
            raise ValueError(
                f"no bounded MMIO-byte mutation satisfied readiness step "
                f"{step.get('step_id', step_index)!r}"
            )
        patch, current = accepted
        patches.append(patch)
        stages.append({"status": "patched", **patch})

    target = parse_address(contract.get("target_checkpoint"))
    if target is not None and not checkpoint_observed(
        Path(str(current_run["bb_trace"])), target
    ):
        raise ValueError(f"final readiness checkpoint 0x{target:x} was not reached")

    active_contexts: list[dict[str, str]] = []
    active_transaction = contract.get("active_source_transaction")
    if active_transaction:
        active_window = invocation_window(
            step=active_transaction,
            evidence=evidence,
            mmio_path=Path(str(current_run["mmio_trace"])),
            bb_path=Path(str(current_run["bb_trace"])),
        )
        active_contexts = observed_source_contexts(active_window)
        if not active_contexts:
            raise ValueError("active Source transaction consumed no Source MMIO reads")

    final_input = output_dir / "readiness_input.bin"
    final_input.write_bytes(current)
    manifest = {
        "schema_version": "ct-mini-peripheral-readiness-v1",
        "base_input": str(base_input),
        "base_input_sha256": sha256_file(base_input),
        "config": str(config),
        "config_sha256": sha256_file(config),
        "readiness_input": str(final_input),
        "readiness_input_sha256": sha256_file(final_input),
        "baseline_mmio": str(current_run["mmio_trace"]),
        "baseline_bb": str(current_run["bb_trace"]),
        "target_checkpoint": (
            f"0x{target:x}" if target is not None else None
        ),
        "active_source_contexts": active_contexts,
        "stages": stages,
        "patches": patches,
        "policy": {
            "firmware_patched": False,
            "program_counter_forced": False,
            "source_buffer_written": False,
            "known_vulnerability_input_used": False,
            "bounded_control_plane_replay": True,
        },
    }
    write_json(output_dir / "readiness_manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--base-input", required=True, type=Path)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--fuzzware-root", required=True, type=Path)
    parser.add_argument("--target-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--instruction-limit", type=int, default=3_000_000)
    parser.add_argument("--consumption-timeout", type=int, default=1_000_000)
    parser.add_argument("--timeout-seconds", type=int, default=180)
    args = parser.parse_args()
    calibrate_readiness(
        contract=load_json(args.contract),
        evidence=load_json(args.evidence),
        base_input=args.base_input,
        config=args.config,
        fuzzware_root=args.fuzzware_root,
        target_root=args.target_root,
        output_dir=args.output_dir,
        instruction_limit=args.instruction_limit,
        consumption_timeout=args.consumption_timeout,
        timeout_seconds=args.timeout_seconds,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
