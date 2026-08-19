#!/usr/bin/env python3
"""Build the UART phase of the RIOT CORD Source-boundary execution plan."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import yaml


UART_EXCEPTION = 21  # Recovered from the ELF vector entry for isr_uart0.
# shell_readline reaches this block after uart_init installed the RX callback
# and immediately before the shell blocks waiting for its first input line.
UART_TRIGGER = 0x20DA82
UART_FR_PC = 0x20D528
UART_FR = 0x4000C018
UART_DR_PC = 0x20D54C
UART_DR = 0x4000C000
UART_TX_READY_PC = 0x20D50C
UART_TX_EMPTY_PC = 0x20D4FC


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--uart-offset", type=lambda value: int(value, 0))
    parser.add_argument(
        "--command",
        default="cord_lc [2001:db8::1]:5683 -r resource\n",
    )
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    base_config = args.target / "config.yml"
    base_input = args.target / "input-calibration-base.bin"
    config = yaml.safe_load(base_config.read_text(encoding="utf-8")) or {}

    # TX status is environmental readiness, not validation input. Keeping it
    # symbolic consumes the input stream during shell echo and can deadlock in
    # uart_write. RX status/data remain input-backed at their own PC contexts.
    config.setdefault("mmio_models", {}).setdefault("bitextract", {}).pop(
        "pc_0020d50c_mmio_4000c018", None
    )
    constants = config["mmio_models"].setdefault("constant", {})
    constants["ct_uart_tx_fifo_available"] = {
        "access_size": 4,
        "addr": UART_FR,
        "pc": UART_TX_READY_PC,
        "val": 0,
    }
    constants["ct_uart_tx_empty"] = {
        "access_size": 4,
        "addr": UART_FR,
        "pc": UART_TX_EMPTY_PC,
        "val": 0x80,
    }

    # Trigger the real UART0 ISR from RIOT's stable idle loop. The ISR's
    # existing MMIO models expose UART_FR and UART_DR through Fuzzware input.
    config.setdefault("interrupt_triggers", {})["ct_uart_shell_input"] = {
        "addr": UART_TRIGGER,
        "irq": UART_EXCEPTION,
        "num_pends": 1,
        "num_skips": 0,
    }
    config["memory_map"]["text"]["file"] = "../firmware.bin"

    output_config = args.out / "config.yml"
    output_input = args.out / "input.bin"
    output_manifest = args.out / "execution_plan.json"
    input_bytes = bytearray(base_input.read_bytes())
    if len(input_bytes) < 0x4000:
        input_bytes.extend(b"\0" * (0x4000 - len(input_bytes)))

    phase = "UART_OFFSET_CALIBRATION"
    if args.uart_offset is not None:
        phase = "UART_COMMAND_REPLAY"
        encoded = args.command.encode("ascii")
        # Seed only the first character. Later input offsets depend on MMIO
        # consumed between scheduler wakeups and are calibrated iteratively.
        stream = bytearray((0x00, encoded[0], 0x01))
        required = args.uart_offset + 3
        if len(input_bytes) < required:
            input_bytes.extend(b"\0" * (required - len(input_bytes)))
        input_bytes[args.uart_offset:required] = stream

    output_config.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    output_input.write_bytes(input_bytes)
    manifest = {
        "schema_version": "ct-mini-riot-cord-execution-plan-v1",
        "phase": phase,
        "alert_id": "chain:sink:6c92d9a4f2748d31fa38",
        "binary_sha256": sha256(args.target / "firmware.elf"),
        "base_config_sha256": sha256(base_config),
        "effective_config": str(output_config),
        "effective_config_sha256": sha256(output_config),
        "input": str(output_input),
        "input_sha256": sha256(output_input),
        "uart": {
            "exception": UART_EXCEPTION,
            "trigger_address": hex(UART_TRIGGER),
            "fr_context": {"pc": hex(UART_FR_PC), "address": hex(UART_FR)},
            "dr_context": {"pc": hex(UART_DR_PC), "address": hex(UART_DR)},
            "input_offset": args.uart_offset,
            "command": args.command if args.uart_offset is not None else None,
            "configured_prefix_length": 1 if args.uart_offset is not None else 0,
        },
        "remaining_phase": {
            "source": "CC2538 RF peripheral",
            "event": "CoAP response matching the emitted request token/message ID",
            "sink": "_on_lookup@0x201130 -> memset@0x201186",
        },
        "policy": {
            "source_boundary_injection": True,
            "program_counter_forcing": False,
            "branch_patching": False,
            "direct_source_buffer_write": False,
            "known_crashing_input_used": False,
        },
    }
    output_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
