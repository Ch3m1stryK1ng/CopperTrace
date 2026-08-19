#!/usr/bin/env python3
"""Compile structured IEEE 802.15.4 frames into RF2xx Source transactions.

The compiler is protocol-specific but vulnerability-agnostic.  It preserves the
unchanged CopperTrace Alert and replaces only SOURCE_PAYLOAD templates/events.
"""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any

from validation_common import load_json, write_json


FRAME_TYPES = {
    "BEACON": 0,
    "DATA": 1,
    "ACK": 2,
    "MAC_COMMAND": 3,
}
ADDRESS_MODES = {
    "NONE": 0,
    "SHORT": 2,
    "EXTENDED": 3,
}
FRAME_VERSIONS = {
    "IEEE802154_2003": 0,
    "IEEE802154_2006": 1,
    "IEEE802154": 2,
}
RF2XX_FRAME_HEADER_SIZE = 2
RF2XX_FRAME_FCS_LENGTH = 2
RF2XX_FRAME_FOOTER_SIZE = 3


def _bounded_int(value: Any, *, bits: int, name: str) -> int:
    result = int(value, 0) if isinstance(value, str) else int(value)
    if not 0 <= result < (1 << bits):
        raise ValueError(f"{name} does not fit in {bits} bits")
    return result


def _enum_value(table: dict[str, int], value: Any, name: str) -> int:
    key = str(value).upper()
    if key not in table:
        raise ValueError(f"unsupported {name}: {value!r}")
    return table[key]


def _fixed_hex(value: Any, *, size: int, name: str) -> bytes:
    result = bytes.fromhex(str(value))
    if len(result) != size:
        raise ValueError(f"{name} must contain exactly {size} bytes")
    return result


def encode_fcf(frame: dict[str, Any]) -> bytes:
    frame_type = _enum_value(FRAME_TYPES, frame["frame_type"], "frame_type")
    dst_mode = _enum_value(
        ADDRESS_MODES, frame.get("dst_addr_mode", "NONE"), "dst_addr_mode"
    )
    src_mode = _enum_value(
        ADDRESS_MODES, frame.get("src_addr_mode", "NONE"), "src_addr_mode"
    )
    version = _enum_value(
        FRAME_VERSIONS,
        frame.get("frame_version", "IEEE802154_2003"),
        "frame_version",
    )
    security = bool(frame.get("security_enabled", False))
    if security:
        raise ValueError("security-enabled frames require an auxiliary-header compiler")

    value = frame_type
    value |= int(bool(frame.get("frame_pending", False))) << 4
    value |= int(bool(frame.get("ack_request", False))) << 5
    value |= int(bool(frame.get("pan_id_compression", False))) << 6
    value |= int(bool(frame.get("sequence_suppression", False))) << 8
    value |= int(bool(frame.get("ie_present", False))) << 9
    value |= dst_mode << 10
    value |= version << 12
    value |= src_mode << 14
    return value.to_bytes(2, "little")


def encode_addressing(frame: dict[str, Any]) -> bytes:
    dst_mode = _enum_value(
        ADDRESS_MODES, frame.get("dst_addr_mode", "NONE"), "dst_addr_mode"
    )
    src_mode = _enum_value(
        ADDRESS_MODES, frame.get("src_addr_mode", "NONE"), "src_addr_mode"
    )
    pan_compression = bool(frame.get("pan_id_compression", False))
    result = bytearray()

    if dst_mode:
        result.extend(
            _bounded_int(
                frame.get("dst_pan_id", 0xFFFF), bits=16, name="dst_pan_id"
            ).to_bytes(2, "little")
        )
        if dst_mode == ADDRESS_MODES["SHORT"]:
            result.extend(
                _bounded_int(
                    frame.get("dst_short", 0xFFFF), bits=16, name="dst_short"
                ).to_bytes(2, "little")
            )
        else:
            result.extend(
                _fixed_hex(
                    frame.get("dst_extended", "0000000000000000"),
                    size=8,
                    name="dst_extended",
                )
            )

    if src_mode:
        if not pan_compression:
            result.extend(
                _bounded_int(
                    frame.get("src_pan_id", 0xFFFF), bits=16, name="src_pan_id"
                ).to_bytes(2, "little")
            )
        if src_mode == ADDRESS_MODES["SHORT"]:
            result.extend(
                _bounded_int(
                    frame.get("src_short", 0), bits=16, name="src_short"
                ).to_bytes(2, "little")
            )
        else:
            result.extend(
                _fixed_hex(
                    frame.get("src_extended", "0000000000000000"),
                    size=8,
                    name="src_extended",
                )
            )
    return bytes(result)


def compile_frame(frame: dict[str, Any]) -> dict[str, Any]:
    fcf = encode_fcf(frame)
    sequence = _bounded_int(frame.get("sequence", 0), bits=8, name="sequence")
    addressing = encode_addressing(frame)
    payload = bytes.fromhex(str(frame["payload_hex"]))
    fcs = _fixed_hex(frame.get("fcs_hex", "0000"), size=2, name="fcs_hex")
    status = _bounded_int(frame.get("status", 0), bits=8, name="status")
    lqi = _bounded_int(frame.get("lqi", 0), bits=8, name="lqi")

    psdu = fcf + bytes([sequence]) + addressing + payload
    phr = len(psdu) + RF2XX_FRAME_FCS_LENGTH
    if not 5 <= phr <= 127:
        raise ValueError(f"RF2xx PHR {phr} is outside the supported range 5..127")

    prefix = bytes([status, phr])
    body = (
        bytes([status, phr])
        + psdu
        + fcs
        + bytes([lqi])
        + bytes(RF2XX_FRAME_FOOTER_SIZE - 1)
    )
    expected_body_length = RF2XX_FRAME_HEADER_SIZE + phr + RF2XX_FRAME_FOOTER_SIZE
    if len(body) != expected_body_length:
        raise AssertionError("RF2xx frame compiler produced an inconsistent length")

    return {
        "fcf": fcf,
        "addressing": addressing,
        "payload": payload,
        "fcs": fcs,
        "phr": phr,
        "prefix": prefix,
        "body": body,
    }


def _field(
    name: str,
    role: str,
    offset: int,
    value: bytes,
    evidence_ref: str,
) -> dict[str, Any]:
    return {
        "name": name,
        "role": role,
        "offset": offset,
        "size": len(value),
        "encoding": "bytes_hex",
        "candidates": [value.hex()],
        "evidence_ref": evidence_ref,
    }


def _frame_templates(
    frame: dict[str, Any], compiled: dict[str, Any], frame_index: int
) -> tuple[dict[str, Any], dict[str, Any]]:
    protocol_ref = str(frame["protocol_evidence_ref"])
    payload_ref = str(frame["payload_evidence_ref"])
    prefix_id = f"rf2xx-frame-{frame_index:02d}-prefix"
    body_id = f"rf2xx-frame-{frame_index:02d}-body"
    prefix = compiled["prefix"]
    body = compiled["body"]

    prefix_template = {
        "template_id": prefix_id,
        "byte_length": len(prefix),
        "fill_byte": 0,
        "payload_start": None,
        "payload_start_evidence_ref": None,
        "concretization_limit": 1,
        "fields": [
            _field("rf2xx_status", "other", 0, prefix[0:1], protocol_ref),
            _field("rf2xx_phr", "len", 1, prefix[1:2], protocol_ref),
        ],
    }

    addressing = compiled["addressing"]
    payload = compiled["payload"]
    cursor = RF2XX_FRAME_HEADER_SIZE
    fields = [
        _field("rf2xx_status", "other", 0, body[0:1], protocol_ref),
        _field("rf2xx_phr", "len", 1, body[1:2], protocol_ref),
        _field("mac_fcf", "packet_type", cursor, compiled["fcf"], protocol_ref),
    ]
    cursor += 2
    fields.append(_field("mac_sequence", "header", cursor, body[cursor : cursor + 1], protocol_ref))
    cursor += 1
    if addressing:
        fields.append(
            _field("mac_addressing", "header", cursor, addressing, protocol_ref)
        )
        cursor += len(addressing)
    fields.append(_field("sixlowpan_payload", "payload", cursor, payload, payload_ref))
    cursor += len(payload)
    fields.append(_field("mac_fcs", "other", cursor, compiled["fcs"], protocol_ref))
    cursor += len(compiled["fcs"])
    fields.append(_field("rf2xx_lqi", "other", cursor, body[cursor : cursor + 1], protocol_ref))

    body_template = {
        "template_id": body_id,
        "byte_length": len(body),
        "fill_byte": 0,
        "payload_start": cursor - len(payload) - len(compiled["fcs"]),
        "payload_start_evidence_ref": payload_ref,
        "concretization_limit": 1,
        "fields": fields,
    }
    return prefix_template, body_template


def _control_requirements(irq_trigger: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate bounded, evidence-backed peripheral control requirements."""
    rows: list[dict[str, Any]] = []
    for index, requirement in enumerate(
        irq_trigger.get("control_requirements", []) or []
    ):
        kind = str(requirement.get("kind", ""))
        if kind != "SPI_REGISTER_RESPONSE":
            raise ValueError(f"unsupported IRQ control requirement: {kind!r}")
        evidence_ref = str(requirement.get("evidence_ref", ""))
        if not evidence_ref:
            raise ValueError("IRQ control requirement has no evidence_ref")
        rows.append(
            {
                "requirement_id": str(
                    requirement.get("requirement_id", f"control-{index:02d}")
                ),
                "kind": kind,
                "command_address": _bounded_int(
                    requirement["command_address"],
                    bits=32,
                    name="command_address",
                ),
                "command_value": _bounded_int(
                    requirement["command_value"],
                    bits=32,
                    name="command_value",
                ),
                "command_ordinal": _bounded_int(
                    requirement.get("command_ordinal", 0),
                    bits=16,
                    name="command_ordinal",
                ),
                "response_address": _bounded_int(
                    requirement["response_address"],
                    bits=32,
                    name="response_address",
                ),
                "response_ordinal": _bounded_int(
                    requirement.get("response_ordinal", 0),
                    bits=16,
                    name="response_ordinal",
                ),
                "required_value": _bounded_int(
                    requirement["required_value"],
                    bits=32,
                    name="required_value",
                ),
                "evidence_ref": evidence_ref,
            }
        )
    return rows


def enrich_plan(base_plan: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    frames = spec.get("frames", []) or []
    if not frames:
        raise ValueError("protocol plan has no frames")
    if len(frames) > 16:
        raise ValueError("protocol plan exceeds the bounded 16-frame limit")

    plan = copy.deepcopy(base_plan)
    templates: list[dict[str, Any]] = []
    events: list[dict[str, Any]] = []
    interrupt_schedule: list[dict[str, Any]] = []
    register_addresses = plan["source_binding"]["register_addresses"]
    if len(register_addresses) != 1:
        raise ValueError("RF2xx compiler requires one Source data register")
    register_address = register_addresses[0]

    order = 0
    for frame_index, frame in enumerate(frames):
        compiled = compile_frame(frame)
        prefix_template, body_template = _frame_templates(
            frame, compiled, frame_index
        )
        templates.extend([prefix_template, body_template])
        for call_index, template in enumerate((prefix_template, body_template)):
            events.append(
                {
                    "event_id": f"rf2xx-frame-{frame_index:02d}-call-{call_index}",
                    "kind": "SOURCE_PAYLOAD",
                    "order": order,
                    "template_id": template["template_id"],
                    "call_index": call_index,
                    "transaction_group": frame_index,
                    "register_address": register_address,
                    "irq": None,
                    "trigger_address": None,
                }
            )
            order += 1
        irq_trigger = frame.get("irq_trigger")
        if irq_trigger:
            function_symbol = str(irq_trigger.get("function_symbol", ""))
            if not function_symbol:
                raise ValueError("frame IRQ trigger has no function_symbol")
            schedule_row = {
                "event_id": f"rf2xx-frame-{frame_index:02d}-irq",
                "order": frame_index,
                "trigger_symbol": function_symbol,
                "trigger_offset": _bounded_int(
                    irq_trigger.get("function_offset", 0),
                    bits=32,
                    name="function_offset",
                ),
                "irq": _bounded_int(
                    irq_trigger["irq"], bits=16, name="irq"
                ),
                "evidence_ref": str(irq_trigger["evidence_ref"]),
            }
            control_requirements = _control_requirements(irq_trigger)
            if control_requirements:
                schedule_row["control_requirements"] = control_requirements
            interrupt_schedule.append(schedule_row)

    plan["input_templates"] = templates
    plan["events"] = events
    if interrupt_schedule:
        plan["interrupt_schedule"] = interrupt_schedule
        plan["interrupt_schedule_policy"] = {
            "replace_trigger_names": list(
                spec.get("replace_trigger_names", ["rf231_rx"])
            ),
            "program_counter_forcing": False,
            "branch_patching": False,
        }
    periodic_irq_overrides: list[dict[str, Any]] = []
    for row in spec.get("periodic_irq_overrides", []) or []:
        evidence_ref = str(row.get("evidence_ref", ""))
        if not evidence_ref:
            raise ValueError("periodic IRQ override has no evidence_ref")
        periodic_irq_overrides.append(
            {
                "trigger_name": str(row["trigger_name"]),
                "every_nth_tick": _bounded_int(
                    row["every_nth_tick"],
                    bits=32,
                    name="every_nth_tick",
                ),
                "irq": _bounded_int(row["irq"], bits=16, name="irq"),
                "evidence_ref": evidence_ref,
            }
        )
    if len(periodic_irq_overrides) > 8:
        raise ValueError("protocol plan exceeds 8 periodic IRQ overrides")
    if periodic_irq_overrides:
        plan["periodic_irq_overrides"] = periodic_irq_overrides
    plan["ordering_constraints"] = [
        "Each RF2xx frame uses call_index 0 for status/PHR and call_index 1 "
        "for the complete frame-buffer transaction.",
        "Frames are injected in ascending transaction_group order.",
    ]
    refs = list(plan.get("evidence_refs", []) or [])
    for frame in frames:
        refs.extend(
            [
                str(frame["protocol_evidence_ref"]),
                str(frame["payload_evidence_ref"]),
            ]
        )
        irq_trigger = frame.get("irq_trigger", {}) or {}
        refs.extend(
            str(requirement["evidence_ref"])
            for requirement in irq_trigger.get("control_requirements", []) or []
        )
    refs.extend(
        str(row["evidence_ref"])
        for row in spec.get("periodic_irq_overrides", []) or []
    )
    plan["evidence_refs"] = list(dict.fromkeys(refs))
    plan["unresolved_assumptions"] = list(
        dict.fromkeys(
            list(plan.get("unresolved_assumptions", []) or [])
            + list(spec.get("unresolved_assumptions", []) or [])
        )
    )
    return plan


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-plan", required=True, type=Path)
    parser.add_argument("--protocol-spec", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    plan = enrich_plan(load_json(args.base_plan), load_json(args.protocol_spec))
    write_json(args.out, plan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
