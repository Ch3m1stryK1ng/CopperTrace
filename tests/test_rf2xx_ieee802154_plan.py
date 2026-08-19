import importlib.util
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
SPEC = importlib.util.spec_from_file_location(
    "compile_rf2xx_ieee802154_plan",
    ROOT / "scripts" / "compile_rf2xx_ieee802154_plan.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def frame(**overrides):
    row = {
        "frame_type": "DATA",
        "frame_version": "IEEE802154_2003",
        "dst_addr_mode": "SHORT",
        "src_addr_mode": "NONE",
        "dst_pan_id": 0xFFFF,
        "dst_short": 0xFFFF,
        "payload_hex": "c000",
        "protocol_evidence_ref": "code:ieee802154_validate_frame",
        "payload_evidence_ref": "code:ieee802154_reassemble",
    }
    row.update(overrides)
    return row


def base_plan():
    return {
        "source_binding": {
            "register_addresses": ["0x40008008"],
        },
        "input_templates": [],
        "events": [],
        "ordering_constraints": [],
        "evidence_refs": ["site:sink"],
        "unresolved_assumptions": [],
    }


def test_compiles_minimal_short_destination_data_frame():
    result = MODULE.compile_frame(frame())

    assert result["fcf"] == bytes.fromhex("0108")
    assert result["addressing"] == bytes.fromhex("ffffffff")
    assert result["phr"] == 11
    assert result["prefix"] == bytes.fromhex("000b")
    assert len(result["body"]) == 16
    assert result["body"][2:11] == bytes.fromhex("010800ffffffffc000")


def test_enriches_two_static_source_calls_per_dynamic_frame():
    plan = MODULE.enrich_plan(base_plan(), {"frames": [frame()]})

    assert [row["byte_length"] for row in plan["input_templates"]] == [2, 16]
    assert [
        (row["call_index"], row["transaction_group"]) for row in plan["events"]
    ] == [(0, 0), (1, 0)]
    assert plan["events"][1]["register_address"] == "0x40008008"


def test_repeated_frames_restart_static_call_indices():
    plan = MODULE.enrich_plan(
        base_plan(),
        {"frames": [frame(), frame(sequence=1, payload_hex="e000000000")]},
    )

    assert [
        (row["call_index"], row["transaction_group"]) for row in plan["events"]
    ] == [(0, 0), (1, 0), (0, 1), (1, 1)]


def test_rejects_security_without_auxiliary_header():
    try:
        MODULE.compile_frame(frame(security_enabled=True))
    except ValueError as exc:
        assert "auxiliary-header compiler" in str(exc)
    else:
        raise AssertionError("security-enabled frame was accepted")


def test_enriches_plan_with_symbol_relative_irq_schedule():
    candidate = frame(
        irq_trigger={
            "function_symbol": "net_if_up",
            "function_offset": "0x3c",
            "irq": 28,
            "evidence_ref": "code:net_if_up:after-up",
        }
    )
    plan = MODULE.enrich_plan(base_plan(), {"frames": [candidate]})

    assert plan["interrupt_schedule"] == [
        {
            "event_id": "rf2xx-frame-00-irq",
            "order": 0,
            "trigger_symbol": "net_if_up",
            "trigger_offset": 0x3C,
            "irq": 28,
            "evidence_ref": "code:net_if_up:after-up",
        }
    ]


def test_enriches_irq_schedule_with_evidence_backed_control_requirement():
    candidate = frame(
        irq_trigger={
            "function_symbol": "net_if_up",
            "function_offset": "0x3c",
            "irq": 28,
            "evidence_ref": "code:net_if_up:after-up",
            "control_requirements": [
                {
                    "requirement_id": "trx-end",
                    "kind": "SPI_REGISTER_RESPONSE",
                    "command_address": "0x4000800c",
                    "command_value": "0x8f",
                    "response_address": "0x40008008",
                    "response_ordinal": 1,
                    "required_value": 8,
                    "evidence_ref": "hardware:RF231:TRX_END",
                }
            ],
        }
    )

    plan = MODULE.enrich_plan(base_plan(), {"frames": [candidate]})
    requirement = plan["interrupt_schedule"][0]["control_requirements"][0]

    assert requirement == {
        "requirement_id": "trx-end",
        "kind": "SPI_REGISTER_RESPONSE",
        "command_address": 0x4000800C,
        "command_value": 0x8F,
        "command_ordinal": 0,
        "response_address": 0x40008008,
        "response_ordinal": 1,
        "required_value": 8,
        "evidence_ref": "hardware:RF231:TRX_END",
    }
    assert "hardware:RF231:TRX_END" in plan["evidence_refs"]
