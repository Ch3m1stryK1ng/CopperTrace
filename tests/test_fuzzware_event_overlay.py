from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from compile_fuzzware_event_overlay import compile_event_overlay  # noqa: E402


def test_compiles_symbol_relative_two_frame_irq_schedule():
    base = {
        "interrupt_triggers": {
            "system_tick": {"every_nth_tick": 1000, "irq": 20},
            "rf231_rx": {"addr": 0x1110, "irq": 28},
        }
    }
    plan = {
        "interrupt_schedule_policy": {
            "replace_trigger_names": ["rf231_rx"],
        },
        "interrupt_schedule": [
            {
                "event_id": "frame-0",
                "order": 0,
                "trigger_symbol": "net_if_up",
                "trigger_offset": 0x3C,
                "irq": 28,
                "evidence_ref": "code:net_if_up:after-up",
            },
            {
                "event_id": "frame-1",
                "order": 1,
                "trigger_symbol": "net_if_up",
                "trigger_offset": 0x40,
                "irq": 28,
                "evidence_ref": "code:net_if_up:next-block",
            },
        ],
        "periodic_irq_overrides": [
            {
                "trigger_name": "system_tick",
                "every_nth_tick": 10000,
                "irq": 20,
                "evidence_ref": "code:cache-timeout:bounded-arrival",
            }
        ],
    }
    config, changes = compile_event_overlay(
        base, plan, {"net_if_up": 0x40569C}
    )
    assert config["interrupt_triggers"]["system_tick"]["irq"] == 20
    assert (
        config["interrupt_triggers"]["system_tick"]["every_nth_tick"] == 10000
    )
    assert "rf231_rx" not in config["interrupt_triggers"]
    assert config["interrupt_triggers"]["ct_plan_irq_00"] == {
        "addr": 0x4056D8,
        "irq": 28,
    }
    assert config["interrupt_triggers"]["ct_plan_irq_01"] == {
        "addr": 0x4056DC,
        "irq": 28,
    }
    assert changes[0]["removed_triggers"][0]["name"] == "rf231_rx"
    assert changes[0]["periodic_trigger_changes"][0]["name"] == "system_tick"
