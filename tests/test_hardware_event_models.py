import json
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from prepare_fuzzware_config import (  # noqa: E402
    apply_hardware_event_models,
    materialize_hardware_event_models,
)


ELF = (
    ROOT
    / "artifacts/development_expansion_baseline_20260722/rehosting"
    / "development_zephyr_01/firmware.elf"
)
PROFILE = (
    ROOT
    / "registries/hardware_events/zephyr_sam4s_rf2xx.v1.json"
)


@pytest.mark.skipif(not ELF.exists(), reason="RF231 regression ELF is unavailable")
def test_materializes_rf2xx_gpio_pin_from_elf_config_object():
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    rows = materialize_hardware_event_models(ELF, profile)
    assert len(rows) == 3
    assert rows[0]["model"] == {
        "pc": 0x40F8A0,
        "addr": 0x400E104C,
        "access_size": 4,
        "val": 4,
    }
    assert rows[0]["derivation"]["pin"] == 2
    assert rows[1]["model"] == {
        "pc": 0x40FA68,
        "addr": 0x40008008,
        "access_size": 4,
        "val": 0,
    }
    assert rows[1]["derivation"]["encoding"] == "constant_for_discarded_read"
    assert rows[2]["kind"] == "interrupt_trigger"
    assert rows[2]["trigger_name"] == "rf231_rx"
    assert rows[2]["model"] == {"addr": 0x4056D8, "irq": 28}


def test_event_model_replaces_unmodeled_same_context():
    config = {
        "mmio_models": {
            "unmodeled": {
                "old": {"pc": 0x1000, "addr": 0x40000000, "access_size": 4}
            }
        }
    }
    changes = apply_hardware_event_models(
        config,
        [
            {
                "name": "event",
                "kind": "constant",
                "model": {
                    "pc": 0x1000,
                    "addr": 0x40000000,
                    "access_size": 4,
                    "val": 8,
                },
                "derivation": {"pin": 3},
            }
        ],
    )
    assert not config["mmio_models"]["unmodeled"]
    assert config["mmio_models"]["constant"]["event"]["val"] == 8
    assert changes[0]["removed_models"][0]["name"] == "old"


def test_interrupt_event_replaces_only_named_trigger():
    config = {
        "interrupt_triggers": {
            "system_tick": {"every_nth_tick": 1000, "irq": 20},
            "rf231_rx": {"addr": 0x1000, "irq": 28},
        }
    }
    changes = apply_hardware_event_models(
        config,
        [
            {
                "name": "rf231_rx_after_interface_up",
                "kind": "interrupt_trigger",
                "trigger_name": "rf231_rx",
                "model": {"addr": 0x2000, "irq": 28},
                "derivation": {"encoding": "ELF_symbol_plus_offset"},
            }
        ],
    )
    assert config["interrupt_triggers"]["system_tick"]["irq"] == 20
    assert config["interrupt_triggers"]["rf231_rx"] == {
        "addr": 0x2000,
        "irq": 28,
    }
    assert changes[0]["replaced_trigger"]["addr"] == 0x1000


@pytest.mark.skipif(not ELF.exists(), reason="RF231 regression ELF is unavailable")
def test_interrupt_trigger_relocates_for_second_zephyr_elf():
    second_elf = ELF.parent.parent / "development_zephyr_02" / "firmware.elf"
    if not second_elf.exists():
        pytest.skip("second RF231 regression ELF is unavailable")
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    rows = materialize_hardware_event_models(second_elf, profile)
    interrupt = next(row for row in rows if row["kind"] == "interrupt_trigger")
    assert interrupt["model"] == {"addr": 0x4056EC, "irq": 28}
