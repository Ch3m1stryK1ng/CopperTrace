import importlib.util
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "rebase_fuzzware_target", SCRIPTS / "rebase_fuzzware_target.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_rebases_address_by_shared_function_relative_offset():
    source = [(0x1000, 0x1100, "worker")]
    target = {"worker": (0x2000, 0x2100)}
    assert MODULE.rebase_address(0x1034, source, target) == 0x2034


def test_rebases_site_id_function_and_instruction():
    source = [(0x1000, 0x1100, "worker")]
    target = {"worker": (0x2000, 0x2100)}
    assert (
        MODULE.rebase_site_id("site:00001000:00001034:tag", source, target)
        == "site:00002000:00002034:tag"
    )


def test_rebases_only_executable_config_fields():
    source = [(0x1000, 0x1100, "worker")]
    target = {"worker": (0x2000, 0x2100)}
    source_config = {
        "interrupt_triggers": {"rx": {"addr": 0x1034, "irq": 28}},
        "mmio_models": {
            "unmodeled": {
                "ct_source_pc_00001020_mmio": {
                    "pc": 0x1020,
                    "addr": 0x40008008,
                }
            }
        },
    }
    target_base = {
        "memory_map": {"text": {"file": "old.bin", "size": 0x1234}},
        "symbols": {0x2000: "worker"},
    }
    result = MODULE.rebase_config(
        source_config=source_config,
        target_base_config=target_base,
        target_firmware_path="/target/firmware.bin",
        source_intervals=source,
        target_by_name=target,
    )
    assert result["interrupt_triggers"]["rx"]["addr"] == 0x2034
    model = next(iter(result["mmio_models"]["unmodeled"].values()))
    assert model == {"pc": 0x2020, "addr": 0x40008008}
    assert result["memory_map"]["text"]["file"] == "/target/firmware.bin"
