import importlib.util
import sys
from pathlib import Path


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from fuzzware_trace import MMIOEvent  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "run_fuzzware_validation", SCRIPTS / "run_fuzzware_validation.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_append_replay_tail_repeats_existing_control_plane_suffix(tmp_path):
    path = tmp_path / "input.bin"
    path.write_bytes(bytes([1, 2, 3, 4]))
    MODULE.append_replay_tail(path, 6, repeat_bytes=2)
    assert path.read_bytes() == bytes([1, 2, 3, 4, 3, 4, 3, 4, 3, 4])


def test_append_replay_tail_zero_is_noop(tmp_path):
    path = tmp_path / "input.bin"
    path.write_bytes(b"abc")
    MODULE.append_replay_tail(path, 0)
    assert path.read_bytes() == b"abc"


def mmio(event_id, mode, address, value, fuzz_index=0, consumed_bytes=0):
    return MMIOEvent(
        event_id=event_id,
        pc=0x1000 + event_id,
        lr=0,
        mode=mode,
        access_size=4,
        fuzz_index=fuzz_index,
        consumed_bytes=consumed_bytes,
        address=address,
        value=value,
    )


def test_matches_nth_spi_data_response_after_command_in_irq_window():
    events = [
        mmio(11, "w", 0x4000800C, 0x8F),
        mmio(12, "r", 0x40008008, 0x25, 20, 1),
        mmio(13, "w", 0x4000800C, 0),
        mmio(14, "r", 0x40008008, 0, 21, 1),
        mmio(31, "r", 0x40008008, 8, 22, 1),
    ]
    requirement = {
        "command_address": 0x4000800C,
        "command_value": 0x8F,
        "response_address": 0x40008008,
        "response_ordinal": 1,
    }

    response = MODULE.match_control_response(
        mmio_events=events,
        requirement=requirement,
        after_event_id=10,
        before_event_id=30,
    )

    assert response is not None
    assert response.event_id == 14
    assert response.fuzz_index == 21
