import importlib.util
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "summarize_ablation_v1.py"
SPEC = importlib.util.spec_from_file_location("summarize_ablation_v1", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_parse_elapsed_seconds_ignores_time_format_label():
    text = "\tElapsed (wall clock) time (h:mm:ss or m:ss): 1:02:03\n"

    assert MODULE.parse_elapsed_seconds(text) == 3723.0


def test_parse_elapsed_seconds_accepts_minute_format():
    text = "\tElapsed (wall clock) time (h:mm:ss or m:ss): 7:08.25\n"

    assert MODULE.parse_elapsed_seconds(text) == 428.25
