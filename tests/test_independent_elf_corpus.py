from __future__ import annotations

import importlib.util
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_independent_elf_corpus",
    ROOT / "scripts/build_independent_elf_corpus.py",
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def write_arm_elf(path: Path, *, machine: int = 40, elf_type: int = 2) -> None:
    data = bytearray(84)
    data[:16] = b"\x7fELF\x01\x01\x01" + b"\x00" * 9
    struct.pack_into("<HHIIIIIHHHHHH", data, 16, elf_type, machine, 1, 0x8000001, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    struct.pack_into("<IIIIIIII", data, 52, 1, 0, 0x08000000, 0x08000000, 84, 84, 5, 4)
    path.write_bytes(data)


def test_parse_accepts_arm_exec_without_interpreter(tmp_path: Path) -> None:
    binary = tmp_path / "firmware.elf"
    write_arm_elf(binary)
    facts, reason = MODULE.parse_elf32_arm(binary)
    assert reason == "eligible"
    assert facts["machine"] == "ARM"
    assert facts["executable_load_segments"] == 1


def test_parse_rejects_relocatable_object(tmp_path: Path) -> None:
    binary = tmp_path / "object.o"
    write_arm_elf(binary, elf_type=1)
    facts, reason = MODULE.parse_elf32_arm(binary)
    assert facts is None
    assert reason == "not_et_exec:1"


def test_selection_prefers_unstripped_sibling_and_hash_order(tmp_path: Path) -> None:
    first = tmp_path / "a.elf"
    stripped = tmp_path / "a_stripped.elf"
    second = tmp_path / "b.elf"
    write_arm_elf(first)
    stripped.write_bytes(first.read_bytes() + b"stripped-variant")
    write_arm_elf(second)
    second.write_bytes(second.read_bytes() + b"second")

    rows = MODULE.discover([tmp_path], set())
    chosen = MODULE.select(rows, 2)
    paths = {Path(row["binary_path"]).name for row in chosen}
    assert paths == {"a.elf", "b.elf"}


def test_development_hash_is_excluded(tmp_path: Path) -> None:
    binary = tmp_path / "firmware.elf"
    write_arm_elf(binary)
    binary_hash = MODULE.sha256_path(binary)
    rows = MODULE.discover([tmp_path], {binary_hash})
    assert rows[0]["eligibility"] == "excluded_development_hash"
    assert MODULE.select(rows, 1) == []


def test_predeclared_path_policy_excludes_before_elf_selection(tmp_path: Path) -> None:
    excluded = tmp_path / "microbench" / "firmware.elf"
    excluded.parent.mkdir()
    write_arm_elf(excluded)
    rows = MODULE.discover([tmp_path], set(), [r"/microbench/"])
    assert rows[0]["eligibility"] == "excluded_path_policy"
    assert "binary_sha256" not in rows[0]
