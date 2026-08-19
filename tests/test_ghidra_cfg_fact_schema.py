from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "ghidra_export_source_facts.py"
SPEC = importlib.util.spec_from_file_location("ghidra_export_source_facts", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
exporter = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(exporter)


def test_schema_marks_cfg_capability_and_has_stable_fingerprint() -> None:
    first = exporter.schema_metadata()
    second = exporter.schema_metadata()

    assert first == second
    assert first["schema_version"] == "ct-mini-ghidra-high-pcode-v5-static-objects"
    assert first["schema_fingerprint"] == exporter.SCHEMA_FINGERPRINT
    assert len(first["schema_fingerprint"]) == 64
    assert first["capabilities"] == {
        "high_pcode": True,
        "ssa_def_use": True,
        "basic_blocks": True,
        "cfg_edges": True,
        "typed_branch_edges": True,
        "pcode_block_binding": True,
        "static_capacity_objects": True,
    }


def test_cfg_normalization_exports_blocks_and_typed_branch_edges() -> None:
    normalized = exporter.normalize_cfg_records(
        0x1000,
        [
            {
                "index": 2,
                "start": "0x1020",
                "stop": "0x1028",
                "predecessor_indices": [0],
                "successor_indices": [],
                "true_successor_index": -1,
                "false_successor_index": -1,
                "pcode_site_ids": ["site:00001000:00001020:0"],
            },
            {
                "index": 0,
                "start": "0x1000",
                "stop": "0x100c",
                "predecessor_indices": [],
                "successor_indices": [2, 1],
                "true_successor_index": 1,
                "false_successor_index": 2,
                "pcode_site_ids": [
                    "site:00001000:00001004:1",
                    "site:00001000:00001008:0",
                    "site:00001000:00001004:1",
                ],
            },
            {
                "index": 1,
                "start": "0x1010",
                "stop": "0x1018",
                "predecessor_indices": [0],
                "successor_indices": [],
                "true_successor_index": -1,
                "false_successor_index": -1,
                "pcode_site_ids": [],
            },
        ],
    )

    blocks = normalized["basic_blocks"]
    assert [row["block_id"] for row in blocks] == [
        "block:00001000:0",
        "block:00001000:1",
        "block:00001000:2",
    ]
    assert blocks[0]["successor_block_ids"] == [
        "block:00001000:1",
        "block:00001000:2",
    ]
    assert blocks[0]["true_successor_block_id"] == "block:00001000:1"
    assert blocks[0]["false_successor_block_id"] == "block:00001000:2"
    assert blocks[0]["pcode_site_ids"] == [
        "site:00001000:00001004:1",
        "site:00001000:00001008:0",
    ]
    assert normalized["cfg_edges"] == [
        {
            "source_block_id": "block:00001000:0",
            "target_block_id": "block:00001000:1",
            "kind": "true",
        },
        {
            "source_block_id": "block:00001000:0",
            "target_block_id": "block:00001000:2",
            "kind": "false",
        },
    ]
    assert normalized["unresolved_block_references"] == []


def test_cfg_normalization_does_not_infer_reciprocal_edges() -> None:
    normalized = exporter.normalize_cfg_records(
        0x2000,
        [
            {
                "index": 0,
                "successor_indices": [1],
                "predecessor_indices": [],
                "pcode_site_ids": [],
            },
            {
                "index": 1,
                "successor_indices": [],
                "predecessor_indices": [],
                "pcode_site_ids": [],
            },
        ],
    )

    assert normalized["basic_blocks"][1]["predecessor_block_ids"] == []
    assert normalized["cfg_edges"] == [
        {
            "source_block_id": "block:00002000:0",
            "target_block_id": "block:00002000:1",
            "kind": "flow",
        }
    ]


def test_cfg_normalization_preserves_real_unresolved_references() -> None:
    normalized = exporter.normalize_cfg_records(
        0x3000,
        [
            {
                "index": 4,
                "successor_indices": [9],
                "predecessor_indices": [2],
                "true_successor_index": -1,
                "false_successor_index": -1,
                "pcode_site_ids": [],
            }
        ],
    )

    assert normalized["basic_blocks"][0]["predecessor_block_ids"] == [
        "block:00003000:2"
    ]
    assert normalized["basic_blocks"][0]["successor_block_ids"] == [
        "block:00003000:9"
    ]
    assert normalized["unresolved_block_references"] == [
        "block:00003000:2",
        "block:00003000:9",
    ]


def test_static_object_normalization_preserves_conflicting_extents() -> None:
    rows = exporter.normalize_static_objects(
        [
            {
                "object_id": "global:20000000:32",
                "storage_space": "ram",
                "function_id": "",
                "base_offset": 0x20000000,
                "extent": 32,
                "writable": True,
                "extent_evidence": "elf_symbol_st_size_and_writable_memory_block",
            },
            {
                "object_id": "global:20000000:32",
                "storage_space": "ram",
                "function_id": "",
                "base_offset": 0x20000000,
                "extent": 32,
                "writable": True,
                "extent_evidence": "elf_symbol_st_size_and_writable_memory_block",
            },
            {
                "object_id": "global:20000000:16",
                "storage_space": "ram",
                "function_id": "",
                "base_offset": 0x20000000,
                "extent": 16,
                "writable": True,
                "extent_evidence": "ghidra_defined_array_datatype",
            },
        ]
    )

    assert len(rows) == 2
    assert {row["extent"] for row in rows} == {16, 32}
