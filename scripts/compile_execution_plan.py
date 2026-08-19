#!/usr/bin/env python3
"""Compile a verified Execution Plan into a bounded semantic input set."""

from __future__ import annotations

import argparse
import hashlib
import itertools
from pathlib import Path
from typing import Any

from validation_common import load_json, write_json


MAX_CONCRETE_INPUTS = 8


def encode_candidate(field: dict[str, Any], candidate: Any) -> bytes:
    size = int(field["size"])
    encoding = str(field["encoding"])
    if encoding == "bytes_hex":
        value = bytes.fromhex(str(candidate))
    else:
        value = int(candidate).to_bytes(
            size,
            byteorder="little" if encoding == "uint_le" else "big",
            signed=False,
        )
    if len(value) != size:
        raise ValueError(f"candidate width mismatch for {field['name']}")
    return value


def concrete_template_values(
    template: dict[str, Any],
) -> list[tuple[bytes, dict[str, Any]]]:
    fields = template.get("fields", []) or []
    candidate_sets = [field["candidates"] for field in fields]
    combinations = itertools.product(*candidate_sets) if fields else [()]
    rows: list[tuple[bytes, dict[str, Any]]] = []
    for combination in combinations:
        payload = bytearray([int(template["fill_byte"])]) * int(template["byte_length"])
        assignments: list[dict[str, Any]] = []
        occupied: set[int] = set()
        for field, candidate in zip(fields, combination):
            offset = int(field["offset"])
            encoded = encode_candidate(field, candidate)
            field_range = set(range(offset, offset + len(encoded)))
            if occupied & field_range:
                raise ValueError(
                    f"overlapping fields in template {template['template_id']}"
                )
            occupied.update(field_range)
            payload[offset : offset + len(encoded)] = encoded
            assignments.append(
                {
                    "field": field["name"],
                    "role": field["role"],
                    "candidate": candidate,
                    "evidence_ref": field["evidence_ref"],
                }
            )
        rows.append((bytes(payload), {"assignments": assignments}))
        if len(rows) >= int(template["concretization_limit"]):
            break
    return rows


def compile_plan(plan: dict[str, Any]) -> list[dict[str, Any]]:
    templates = {
        str(row["template_id"]): concrete_template_values(row)
        for row in plan["input_templates"]
    }
    events = sorted(plan["events"], key=lambda row: int(row["order"]))
    source_events = [row for row in events if row["kind"] == "SOURCE_PAYLOAD"]
    choices = [templates[str(event["template_id"])] for event in source_events]
    variants: list[dict[str, Any]] = []
    for variant_index, selected in enumerate(itertools.product(*choices)):
        event_rows: list[dict[str, Any]] = []
        semantic_stream = bytearray()
        for event, (payload, metadata) in zip(source_events, selected):
            stream_offset = len(semantic_stream)
            semantic_stream.extend(payload)
            event_rows.append(
                {
                    "event_id": event["event_id"],
                    "order": event["order"],
                    "call_index": int(event.get("call_index", 0)),
                    "transaction_group": int(event.get("transaction_group", 0)),
                    "template_id": event["template_id"],
                    "register_address": event["register_address"],
                    "semantic_stream_offset": stream_offset,
                    "byte_length": len(payload),
                    "payload_hex": payload.hex(),
                    **metadata,
                }
            )
        variants.append(
            {
                "variant_id": f"input-{variant_index:03d}",
                "semantic_stream": bytes(semantic_stream),
                "events": event_rows,
            }
        )
        if len(variants) >= MAX_CONCRETE_INPUTS:
            break
    return variants


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    plan = load_json(args.plan)
    variants = compile_plan(plan)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    manifest_rows: list[dict[str, Any]] = []
    for variant in variants:
        variant_dir = args.out_dir / variant["variant_id"]
        variant_dir.mkdir(parents=True, exist_ok=True)
        stream = variant["semantic_stream"]
        (variant_dir / "semantic_stream.bin").write_bytes(stream)
        for event in variant["events"]:
            start = int(event["semantic_stream_offset"])
            end = start + int(event["byte_length"])
            (variant_dir / f"event-{int(event['order']):03d}.bin").write_bytes(
                stream[start:end]
            )
        manifest_rows.append(
            {
                "variant_id": variant["variant_id"],
                "semantic_stream_file": str(
                    (variant_dir / "semantic_stream.bin").relative_to(args.out_dir)
                ),
                "semantic_stream_sha256": hashlib.sha256(stream).hexdigest(),
                "semantic_stream_length": len(stream),
                "events": variant["events"],
            }
        )
    write_json(
        args.out_dir / "manifest.json",
        {
            "schema_version": "ct-mini-semantic-input-set-v1",
            "plan_id": plan["plan_id"],
            "alert_id": plan["alert_id"],
            "binary_sha256": plan["binary_sha256"],
            "variant_count": len(manifest_rows),
            "variants": manifest_rows,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
