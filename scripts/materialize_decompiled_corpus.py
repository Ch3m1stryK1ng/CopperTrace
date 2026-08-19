#!/usr/bin/env python3
"""Materialize the existing Mini decompiled-C input from Ghidra ProgramFacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def function_rows(program_facts: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        row
        for row in program_facts.get("functions", [])
        if str(row.get("name", "")).strip()
        and str(row.get("decompiled_c", "")).strip()
    ]
    return sorted(
        rows,
        key=lambda row: (
            int(str(row.get("entry", "0")), 16),
            str(row.get("name", "")),
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("program_facts", type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--regime", choices=("unstripped", "stripped"), default="unstripped")
    args = parser.parse_args()

    facts = json.loads(args.program_facts.read_text(errors="replace"))
    rows = function_rows(facts)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    decomp_dir = args.out_dir / "decomp" / args.regime
    decomp_dir.mkdir(parents=True, exist_ok=True)

    plain_path = args.out_dir / f"plain_decompiled.{args.regime}.c"
    with plain_path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(str(row["decompiled_c"]).rstrip())
            stream.write("\n\n")

    with (decomp_dir / "functions.full.jsonl").open("w", encoding="utf-8") as stream:
        for row in rows:
            body = str(row["decompiled_c"])
            stream.write(
                json.dumps(
                    {
                        "function_id": row.get("function_id", ""),
                        "name": row["name"],
                        "regime": args.regime,
                        "addr": row.get("entry", ""),
                        "end": row.get("end", ""),
                        "signature": row.get("signature", ""),
                        "body": body,
                        "body_hash": hashlib.sha256(body.encode()).hexdigest(),
                    },
                    sort_keys=True,
                )
                + "\n"
            )

    summary = {
        "schema_version": "ct-mini-decompiled-corpus-v1",
        "program_facts": str(args.program_facts.resolve()),
        "program_facts_sha256": hashlib.sha256(args.program_facts.read_bytes()).hexdigest(),
        "regime": args.regime,
        "function_count": len(rows),
        "plain_decompiled_c": str(plain_path.resolve()),
    }
    (args.out_dir / "decompiled_corpus_summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
