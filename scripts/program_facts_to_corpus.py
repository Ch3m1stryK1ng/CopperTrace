#!/usr/bin/env python3
"""Materialize a complete decompiled-C corpus from Ghidra program facts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--program-facts", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()

    facts = json.loads(args.program_facts.read_text(errors="replace"))
    functions = list(facts.get("functions", []) or [])
    materialized = [
        function
        for function in sorted(functions, key=lambda row: str(row.get("entry", "")))
        if str(function.get("decompiled_c", "")).strip()
    ]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    if args.out.suffix == ".jsonl":
        with args.out.open("w", encoding="utf-8") as handle:
            for function in materialized:
                handle.write(
                    json.dumps(
                        {
                            "function_id": function.get("function_id", ""),
                            "name": function.get("name", ""),
                            "addr": function.get("entry", ""),
                            "body": str(function.get("decompiled_c", "")).strip(),
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
    else:
        chunks = [
        "/* CopperTrace Mini full Ghidra decompile corpus. */\n",
        f"/* binary_sha256: {facts.get('binary_sha256', '')} */\n\n",
        ]
        for function in materialized:
            code = str(function.get("decompiled_c", "")).strip()
            chunks.append(
                f"/* CT-FUNCTION {function.get('function_id', '')} "
                f"entry={function.get('entry', '')} name={function.get('name', '')} */\n"
            )
            chunks.append(code + "\n\n")
        args.out.write_text("".join(chunks), encoding="utf-8")
    print(json.dumps({
        "functions_in_facts": len(functions),
        "functions_materialized": len(materialized),
        "format": "jsonl" if args.out.suffix == ".jsonl" else "c",
        "output": str(args.out),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
