#!/usr/bin/env python3
"""Produce a reviewer-facing report of open 10B-6B sites."""

from __future__ import annotations

import csv
from pathlib import Path

source = Path(
    "audit/stage10b6/conditional-assignment-inventory.csv"
)
output = Path(
    "target/stage10b6/conditional-assignment-review.md"
)
output.parent.mkdir(parents=True, exist_ok=True)

with source.open(newline="", encoding="utf-8") as stream:
    rows = [
        row
        for row in csv.DictReader(stream)
        if row["status"] == "open"
    ]

with output.open("w", encoding="utf-8") as stream:
    print("# Stage 10B-6B Conditional Assignment Review", file=stream)
    print(file=stream)
    print(f"Open sites: {len(rows)}", file=stream)
    print(file=stream)

    for row in rows:
        print(
            f"## {row['site_id']} — `{row['file']}:{row['line']}`",
            file=stream,
        )
        print(file=stream)
        print(f"- Kind: `{row['kind']}`", file=stream)
        print(f"- Classification: `{row['classification']}`", file=stream)
        print(
            f"- Recommended primitive: "
            f"`{row['recommended_primitive']}`",
            file=stream,
        )
        if row["condition"]:
            print(f"- Condition: `{row['condition']}`", file=stream)
        print(file=stream)
        print("```rust", file=stream)
        print(row["source"], file=stream)
        print("```", file=stream)
        print(file=stream)
        print(row["rationale"], file=stream)
        print(file=stream)

print(f"Wrote {output}")
