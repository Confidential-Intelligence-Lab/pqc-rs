#!/usr/bin/env python3
"""Apply narrowly safe scalar conditional-assignment migrations."""

from __future__ import annotations

import csv
import re
from pathlib import Path

ROOTS = (
    Path("crates/pqc-ml-kem/src"),
    Path("crates/pqc-ml-dsa/src"),
)

# Only transform a one-line integer assignment guarded by an existing CtMask.
BLOCK_RE = re.compile(
    r"(?P<indent>^[ \t]*)if\s+(?P<mask>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"==\s*CtMask(?P<bits>8|16|32|64)::TRUE\s*\{\s*\n"
    r"(?P<body_indent>[ \t]+)(?P<destination>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"=\s*(?P<source>[A-Za-z_][A-Za-z0-9_]*);\s*\n"
    r"(?P=indent)\}",
    re.MULTILINE,
)

FIELDS = ("file", "line", "before", "after", "status")


def migrate(path: Path) -> list[dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    rows: list[dict[str, str]] = []

    def replacement(match: re.Match[str]) -> str:
        bits = match.group("bits")
        function = f"ct_select_u{bits}"
        destination = match.group("destination")
        source = match.group("source")
        mask = match.group("mask")
        line = text.count("\n", 0, match.start()) + 1
        before = match.group(0)
        after = (
            f"{match.group('indent')}{destination} = {function}("
            f"{mask}, {source}, {destination});"
        )
        rows.append(
            {
                "file": str(path),
                "line": str(line),
                "before": before.replace("\n", "\\n"),
                "after": after,
                "status": "applied",
            }
        )
        return after

    migrated = BLOCK_RE.sub(replacement, text)

    if migrated != text:
        path.write_text(migrated, encoding="utf-8")

    return rows


def main() -> None:
    rows: list[dict[str, str]] = []

    for root in ROOTS:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.rs")):
            rows.extend(migrate(path))

    ledger = Path(
        "audit/stage10b6/applied-conditional-assignment-migrations.csv"
    )
    ledger.parent.mkdir(parents=True, exist_ok=True)

    with ledger.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"conditional migrations applied: {len(rows)}")
    print(f"ledger: {ledger}")


if __name__ == "__main__":
    main()
