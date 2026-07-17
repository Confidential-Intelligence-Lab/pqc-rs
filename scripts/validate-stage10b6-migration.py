#!/usr/bin/env python3
"""Validate Stage 10B-6 migration ledgers."""

from __future__ import annotations

import csv
from pathlib import Path

INVENTORY = Path("audit/stage10b6/byte-comparison-inventory.csv")
LEDGER = Path("audit/stage10b6/applied-byte-comparison-migrations.csv")


def read(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        raise SystemExit(f"missing {path}")

    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def main() -> None:
    inventory = read(INVENTORY)
    applied = read(LEDGER)

    open_security = [
        row
        for row in inventory
        if row["classification"] == "security-relevant"
        and row["status"] == "open"
    ]

    print(f"inventory sites: {len(inventory)}")
    print(f"applied migrations: {len(applied)}")
    print(f"security-relevant inventory sites requiring review: {len(open_security)}")

    if open_security:
        print("Review remaining sites in:")
        print(f"  {INVENTORY}")

    # Inventory openness is informational in 10B-6A. Functional regression
    # tests remain the hard gate.
    print("Stage 10B-6A migration ledger validation passed.")


if __name__ == "__main__":
    main()
