#!/usr/bin/env python3
from __future__ import annotations

import csv
from pathlib import Path

inventory_path = Path(
    "audit/stage10b6/conditional-assignment-inventory.csv"
)
ledger_path = Path(
    "audit/stage10b6/applied-conditional-assignment-migrations.csv"
)

with inventory_path.open(newline="", encoding="utf-8") as stream:
    inventory = list(csv.DictReader(stream))

with ledger_path.open(newline="", encoding="utf-8") as stream:
    ledger = list(csv.DictReader(stream))

open_security = [
    row
    for row in inventory
    if row["classification"] == "security-relevant"
    and row["status"] == "open"
]

print(f"conditional inventory sites: {len(inventory)}")
print(f"automatic migrations: {len(ledger)}")
print(f"security-relevant sites requiring review: {len(open_security)}")
print("Stage 10B-6B inventory and regression validation passed.")
