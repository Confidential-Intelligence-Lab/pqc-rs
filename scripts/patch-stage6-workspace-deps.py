#!/usr/bin/env python3
from pathlib import Path
import sys

cargo_toml = Path("Cargo.toml")

if not cargo_toml.exists():
    raise SystemExit("Cargo.toml not found. Run this script from the repository root.")

text = cargo_toml.read_text(encoding="utf-8")

if "[workspace.dependencies]" not in text:
    raise SystemExit("Cargo.toml does not contain [workspace.dependencies].")

required = [
    'serde = { version = "1", features = ["derive"] }',
    'serde_json = "1"',
]

missing = [line for line in required if line not in text]
if not missing:
    print("Workspace serde dependencies are already present.")
    sys.exit(0)

lines = text.splitlines()
section_index = lines.index("[workspace.dependencies]")

insert_at = len(lines)
for index in range(section_index + 1, len(lines)):
    if lines[index].startswith("[") and lines[index].endswith("]"):
        insert_at = index
        break

for line in reversed(missing):
    lines.insert(insert_at, line)

cargo_toml.write_text("\n".join(lines) + "\n", encoding="utf-8")

print("Added workspace dependencies:")
for line in missing:
    print(f"  {line}")
