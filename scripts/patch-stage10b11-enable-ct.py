#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-core/src/lib.rs")
if not path.exists():
    raise SystemExit("Run from the repository root")

text = path.read_text(encoding="utf-8")
if "pub mod ct;\n" not in text:
    text = text.rstrip() + "\n\n/// Constant-time utility primitives.\npub mod ct;\n"

path.write_text(text.rstrip() + "\n", encoding="utf-8")
print("Enabled pqc-core constant-time module.")
