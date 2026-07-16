#!/usr/bin/env python3
from pathlib import Path

lib = Path("crates/pqc-ml-dsa/src/lib.rs")
if not lib.exists():
    raise SystemExit("Run from the repository root")

text = lib.read_text(encoding="utf-8")
if "pub mod audit;\n" not in text:
    text = text.rstrip() + "\npub mod audit;\n"

lib.write_text(text.rstrip() + "\n", encoding="utf-8")
print("Enabled Stage 9F-2B audit module.")
