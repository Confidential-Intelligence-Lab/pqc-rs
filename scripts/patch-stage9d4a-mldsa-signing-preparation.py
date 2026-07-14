#!/usr/bin/env python3
from pathlib import Path

lib = Path("crates/pqc-ml-dsa/src/lib.rs")
if not lib.exists():
    raise SystemExit("Run from the repository root after Stage 9D-3")

text = lib.read_text(encoding="utf-8")
if "pub mod signing;\n" not in text:
    text = text.rstrip() + "\npub mod signing;\n"

lib.write_text(text.rstrip() + "\n", encoding="utf-8")
print("Applied Stage 9D-4A signing preparation.")
