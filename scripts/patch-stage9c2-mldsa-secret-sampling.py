#!/usr/bin/env python3
from pathlib import Path

root = Path.cwd()
lib = root / "crates/pqc-ml-dsa/src/lib.rs"

if not lib.exists():
    raise SystemExit("Run from the repository root after Stage 9C-1")

text = lib.read_text(encoding="utf-8")
declaration = "pub mod sample;\n"

if declaration not in text:
    text = text.rstrip() + "\n" + declaration

lib.write_text(text.rstrip() + "\n", encoding="utf-8")
print("Applied Stage 9C-2 ML-DSA bounded secret sampling.")
