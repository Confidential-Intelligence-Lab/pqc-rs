#!/usr/bin/env python3
from pathlib import Path

lib = Path("crates/pqc-ml-dsa/src/lib.rs")
manifest = Path("crates/pqc-ml-dsa/Cargo.toml")

if not lib.exists() or not manifest.exists():
    raise SystemExit("Run from the repository root after Stage 9E-4")

text = lib.read_text(encoding="utf-8")
if "pub mod hash_mldsa;\n" not in text:
    text = text.rstrip() + "\npub mod hash_mldsa;\n"
lib.write_text(text, encoding="utf-8")

text = manifest.read_text(encoding="utf-8")
if not any(
    line.strip().startswith("sha2 ")
    or line.strip().startswith("sha2=")
    for line in text.splitlines()
):
    marker = "[dependencies]"
    start = text.find(marker)
    if start < 0:
        raise SystemExit("Missing [dependencies]")
    end = text.find("\n[", start + len(marker))
    if end < 0:
        end = len(text)
    text = (
        text[:end].rstrip()
        + "\nsha2 = { workspace = true }\n\n"
        + text[end:].lstrip("\n")
    )

manifest.write_text(text.rstrip() + "\n", encoding="utf-8")
print("Applied Stage 9E-5 HashML-DSA module.")
