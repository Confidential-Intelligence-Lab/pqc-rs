#!/usr/bin/env python3
from pathlib import Path

manifest = Path("fuzz/Cargo.toml")
if not manifest.exists():
    raise SystemExit("Missing fuzz/Cargo.toml")

text = manifest.read_text(encoding="utf-8")

if "pqc-ml-dsa" not in text:
    marker = "[dependencies]"
    start = text.find(marker)
    if start < 0:
        raise SystemExit("Missing [dependencies]")
    end = text.find("\n[", start + len(marker))
    if end < 0:
        end = len(text)
    text = (
        text[:end].rstrip()
        + '\npqc-ml-dsa = { package = "pqc-rs-ml-dsa", path = "../crates/pqc-ml-dsa" }\n\n'
        + text[end:].lstrip("\n")
    )

if 'name = "mldsa_primitives"' not in text:
    text += '''

[[bin]]
name = "mldsa_primitives"
path = "fuzz_targets/mldsa_primitives.rs"
test = false
doc = false
bench = false
'''

manifest.write_text(text.rstrip() + "\n", encoding="utf-8")
print("Applied Stage 9C-6 ML-DSA fuzz target.")
