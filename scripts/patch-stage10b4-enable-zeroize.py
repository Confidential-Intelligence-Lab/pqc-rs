#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-core/src/ct/mod.rs")
text = path.read_text(encoding="utf-8")

if "mod zeroize;\n" not in text:
    insertion = text.find("mod typed;")
    if insertion < 0:
        insertion = text.find("mod select;")
    if insertion < 0:
        raise SystemExit("Could not locate module declarations")
    line_end = text.find("\n", insertion)
    text = text[:line_end + 1] + "mod zeroize;\n" + text[line_end + 1:]

exports = """pub use zeroize::{
    zeroize_bytes, zeroize_u16, zeroize_u32, zeroize_u64,
};
"""

if "pub use zeroize::{" not in text:
    text = text.rstrip() + "\n" + exports

path.write_text(text.rstrip() + "\n", encoding="utf-8")
print("Enabled Stage 10B-4 zeroization module.")
