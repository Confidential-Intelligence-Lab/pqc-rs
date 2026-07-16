#!/usr/bin/env python3
from pathlib import Path
path = Path("crates/pqc-core/src/ct/mod.rs")
if not path.exists(): raise SystemExit("Run from repository root")
text = path.read_text(encoding="utf-8")
if "mod compare;\n" not in text:
    i = text.find("mod mask;")
    if i < 0: raise SystemExit("Could not locate ct module declarations")
    text = text[:i] + "mod compare;\n" + text[i:]
exports = "pub use compare::{\n    ct_eq_bytes, ct_eq_slices, ct_is_zero_bytes, ct_is_zero_slice,\n};\n"
if "pub use compare::{" not in text:
    i = text.find("pub use mask::{")
    if i < 0: raise SystemExit("Could not locate ct exports")
    text = text[:i] + exports + text[i:]
path.write_text(text, encoding="utf-8")
print("Enabled Stage 10B-2 comparison primitives.")
