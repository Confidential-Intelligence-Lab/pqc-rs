#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-core/src/ct/mod.rs")
if not path.exists():
    raise SystemExit("Run from the repository root")

text = path.read_text(encoding="utf-8")

for module in ("container", "typed"):
    declaration = f"mod {module};\n"
    if declaration not in text:
        insertion = text.find("mod mask;")
        if insertion < 0:
            raise SystemExit("Could not locate module declarations")
        text = text[:insertion] + declaration + text[insertion:]

container_export = "pub use container::SecretBytes;\n"
if container_export not in text:
    first_export = text.find("pub use compare::{")
    if first_export < 0:
        first_export = text.find("pub use mask::{")
    if first_export < 0:
        raise SystemExit("Could not locate exports")
    text = text[:first_export] + container_export + text[first_export:]

typed_export = """pub use typed::{
    ct_assign_u16_array, ct_assign_u32_array, ct_assign_u64_array,
};
"""
if "pub use typed::{" not in text:
    first_export = text.find("pub use compare::{")
    if first_export < 0:
        first_export = text.find("pub use mask::{")
    if first_export < 0:
        raise SystemExit("Could not locate exports")
    text = text[:first_export] + typed_export + text[first_export:]

path.write_text(text, encoding="utf-8")
print("Enabled Stage 10B-3 secret containers and typed assignment.")
