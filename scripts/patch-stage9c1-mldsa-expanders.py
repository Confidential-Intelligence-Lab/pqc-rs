#!/usr/bin/env python3
from pathlib import Path

root = Path.cwd()
lib = root / "crates/pqc-ml-dsa/src/lib.rs"
manifest = root / "crates/pqc-ml-dsa/Cargo.toml"

for path in (lib, manifest):
    if not path.exists():
        raise SystemExit(f"Missing {path}; run from the repository root")

lib_text = lib.read_text(encoding="utf-8")
if "pub mod xof;\n" not in lib_text:
    lib_text = lib_text.rstrip() + "\npub mod xof;\n"
lib.write_text(lib_text, encoding="utf-8")

manifest_text = manifest.read_text(encoding="utf-8")
if "sha3 = { workspace = true }" not in manifest_text:
    marker = "[dependencies]"
    start = manifest_text.find(marker)
    if start < 0:
        raise SystemExit("Missing [dependencies]")
    end = manifest_text.find("\n[", start + len(marker))
    if end < 0:
        end = len(manifest_text)
    manifest_text = (
        manifest_text[:end].rstrip()
        + "\nsha3 = { workspace = true }\n\n"
        + manifest_text[end:].lstrip("\n")
    )
manifest.write_text(manifest_text.rstrip() + "\n", encoding="utf-8")
print("Applied Stage 9C-1 ML-DSA XOF expanders.")
