#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-ml-kem/src/lib.rs")
if not path.exists():
    raise SystemExit(f"{path} not found; run from repository root")

text = path.read_text(encoding="utf-8")
declaration = "pub mod ml_kem_encaps;\n"

if declaration not in text:
    marker = "pub mod ml_kem_keygen;\n"
    if marker not in text:
        raise SystemExit("Could not locate `pub mod ml_kem_keygen;`")
    text = text.replace(marker, marker + declaration, 1)
    path.write_text(text, encoding="utf-8")
    print(f"Updated {path}")
else:
    print("ML-KEM encapsulation module already declared.")
