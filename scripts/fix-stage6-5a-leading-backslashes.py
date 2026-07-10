#!/usr/bin/env python3
from pathlib import Path

FILES = [
    Path("crates/pqc-test-harness/src/acvp_encap_decap.rs"),
    Path("crates/pqc-test-harness/src/bin/ml-kem-acvp-encap-decap-inventory.rs"),
    Path("crates/pqc-test-harness/tests/acvp_encap_decap.rs"),
]

for path in FILES:
    if not path.exists():
        raise SystemExit(f"Missing expected file: {path}")

    text = path.read_text(encoding="utf-8")
    if text.startswith("\\
"):
        path.write_text(text[2:], encoding="utf-8")
        print(f"Removed leading backslash from {path}")
    elif text.startswith("\\"):
        path.write_text(text[1:], encoding="utf-8")
        print(f"Removed leading backslash from {path}")
    else:
        print(f"No leading backslash found in {path}")
