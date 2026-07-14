#!/usr/bin/env python3
from pathlib import Path

manifest = Path("crates/pqc-test-harness/Cargo.toml")
if not manifest.exists():
    raise SystemExit("Run from the repository root")

text = manifest.read_text(encoding="utf-8")

if "pqc-ml-dsa" not in text:
    marker = "[dependencies]"
    start = text.find(marker)
    if start < 0:
        raise SystemExit("Missing [dependencies] in test-harness manifest")
    end = text.find("\n[", start + len(marker))
    if end < 0:
        end = len(text)
    text = (
        text[:end].rstrip()
        + '\npqc-ml-dsa = { package = "pqc-rs-ml-dsa", '
          'version = "0.4.0-rc.1", path = "../pqc-ml-dsa" }\n\n'
        + text[end:].lstrip("\n")
    )

manifest.write_text(text.rstrip() + "\n", encoding="utf-8")
print("Applied Stage 9D-6 validation harness dependency.")
