#!/usr/bin/env python3
from pathlib import Path

lib_path = Path("crates/pqc-test-harness/src/lib.rs")
manifest_path = Path("crates/pqc-test-harness/Cargo.toml")

for path in [lib_path, manifest_path]:
    if not path.exists():
        raise SystemExit(f"{path} not found; run from repository root")

text = lib_path.read_text(encoding="utf-8")
declaration = "pub mod hpke_pq_vectors;\n"
if declaration not in text:
    text = text.rstrip() + "\n" + declaration
    lib_path.write_text(text, encoding="utf-8")
    print(f"Updated {lib_path}")

text = manifest_path.read_text(encoding="utf-8")
section = "[dependencies]"
start = text.find(section)
if start < 0:
    raise SystemExit("Missing [dependencies] in test-harness manifest")
next_section = text.find("\n[", start + len(section))
end = len(text) if next_section < 0 else next_section
dependency_section = text[start:end]

if "pqc-hpke" not in dependency_section:
    prefix = text[:end].rstrip()
    suffix = text[end:].lstrip("\n")
    text = (
        prefix
        + '\npqc-hpke = { path = "../pqc-hpke" }\n\n'
        + suffix
    )
    manifest_path.write_text(text, encoding="utf-8")
    print(f"Updated {manifest_path}")
