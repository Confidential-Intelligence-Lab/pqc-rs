#!/usr/bin/env python3
from pathlib import Path

root_manifest = Path("Cargo.toml")
hpke_manifest = Path("crates/pqc-hpke/Cargo.toml")
hpke_lib = Path("crates/pqc-hpke/src/lib.rs")

for path in [root_manifest, hpke_manifest, hpke_lib]:
    if not path.exists():
        raise SystemExit(f"{path} not found; run from repository root")

def ensure_dependency(text, section, key, line):
    marker = f"[{section}]"
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"Missing section [{section}]")

    next_section = text.find("\n[", start + len(marker))
    end = len(text) if next_section < 0 else next_section

    section_text = text[start:end]
    if any(
        candidate.split("=", 1)[0].strip() == key
        for candidate in section_text.splitlines()
        if "=" in candidate
    ):
        return text

    insertion = end
    prefix = text[:insertion].rstrip()
    suffix = text[insertion:].lstrip("\n")
    return prefix + "\n" + line + "\n\n" + suffix

text = root_manifest.read_text(encoding="utf-8")
text = ensure_dependency(
    text,
    "workspace.dependencies",
    "pqc-ml-kem",
    'pqc-ml-kem = { path = "crates/pqc-ml-kem", version = "0.4.0" }',
)
root_manifest.write_text(text, encoding="utf-8")
print(f"Updated {root_manifest}")

text = hpke_manifest.read_text(encoding="utf-8")
text = ensure_dependency(
    text,
    "dependencies",
    "pqc-ml-kem",
    "pqc-ml-kem = { workspace = true }",
)
text = ensure_dependency(
    text,
    "dependencies",
    "sha3",
    "sha3 = { workspace = true }",
)
text = ensure_dependency(
    text,
    "dependencies",
    "hex",
    "hex = { workspace = true }",
)
hpke_manifest.write_text(text, encoding="utf-8")
print(f"Updated {hpke_manifest}")

text = hpke_lib.read_text(encoding="utf-8")
declaration = "pub mod ml_kem;\n"
if declaration not in text:
    text = text.rstrip() + "\n" + declaration
    hpke_lib.write_text(text, encoding="utf-8")
    print(f"Updated {hpke_lib}")
else:
    print("ML-KEM HPKE adapter already declared.")
