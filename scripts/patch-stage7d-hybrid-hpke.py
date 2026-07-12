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
    for existing in section_text.splitlines():
        if "=" in existing and existing.split("=", 1)[0].strip() == key:
            return text
    return text[:end].rstrip() + "\n" + line + "\n\n" + text[end:].lstrip("\n")


text = root_manifest.read_text(encoding="utf-8")
for key, line in [
    (
        "x25519-dalek",
        'x25519-dalek = { version = "2", features = ["static_secrets"] }',
    ),
    ("p256", 'p256 = { version = "0.13", features = ["ecdh"] }'),
    ("p384", 'p384 = { version = "0.13", features = ["ecdh"] }'),
]:
    text = ensure_dependency(text, "workspace.dependencies", key, line)
root_manifest.write_text(text, encoding="utf-8")
print(f"Updated {root_manifest}")

text = hpke_manifest.read_text(encoding="utf-8")
for key in ["x25519-dalek", "p256", "p384"]:
    text = ensure_dependency(
        text,
        "dependencies",
        key,
        f"{key} = {{ workspace = true }}",
    )
hpke_manifest.write_text(text, encoding="utf-8")
print(f"Updated {hpke_manifest}")

text = hpke_lib.read_text(encoding="utf-8")
for declaration in ["pub mod hybrid_kem;\n", "pub mod hybrid_setup;\n"]:
    if declaration not in text:
        text = text.rstrip() + "\n" + declaration
hpke_lib.write_text(text, encoding="utf-8")
print(f"Updated {hpke_lib}")
