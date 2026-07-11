#!/usr/bin/env python3
from pathlib import Path

root_manifest = Path("Cargo.toml")
hpke_manifest = Path("crates/pqc-hpke/Cargo.toml")
hpke_lib = Path("crates/pqc-hpke/src/lib.rs")

for path in [root_manifest, hpke_manifest, hpke_lib]:
    if not path.exists():
        raise SystemExit(f"{path} not found; run from repository root")

def add_to_section(text, section, lines):
    marker = f"[{section}]"
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"Missing section [{section}]")

    insert_at = len(text)
    next_section = text.find("\n[", start + len(marker))
    if next_section >= 0:
        insert_at = next_section + 1

    additions = [
        line for line in lines
        if line.split("=", 1)[0].strip() not in {
            existing.split("=", 1)[0].strip()
            for existing in text[start:insert_at].splitlines()
            if "=" in existing
        }
    ]

    if not additions:
        return text

    prefix = text[:insert_at].rstrip()
    suffix = text[insert_at:].lstrip("\n")
    return prefix + "\n" + "\n".join(additions) + "\n\n" + suffix

text = root_manifest.read_text(encoding="utf-8")
text = add_to_section(
    text,
    "workspace.dependencies",
    [
        'hkdf = "0.12"',
        'sha2 = "0.10"',
    ],
)
root_manifest.write_text(text, encoding="utf-8")
print(f"Updated {root_manifest}")

text = hpke_manifest.read_text(encoding="utf-8")
text = add_to_section(
    text,
    "dependencies",
    [
        "hkdf = { workspace = true }",
        "sha2 = { workspace = true }",
        "hex = { workspace = true }",
    ],
)
hpke_manifest.write_text(text, encoding="utf-8")
print(f"Updated {hpke_manifest}")

text = hpke_lib.read_text(encoding="utf-8")
declarations = [
    "pub mod error;\n",
    "pub mod identifiers;\n",
    "pub mod kdf;\n",
    "pub mod key_schedule;\n",
]

for declaration in declarations:
    if declaration not in text:
        text = text.rstrip() + "\n" + declaration

if "pub use error::HpkeError;" not in text:
    text = text.rstrip() + "\n\npub use error::HpkeError;\n"

hpke_lib.write_text(text, encoding="utf-8")
print(f"Updated {hpke_lib}")
