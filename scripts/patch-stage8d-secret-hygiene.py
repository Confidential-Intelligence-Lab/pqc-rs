#!/usr/bin/env python3
from pathlib import Path

root_manifest = Path("Cargo.toml")
core_manifest = Path("crates/pqc-core/Cargo.toml")
core_lib = Path("crates/pqc-core/src/lib.rs")

for path in (root_manifest, core_manifest, core_lib):
    if not path.exists():
        raise SystemExit(f"{path} not found; run from the repository root")

def add_dependency(text: str, section: str, key: str, line: str) -> str:
    marker = f"[{section}]"
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"Missing [{section}] in manifest")
    end = text.find("\n[", start + len(marker))
    if end < 0:
        end = len(text)
    section_text = text[start:end]
    for existing in section_text.splitlines():
        if "=" in existing and existing.split("=", 1)[0].strip() == key:
            return text
    return text[:end].rstrip() + "\n" + line + "\n\n" + text[end:].lstrip("\n")

text = root_manifest.read_text(encoding="utf-8")
text = add_dependency(
    text,
    "workspace.dependencies",
    "zeroize",
    'zeroize = { version = "1.8", features = ["zeroize_derive"] }',
)
root_manifest.write_text(text, encoding="utf-8")

text = core_manifest.read_text(encoding="utf-8")
text = add_dependency(
    text,
    "dependencies",
    "zeroize",
    "zeroize = { workspace = true }",
)
core_manifest.write_text(text, encoding="utf-8")

text = core_lib.read_text(encoding="utf-8")
declaration = "pub mod secret;\n"
if declaration not in text:
    text = text.rstrip() + "\n" + declaration
core_lib.write_text(text, encoding="utf-8")

print("Applied Stage 8D secret wrapper support.")
