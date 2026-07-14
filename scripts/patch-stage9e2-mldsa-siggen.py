#!/usr/bin/env python3
from pathlib import Path

manifest = Path("crates/pqc-test-harness/Cargo.toml")
if not manifest.exists():
    raise SystemExit("Run from the repository root")

text = manifest.read_text(encoding="utf-8")
marker = "[dependencies]"
start = text.find(marker)
if start < 0:
    raise SystemExit("Missing [dependencies]")
end = text.find("\n[", start + len(marker))
if end < 0:
    end = len(text)

section = text[start:end]
required = [
    (
        "pqc-ml-dsa",
        'pqc-ml-dsa = { package = "pqc-rs-ml-dsa", version = "0.4.0-rc.1", path = "../pqc-ml-dsa" }',
    ),
    ("serde_json", "serde_json = { workspace = true }"),
]
additions = []

for key, entry in required:
    if not any(
        line.strip().startswith(f"{key} ")
        or line.strip().startswith(f"{key}=")
        for line in section.splitlines()
    ):
        additions.append(entry)

if additions:
    text = (
        text[:end].rstrip()
        + "\n"
        + "\n".join(additions)
        + "\n\n"
        + text[end:].lstrip("\n")
    )

manifest.write_text(text.rstrip() + "\n", encoding="utf-8")
print("Applied Stage 9E-2A sigGen harness dependencies.")
