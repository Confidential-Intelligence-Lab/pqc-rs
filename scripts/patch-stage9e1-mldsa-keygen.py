#!/usr/bin/env python3
from pathlib import Path
manifest = Path("crates/pqc-test-harness/Cargo.toml")
if not manifest.exists(): raise SystemExit("Run from repository root")
text = manifest.read_text(encoding="utf-8")
marker = "[dependencies]"
start = text.find(marker)
if start < 0: raise SystemExit("Missing [dependencies]")
end = text.find("\n[", start + len(marker))
if end < 0: end = len(text)
section = text[start:end]
entries = []
if "pqc-ml-dsa" not in section: entries.append('pqc-ml-dsa = { package = "pqc-rs-ml-dsa", version = "0.4.0-rc.1", path = "../pqc-ml-dsa" }')
if "serde_json" not in section: entries.append('serde_json = { workspace = true }')
if entries: text = text[:end].rstrip() + "\n" + "\n".join(entries) + "\n\n" + text[end:].lstrip("\n")
manifest.write_text(text.rstrip()+"\n", encoding="utf-8")
print("Applied Stage 9E-1 dependencies.")
