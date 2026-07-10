\
#!/usr/bin/env python3
from pathlib import Path

path = Path("crates/pqc-test-harness/src/lib.rs")
if not path.exists():
    raise SystemExit(f"{path} not found; run from repository root")

text = path.read_text(encoding="utf-8")
declaration = "pub mod acvp_encap_decap;\n"

if declaration not in text:
    marker = "pub mod acvp;\n"
    if marker not in text:
        raise SystemExit("Could not locate `pub mod acvp;` in harness lib.rs")
    text = text.replace(marker, marker + declaration, 1)
    path.write_text(text, encoding="utf-8")
    print(f"Updated {path}")
else:
    print("Harness module declaration already present.")
