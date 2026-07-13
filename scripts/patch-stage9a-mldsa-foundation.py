#!/usr/bin/env python3
from pathlib import Path

root = Path.cwd()
lib = root / "crates/pqc-ml-dsa/src/lib.rs"
manifest = root / "crates/pqc-ml-dsa/Cargo.toml"

for path in (lib, manifest):
    if not path.exists():
        raise SystemExit(f"Missing {path}; run from repository root")

lib_text = lib.read_text(encoding="utf-8")
declarations = [
    "pub mod api;\n",
    "pub mod error;\n",
    "pub mod params;\n",
    "pub use api::MlDsa;\n",
    "pub use error::MlDsaError;\n",
    "pub use params::{MlDsaParameterSet, MlDsaParameters};\n",
]

for declaration in declarations:
    if declaration not in lib_text:
        lib_text = lib_text.rstrip() + "\n" + declaration

lib.write_text(lib_text.rstrip() + "\n", encoding="utf-8")

manifest_text = manifest.read_text(encoding="utf-8")
if "description =" not in manifest_text:
    marker = "[package]"
    start = manifest_text.find(marker)
    if start < 0:
        raise SystemExit("Missing [package] in pqc-ml-dsa manifest")
    insertion = start + len(marker)
    manifest_text = (
        manifest_text[:insertion]
        + '\ndescription = "FIPS 204 ML-DSA implementation for PQC-rs"'
        + manifest_text[insertion:]
    )

manifest.write_text(manifest_text.rstrip() + "\n", encoding="utf-8")
print("Applied Stage 9A ML-DSA foundation.")
