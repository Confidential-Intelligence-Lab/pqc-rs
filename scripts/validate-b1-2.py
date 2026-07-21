#!/usr/bin/env python3
from pathlib import Path
import sys

root = Path(__file__).resolve().parents[1]
checks = {
    "suite registry": root / "crates/pqc-hpke/src/suite.rs",
    "matrix tests": root / "crates/pqc-hpke/tests/ciphersuite_matrix.rs",
}

missing = [name for name, path in checks.items() if not path.is_file()]
if missing:
    for name in missing:
        print(f"missing: {name}", file=sys.stderr)
    raise SystemExit(1)

suite = checks["suite registry"].read_text()
matrix = checks["matrix tests"].read_text()
lib = (root / "crates/pqc-hpke/src/lib.rs").read_text()
required = [
    ("suite module export", "pub mod suite;" in lib),
    ("typed suite", "pub struct HpkeSuite" in suite),
    ("three KDF registry", "pub const fn supported_kdfs() -> [KdfId; 3]" in suite),
    ("three AEAD registry", "pub const fn supported_aeads() -> [AeadId; 3]" in suite),
    ("base matrix", "assert_eq!(executed, 27);" in matrix),
    ("PSK matrix", matrix.count("assert_eq!(executed, 27);") == 2),
    ("unsupported KDF", "HpkeError::UnsupportedKdf" in matrix),
    ("unsupported AEAD", "HpkeError::UnsupportedAead" in matrix),
]

failed = [name for name, ok in required if not ok]
if failed:
    for name in failed:
        print(f"failed: {name}", file=sys.stderr)
    raise SystemExit(1)

print("B1.2 static validation: pass")
