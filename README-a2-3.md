# Milestone A2.3 — Rust ↔ liboqs cross-provider interoperability

A2.3 adds true bidirectional interoperability tests for ML-KEM-512/768/1024 and ML-DSA-44/65/87.

## Run

```bash
export OQS_LIBOQS_PATH=/opt/homebrew/lib/liboqs.dylib
cargo xtask interop-cross --strict
```

The expected result is 12 executed cases: six ML-KEM exchanges and six ML-DSA cross-verifications.

The Rust provider uses the repository's deterministic FIPS-oriented internal entry points, not the placeholder top-level ML-KEM/ML-DSA convenience APIs. The liboqs provider compiles a small bridge against the installed public liboqs headers and library, avoiding fragile assumptions about C structure layout in Python `ctypes`.

A passing report demonstrates byte-compatible artifact exchange only for the provider versions and parameter sets tested. It is not a NIST validation or certification claim.
