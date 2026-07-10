# pqc-rfc9958-rs

Rust workspace for implementing and validating post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-10 status

Stage 5B-10 adds a FIPS 203 conformance gate:

- conformance maturity levels
- component status manifest
- parameter-set conformance status
- KAT and intermediate-value record types
- deterministic validation results
- negative parameter-set mismatch tests
- FIPS 203 traceability documentation

The repository explicitly does **not** claim FIPS 203 conformance or official
KAT validation at this stage.

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

```bash
git add .
git commit -m "Stage 5B-10: Add FIPS 203 conformance gate"
git push origin main
```
