# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-5 status

Stage 5B-5 adds K-PKE packing helpers for ML-KEM object components:

- public-key component packing
- secret-key component packing
- ciphertext component packing
- component splitting helpers
- shape tests for ML-KEM-512/768/1024
- rank and length rejection tests

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

After tests pass:

```bash
git add .
git commit -m "Stage 5B-5: Add ML-KEM K-PKE packing helpers"
git push origin main
```
