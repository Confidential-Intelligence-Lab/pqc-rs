# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-7 status

Stage 5B-7 adds deterministic K-PKE encryption structure:

- public-key component decoding
- eta2 encryption-noise sampling
- structural `u = A^T r + e1`
- structural `v = t^T r + e2 + m`
- ciphertext component packing
- deterministic encryption tests for ML-KEM-512/768/1024

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
git commit -m "Stage 5B-7: Add deterministic K-PKE encryption structure"
git push origin main
```
