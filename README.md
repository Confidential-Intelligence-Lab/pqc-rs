# pqc-rfc9958-rs

Rust workspace for implementing and validating post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-13 status

Stage 5B-13 introduces explicit K-PKE NTT-domain intermediates:

- NTT polynomial vectors
- NTT polynomial matrices
- vector and matrix transforms
- NTT-domain inner products
- NTT-domain matrix-vector multiplication
- equivalence tests against coefficient-domain arithmetic

Existing K-PKE APIs remain unchanged and the project remains pre-KAT.

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

```bash
git add .
git commit -m "Stage 5B-13: Add NTT-domain K-PKE intermediates"
git push origin main
```
