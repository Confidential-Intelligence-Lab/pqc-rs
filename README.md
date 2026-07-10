# pqc-rfc9958-rs

Rust workspace for implementing and validating post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-12 status

Stage 5B-12 routes K-PKE polynomial arithmetic through the verified ML-KEM
NTT path while preserving the existing structural APIs and encodings.

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

```bash
git add .
git commit -m "Stage 5B-12: Route K-PKE arithmetic through NTT"
git push origin main
```
