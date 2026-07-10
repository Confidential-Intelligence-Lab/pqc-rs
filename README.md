# pqc-rfc9958-rs

Rust workspace for implementing and validating post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-14 status

Stage 5B-14 adopts explicit NTT-domain intermediates in structural K-PKE key
generation and encryption while preserving existing encodings.

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

```bash
git add .
git commit -m "Stage 5B-14: Adopt NTT-domain K-PKE intermediates"
git push origin main
```
