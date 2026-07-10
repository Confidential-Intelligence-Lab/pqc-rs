# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-9 status

Stage 5B-9 integrates structural K-PKE behind the public `Kpke` trait for
ML-KEM-512, ML-KEM-768, and ML-KEM-1024.

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

```bash
git add .
git commit -m "Stage 5B-9: Integrate structural K-PKE trait"
git push origin main
```
