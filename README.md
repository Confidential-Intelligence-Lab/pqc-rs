# pqc-rfc9958-rs

Rust workspace for implementing and validating post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-15 status

Stage 5B-15 adds deterministic internal golden fixtures for:

- seed expansion
- matrix expansion
- secret/error sampling
- packed K-PKE public keys
- packed CPA secret-key components
- packed ciphertexts

These are internal regression fixtures, not official FIPS 203 KATs.

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

```bash
git add .
git commit -m "Stage 5B-15: Add intermediate-value golden fixtures"
git push origin main
```
