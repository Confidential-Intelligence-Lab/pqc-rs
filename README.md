# pqc-rfc9958-rs

Rust workspace for implementing and validating post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-11 status

Stage 5B-11 adds reference-compatible ML-KEM NTT arithmetic:

- centered zeta schedule
- forward NTT
- `invntt_tomont`
- ordinary inverse convenience wrapper
- complete NTT-domain base multiplication
- sparse and dense equivalence tests against schoolbook multiplication

Official FIPS 203 KAT validation remains pending.

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

```bash
git add .
git commit -m "Stage 5B-11: Add reference-compatible ML-KEM NTT"
git push origin main
```
