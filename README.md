# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-4 status

Stage 5B-4 now keeps the public FIPS NTT boundary correctness-preserving and
retains the first butterfly implementation as experimental helpers.

Added:

- `experimental_forward_ntt`
- `experimental_inverse_ntt`
- canonical-output tests for the experimental forward path
- public boundary round-trip tests

The exact FIPS 203 inverse/scaling convention and full NTT-domain multiplication
remain Stage 5B-5 work.

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
git commit -m "Stage 5B-4: Add experimental ML-KEM NTT path"
git push origin main
```
