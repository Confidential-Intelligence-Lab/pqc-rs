# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-6 status

Stage 5B-6 adds deterministic K-PKE key-generation structure:

- seed expansion into `rho` and `sigma`
- noise polynomial sampling
- noise vector sampling
- public vector computation
- public/secret component packing
- deterministic shape tests for ML-KEM-512/768/1024

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
git commit -m "Stage 5B-6: Add deterministic K-PKE keygen structure"
git push origin main
```
