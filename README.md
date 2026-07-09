# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

RFC 9958 is informational. This project treats it as a traceability and
engineering-guidance document, while normative algorithm behavior is drawn from
the underlying standards such as FIPS 203, FIPS 204, FIPS 205, and relevant
IETF protocol specifications.

## Stage 5B-3 status

Stage 5B-3 upgrades the ML-KEM arithmetic layer with word-level Montgomery
reduction and centered reduction helpers.

Added:

- `reduce_centered`
- word-level `montgomery_reduce`
- negative-product Montgomery tests
- centered representative tests

This prepares the codebase for the real NTT butterfly implementation.

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
git commit -m "Stage 5B-3: Add word-level Montgomery reduction"
git push origin main
```
