# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

RFC 9958 is informational. This project treats it as a traceability and
engineering-guidance document, while normative algorithm behavior is drawn from
the underlying standards such as FIPS 203, FIPS 204, FIPS 205, and relevant
IETF protocol specifications.

## Stage 5B-1 status

Stage 5B-1 begins the real FIPS 203 ML-KEM implementation path by adding
Montgomery-domain and Barrett-reduction arithmetic foundations.

Added:

- Montgomery constants for `q = 3329`
- Barrett reduction API
- Montgomery reduction API
- Montgomery conversion helpers
- Montgomery-domain multiplication helper
- tests for constants, round trips, and multiplication consistency

Important: this stage does not yet replace the Stage 5A FIPS NTT facade.
The next increment should implement the real FIPS 203 NTT schedule on top of
this arithmetic layer.

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
git commit -m "Stage 5B-1: Add Montgomery and Barrett arithmetic"
git push origin main
```
