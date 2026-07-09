# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

RFC 9958 is informational. This project treats it as a traceability and
engineering-guidance document, while normative algorithm behavior is drawn from
the underlying standards such as FIPS 203, FIPS 204, FIPS 205, and relevant
IETF protocol specifications.

## Stage 5A status

Stage 5A adds the FIPS 203 ML-KEM implementation structure:

- parameter-set algorithm constants
- FIPS NTT facade module
- matrix expansion from `rho`
- rejection-sampling helper
- message-to-polynomial and polynomial-to-message helpers
- tests for deterministic expansion and encoding behavior

Important: Stage 5A is still **not production ML-KEM**. It prepares the module
layout and deterministic implementation structure for Stage 5B, where the exact
FIPS 203 NTT, K-PKE keygen/encrypt/decrypt, and official KAT validation should
be introduced.

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
git commit -m "Stage 5A: FIPS 203 ML-KEM implementation structure"
git push origin main
```
