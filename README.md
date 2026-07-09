# pqc-rfc9958-rs

Rust workspace for implementing and validating the post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

RFC 9958 is informational. This project treats it as a traceability and
engineering-guidance document, while normative algorithm behavior is drawn from
the underlying standards such as FIPS 203, FIPS 204, FIPS 205, and relevant
IETF protocol specifications.

## Stage 5B-2 status

Stage 5B-2 adds FIPS NTT schedule assets:

- compact zeta schedule module
- bit-reversal helper
- zeta canonicality tests
- generator/order tests
- zeta-indexed `basemul` helper

Important: this stage still keeps the FIPS NTT forward/inverse transforms as a
facade. Stage 5B-3 should replace the facade with the actual butterfly
implementation.

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
git commit -m "Stage 5B-2: Add FIPS NTT zeta schedule assets"
git push origin main
```
