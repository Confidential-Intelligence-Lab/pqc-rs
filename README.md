# pqc-rfc9958-rs

Rust workspace for implementing and validating post-quantum cryptographic
algorithms and protocol engineering patterns discussed by RFC 9958.

## Stage 5B-16 status

Stage 5B-16 adds an authoritative NIST ACVP import path:

- pinned ACVP-Server release
- reproducible fetch script
- provenance and checksum files
- typed ML-KEM keyGen JSON parser
- prompt/expected joining
- strict metadata and case matching

No official vector is marked as passed yet.

## Fetch vectors

```bash
./scripts/fetch-nist-acvp-ml-kem.sh
```

## Validate

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## GitHub stage workflow

```bash
git add .
git commit -m "Stage 5B-16: Add NIST ACVP vector import"
git push origin main
```
