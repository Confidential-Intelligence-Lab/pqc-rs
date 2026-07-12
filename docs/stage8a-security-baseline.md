# Stage 8A: Security Hygiene Baseline

Stage 8A adds repeatable security gates without modifying the validated
cryptographic algorithms.

## Required checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo audit
cargo deny check
```

The convenience script is:

```bash
./scripts/run-security-baseline.sh
```

## Negative protocol tests

The HPKE tests require altered AAD, modified ciphertext, and mismatched `info`
to fail without advancing receiver state. Exporter contexts must also domain
separate exported values.

## Claim boundary

A clean Stage 8A result establishes a repeatable hygiene baseline. It is not a
formal constant-time proof, side-channel evaluation, certification, or security
audit.
