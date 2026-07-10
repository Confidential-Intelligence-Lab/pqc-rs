# pqc-rfc9958-rs

## Stage 6.3 status

Stage 6.3 adds opt-in ML-KEM KeyGen trace capture and a runner that emits the
first failing NIST ACVP case as JSON plus binary checkpoints.

Validate:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Generate the first failing trace:

```bash
cargo run -p pqc-test-harness \
  --bin ml-kem-acvp-keygen-trace \
  --release
```

The implementation remains pre-conformance.
