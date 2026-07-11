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

<!-- STANDARDS-STATUS:BEGIN -->
## Standards status

- **FIPS 203 ML-KEM:** validated against the imported NIST ACVP corpus.
- **RFC 9958:** engineering guidance traced; it is not treated as an
  executable protocol or conformance specification.
- **RFC 9180 HPKE:** implementation and vector validation pending.
- **draft-ietf-hpke-pq-05:** pinned experimental integration target;
  Internet-Draft status is preserved explicitly.

Passing ACVP vectors is not a claim of CMVP module validation.
<!-- STANDARDS-STATUS:END -->
