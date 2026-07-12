# PQC-rs

**Production-quality post-quantum cryptography in Rust**

PQC-rs is a standards-focused Rust workspace for post-quantum cryptography and post-quantum key establishment. The current release candidate concentrates on ML-KEM and HPKE, including pure post-quantum and PQ/traditional hybrid Base-mode key establishment.

> **Security status:** experimental, pre-audit software. Do not use this release to protect production secrets without an independent security review and an application-specific risk assessment.

## Implemented scope

| Component | Status |
|---|---|
| ML-KEM-512/768/1024 | Implemented and ACVP-vector tested |
| RFC 9180 HPKE foundation | Implemented |
| Pure ML-KEM HPKE Base mode | Pinned vector suite passing |
| PQ/traditional hybrid HPKE Base mode | Pinned vector suite passing |
| ML-DSA / SLH-DSA | Planned |
| HPKE PSK/Auth/AuthPSK modes | Planned |
| JOSE/COSE, TLS, X.509, PKCS/CMS | Planned |

## Validation status

The workspace includes ACVP and HPKE vector harnesses, negative tests, dependency auditing, fuzzing, Miri, sanitizers, secret-lifetime review, and reproducible performance baselines. This is test-vector evidence, not certification or independent audit.

## Release scope

Release-candidate crates: `pqc-core`, `pqc-ml-kem`, and `pqc-hpke`. Experimental or incomplete crates remain unpublished.

## Build

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Conformance harnesses

```bash
cargo run -p pqc-test-harness --bin ml-kem-acvp-keygen --release
cargo run -p pqc-test-harness --bin ml-kem-acvp-encapsulation --release
cargo run -p pqc-test-harness --bin ml-kem-acvp-decapsulation --release
cargo run -p pqc-test-harness --bin ml-kem-acvp-key-check --release
cargo run -p pqc-test-harness --bin hpke-pq-base-vectors --release
cargo run -p pqc-test-harness --bin hpke-pq-hybrid-vectors --release
```

Expected release-gate results: KeyGen 75/75, Encaps 75/75, Decaps 30/30, key checks 60/60, pure-PQ HPKE 105/105, hybrid HPKE 102/102.

## License

Apache-2.0 OR MIT.
