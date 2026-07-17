# Standards Traceability

This directory explains how `pqc-rfc9958-rs` maps standards and engineering guidance to source code, tests, and assurance evidence.

The canonical machine-readable source is [`compliance/matrix.toml`](../../compliance/matrix.toml). Generate reports with:

```bash
cargo xtask compliance
```

Use strict mode in CI:

```bash
cargo xtask compliance --strict
```

## Important scope distinction

RFC 9958, *Post-Quantum Cryptography for Engineers*, is an **Informational RFC**. It provides engineering context, algorithm summaries, protocol considerations, and recommendations. It is not the normative algorithm definition for ML-KEM, ML-DSA, SLH-DSA, or HPKE.

Normative conformance matrices will be maintained separately for FIPS 203, FIPS 204, FIPS 205, RFC 9180, and the applicable post-quantum HPKE specifications. The initial RFC 9958 matrix therefore uses conservative `mapped` statuses and does not claim algorithm conformance merely because a corresponding crate exists.
