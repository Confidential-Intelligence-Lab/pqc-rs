# Standards Traceability

PQC-rs maps standards and engineering guidance to implementation paths, tests,
interoperability evidence, and assurance artifacts.

The canonical machine-readable source is
[`compliance/matrix.toml`](../../compliance/matrix.toml). Generate the
traceability reports with:

```bash
cargo xtask compliance
```

Use strict mode for the CI gate:

```bash
cargo xtask compliance --strict
```

## Scope

Normative conformance and informational guidance are tracked separately.

- **FIPS 203** defines ML-KEM.
- **FIPS 204** defines ML-DSA.
- **FIPS 205** defines SLH-DSA.
- **RFC 9180** defines HPKE.
- Applicable post-quantum and hybrid HPKE work is tracked against its explicitly
  pinned specification revision until the relevant specification is final.
- **RFC 9958**, *Post-Quantum Cryptography for Engineers*, is an Informational
  RFC. It provides engineering guidance and does not define ML-KEM, ML-DSA,
  SLH-DSA, or HPKE.

Repository traceability and validation evidence do not constitute NIST
validation, certification, formal verification, or an independent security
audit.

## Detailed mappings

The standards directory contains human-readable traceability documentation and
generated reports. Machine-readable requirements and evidence references live
under `compliance/standards/`.
