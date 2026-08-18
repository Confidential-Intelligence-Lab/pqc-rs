# pqc-rs-test-harness

`pqc-rs-test-harness` is the shared **validation and assurance** layer for
PQC-rs and PQC-Forge.

It provides infrastructure for conformance testing, interoperability testing,
vector processing, and assurance workflows.

This crate is published so downstream implementers and researchers can reuse
the same support infrastructure used by PQC-rs.

It is not an application-facing cryptographic API and should not be treated as
a substitute for the public ML-KEM, ML-DSA, SLH-DSA, HPKE, protocol, or
secure-channel APIs.

## Internal validation support

Some harness functionality enables implementation-facing features such as the
pqc-rs-ml-dsa internal-api feature in order to test internal algorithmic stages
and invariants. Those interfaces are intended for validation and research
tooling rather than ordinary application use.

## Typical uses

The harness supports repository workflows involving:

- known-answer and vector validation;
- ACVP-oriented tooling;
- interoperability checks;
- implementation-level regression tests;
- assurance and reproducibility infrastructure.

## License

MIT
