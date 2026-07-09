# pqc-rfc9958-rs

`pqc-rfc9958-rs` is a research-grade Rust library implementing the post-quantum cryptographic algorithms and protocol building blocks discussed in IETF RFC 9958.

Unlike a production-oriented cryptographic library focused solely on deployment, this project emphasizes:

- standards traceability
- correctness and reproducibility
- comprehensive validation
- constant-time software engineering
- interoperability testing
- benchmarking and optimization
- protocol-level reference implementations

The repository follows a staged development process in which each component is introduced together with documentation, validation harnesses, and performance evaluation before optimization.

## Initial scope

- ML-KEM (FIPS 203)
- ML-DSA (FIPS 204)
- SLH-DSA (FIPS 205)
- Hybrid classical/PQ key establishment
- HPKE integration
- Test harnesses
- KAT validation
- Fuzzing
- Benchmarking
- Protocol interoperability

## Project goals

- Standards-compliant implementations
- Safe Rust (`#![forbid(unsafe_code)]` by default)
- `no_std` support
- Constant-time software engineering
- Extensive automated testing
- Clear architecture suitable for research and education
- Portable baseline implementations followed by optimized SIMD backends

This project is intended as both a reusable software library and a reference implementation supporting research, education, experimentation, and future protocol development.
