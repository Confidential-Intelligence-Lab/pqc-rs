# Changelog

All notable user-visible changes will be documented here.

The project follows the principles of Keep a Changelog and intends to adopt Semantic Versioning before the first stable release.

## [Unreleased]

## [0.4.0] - 2026-07-22

### Changed

- promoted the three published `0.4.0-rc.1` packages to the
  non-prerelease `0.4.0` line without changing their cryptographic
  implementations;
- updated workspace dependency requirements, documentation, and release
  tooling for the stable promotion.

### Security

- retained the existing conservative security qualifications and kept
  ML-DSA, SLH-DSA, the experimental hybrid placeholder, and the test
  harness outside the public release boundary.

## [0.4.0-rc.1] - 2026-07-18

### Added

- first public release-candidate packages for `pqc-rs-core`, `pqc-rs-ml-kem`,
  and `pqc-rs-hpke`;
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key generation, encapsulation,
  decapsulation, key checks, and validation infrastructure;
- HPKE Base and PSK modes with pure post-quantum and revision-pinned hybrid
  profiles;
- standards traceability and compliance-reporting framework;
- layered side-channel and release-assurance infrastructure;
- public project identity, contribution, security, governance, support, roadmap, citation, and release documentation.

### Changed

- clarified that RFC 9958 is an informational engineering guide and that normative conformance is assessed against the applicable FIPS and RFC specifications.

### Security

- documented conservative security-claim and responsible-disclosure policies.
- kept ML-DSA, SLH-DSA, the experimental hybrid placeholder, and the test
  harness outside the public release boundary.

## B1.3.1 — Public API review

- Added preferred suite-first HPKE Base and PSK setup entry points.
- Preserved identifier-based setup APIs as compatibility wrappers.
- Added generated workspace API inventory and classification.
- Added `cargo xtask api-review [--check]`.

### B1.3.2 — Zeroization and secret-lifetime audit

- Added a machine-readable secret-type policy with explicit compatibility exceptions.
- Added generated secret inventory and zeroization audit documents.
- Added `cargo xtask zeroization-audit --check` and CI drift enforcement.

## B1.3.3 — Constant-time and secret-dependency audit

- Added a machine-readable constant-time policy covering eleven critical boundaries.
- Consolidated source, timing, rejection-loop, and generated-code evidence.
- Added generated constant-time and secret-dependency audit documents.
- Added `cargo xtask constant-time-audit --check` and CI drift enforcement.
- Explicitly classified ML-DSA signing and selected sampling routines as algorithmically variable-time rather than making an unsupported fixed-time claim.

## B1.3.5 — Performance baseline

- Added a machine-readable performance policy covering ten benchmark groups.
- Added ML-DSA key generation, signing, and verification Criterion benchmarks for all three parameter sets.
- Added generated performance-baseline and benchmark-register documents.
- Added environment and toolchain provenance capture for reproducible benchmark campaigns.
- Added `cargo xtask performance-audit --check` and benchmark smoke enforcement in CI.

[Unreleased]: https://github.oit.uci.edu/rcammaro/pqc-rfc9958-rs/compare/v0.4.0...HEAD
[0.4.0]: https://github.oit.uci.edu/rcammaro/pqc-rfc9958-rs/compare/v0.4.0-rc.1...v0.4.0
[0.4.0-rc.1]: https://github.oit.uci.edu/rcammaro/pqc-rfc9958-rs/releases/tag/v0.4.0-rc.1
