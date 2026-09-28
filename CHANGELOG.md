# Changelog

All notable user-visible changes will be documented here.

The project follows the principles of Keep a Changelog and intends to adopt Semantic Versioning before the first stable release.

## [Unreleased]

## [1.0.0] - 2026-09-28

### Stable release

- promoted the five coordinated PQC-rs cryptographic-foundation crates to
  stable `1.0.0`;
- froze the documented 1.x public compatibility boundary;
- retained feature-gated engineering and assurance surfaces outside the stable
  SemVer contract;
- preserved the cryptographic implementation validated by `1.0.0-rc.1`
  without cryptographic source changes;
- completed release, fuzz-consumer, and warning-hygiene integration required
  for the stable release line.

## [1.0.0-rc.1] - 2026-09-27

### Added

- established the first coordinated 1.0 release-candidate line for
  `pqc-rs-core`, `pqc-rs-ml-kem`, `pqc-rs-ml-dsa`, `pqc-rs-slh-dsa`, and
  `pqc-rs-hpke`;
- added the repository-wide PQC-rs 1.0 SemVer compatibility contract;
- consolidated the hardened FIPS 203, FIPS 204, FIPS 205, and RFC 9180
  cryptographic foundation under one release boundary.

### Changed

- moved the five cryptographic-foundation crates to `1.0.0-rc.1` while keeping
  PQC-Forge/application and assurance crates separately versioned;
- excluded feature-gated `internal-api` interfaces from the supported 1.x
  compatibility commitment;
- deferred the standalone hybrid placeholder beyond the 1.0 compatibility
  boundary;
- updated release tooling for the five-crate dependency-ordered publication
  sequence.

### Security

- retained conservative security qualifications: repository validation,
  interoperability, fuzzing, timing, and assurance evidence do not constitute
  an independent security audit, formal verification, certification, or FIPS
  module validation.


### Added

- prepared `pqc-rs-slh-dsa` `0.5.0` as the hardened FIPS 205 release line,
  covering all twelve standardized parameter sets, Pure SLH-DSA and
  HashSLH-DSA, deterministic and hedged signing, validation, interoperability,
  assurance, and reproducible performance evidence;
- added release-candidate documentation for the `pqc-rs-slh-dsa` `0.5.0`
  publication path.

### Changed

- established `pqc-rs-slh-dsa` `0.5.0` as a new pre-1.0 API boundary after
  removing the public `SlhDsaError::NotImplemented` variant and completing the
  hardened public interface;
- updated release policy and workspace dependency metadata for the SLH-DSA
  `0.5.0` candidate.

### Added

- published `pqc-rs-ml-dsa` `0.4.0` independently from the original workspace
  promotion, covering FIPS 204 ML-DSA-44, ML-DSA-65, and ML-DSA-87;
- recorded the immutable publication provenance at source commit
  `98140a3422fbc212bd43d96992028d29c548714d`, crate tag
  `pqc-rs-ml-dsa-v0.4.0`, and verified crates.io archive checksum
  `d7e2b207710f11adf90a4e4a5046e1c6f20ef0996463f034007d7e890ba752d3`.

### Changed

- corrected active documentation and release-policy tooling to recognize
  ML-DSA as a published public crate while preserving the original `v0.4.0`
  workspace-release history.

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

[Unreleased]: https://github.com/Confidential-Intelligence-Lab/pqc-rs/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Confidential-Intelligence-Lab/pqc-rs/compare/v1.0.0-rc.1...v1.0.0
[1.0.0-rc.1]: https://github.com/Confidential-Intelligence-Lab/pqc-rs/releases/tag/v1.0.0-rc.1
[0.4.0]: https://github.com/Confidential-Intelligence-Lab/pqc-rs/compare/v0.4.0-rc.1...v0.4.0
[0.4.0-rc.1]: https://github.com/Confidential-Intelligence-Lab/pqc-rs/releases/tag/v0.4.0-rc.1
