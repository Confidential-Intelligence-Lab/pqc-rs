# Roadmap

This roadmap communicates direction rather than a binding delivery schedule.

## Milestone A — Production-ready RFC 9958 workspace

### A1. Standards and compliance

- live standards traceability engine;
- RFC 9958 informational mapping;
- FIPS 203, FIPS 204, and FIPS 205 normative matrices;
- RFC 9180 and applicable PQ-HPKE mappings;
- ACVP/CAVP workflow documentation;
- generated compliance and gap reports.

### A2. Interoperability

- cross-implementation key, ciphertext, signature, and shared-secret tests;
- documented wire formats and parameter identifiers;
- compatibility evidence for selected external implementations;
- negative and malformed-input interoperability testing.

### A3. Release engineering

- public API and feature-flag audit;
- semantic-versioning policy and API stability review;
- package metadata and `cargo publish --dry-run` gates;
- reproducible builds, SBOMs, checksums, and signed release artifacts;
- automated release notes and evidence bundles.

### A4. Documentation

- user and integration guides;
- architecture and developer documentation;
- threat model, security model, and known limitations;
- comprehensive API examples and rustdoc review.

### A5. Public project identity

- concise public README;
- contribution, security, governance, support, citation, and release policies;
- project roadmap and changelog;
- GitHub organization profile and public-launch material.

## Milestone B — Ecosystem foundation

- establish the `pqc-rs` organization and common project conventions;
- evaluate extraction of stable common abstractions into `pqc-core`;
- define cross-repository release, security, and contribution processes;
- publish shared benchmarking and standards tooling where appropriate.

## Milestone C — Global algorithm expansion

Candidate algorithm crates include:

- SMAUG-T;
- Classic McEliece;
- HAETAE;
- other internationally or regionally standardized PQC schemes.

An algorithm enters implementation only after confirming an authoritative specification, usable test vectors, intellectual-property and licensing conditions, maintenance ownership, and fit with the common API model.

## Milestone D — Unified research platform

- umbrella crate and common algorithm traits;
- cross-algorithm benchmarking and interoperability tools;
- hybrid, threshold, and experimental constructions behind unstable APIs;
- reproducible research artifacts and comparison datasets.

## Deferred but retained — High-performance engineering

Architecture-specific optimization remains part of the roadmap, including vectorized NTT and polynomial arithmetic, NEON, AVX2, AVX-512, SVE2, cache-aware implementations, performance-regression CI, and future hardware acceleration.

This work is intentionally deferred until API boundaries and the initial algorithm portfolio stabilize. Correctness, compliance, interoperability, and release maturity take priority.
