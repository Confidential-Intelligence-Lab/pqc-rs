# PQC-rs 1.0 SemVer contract

This document defines the compatibility boundary intended for the PQC-rs 1.x
cryptographic release line.

The 1.0 cryptographic boundary consists of:

- `pqc-rs-core`;
- `pqc-rs-ml-kem`;
- `pqc-rs-ml-dsa`;
- `pqc-rs-slh-dsa`; and
- `pqc-rs-hpke`.

These crates may have independent implementation histories and pre-1.0 version
numbers. Promotion to the 1.0 release line establishes the supported
compatibility contract described here.

## Supported compatibility boundary

For ordinary downstream builds, the supported 1.x compatibility boundary
includes:

- documented public modules, types, traits, constants, and functions;
- documented crate-root re-exports;
- documented constructors and operations;
- documented serialization, encoding, and wire-format behavior where those
  representations form part of the public protocol contract;
- documented error and failure semantics;
- documented ownership and secret-handling behavior that is observable through
  the public API; and
- documented supported Cargo feature behavior.

Removal or incompatible modification of a supported public item or documented
behavior requires explicit SemVer review.

The generated workspace API inventory is supporting evidence for this boundary.
It does not by itself define compatibility: the supported contract is the
combination of the documented public API, crate documentation, feature
contracts, protocol/encoding commitments, and this policy.

## Internal and assurance surfaces

The non-default `internal-api` feature is an unstable engineering and assurance
surface. Interfaces reachable only through `internal-api` are excluded from the
PQC-rs 1.x SemVer compatibility commitment.

They exist so repository validation, ACVP, interoperability, fuzzing, timing,
generated-code analysis, and other assurance tooling can exercise low-level
implementation behavior without making those interfaces application-facing
contracts.

Applications must not depend on `internal-api`.

The following are also outside the 1.x application compatibility boundary:

- `pqc-rs-test-harness`;
- benchmarks and profiling infrastructure;
- repository assurance and certification tooling;
- generated compliance and audit machinery;
- private implementation modules; and
- test-only interfaces.

## Deferred and application-layer crates

The standalone `pqc-rs-hybrid` crate is not part of the 1.0 compatibility
boundary. Its retained placeholder implementation is excluded until a future
release defines supported functionality.

PQC-Forge/application-layer crates, including protocol, secure-channel, and
authentication integration crates, are versioned and reviewed separately from
the PQC-rs 1.0 cryptographic boundary.

Their presence in the workspace does not extend the compatibility commitment
defined by this document.

## Feature compatibility

Default application-facing feature combinations documented as supported are
part of the compatibility contract.

Features explicitly documented as internal, assurance-only, experimental, or
unsupported are not stability commitments merely because Cargo exposes their
names.

Changes that remove a supported feature, materially alter its documented
meaning, or change whether a supported public API is reachable require explicit
SemVer review.

## Security and standards behavior

Semantic-version compatibility does not mean that an implementation defect,
security weakness, or standards-conformance defect must be preserved.

A corrective release may change internal implementation behavior, reject input
that was previously accepted incorrectly, or correct output that violated the
documented normative contract.

Such changes must be documented and reviewed for downstream impact. A security
or standards correction must not silently broaden the project's claims.

No SemVer statement in this document constitutes certification, formal
verification, universal constant-time behavior, or external validation.

## MSRV

The workspace `rust-version` defines the minimum supported Rust version for the
release line unless a crate documents a stricter requirement.

Raising the MSRV within the 1.x line requires an explicit release-policy and
compatibility review and must be called out in release notes.

## Change control

Before a 1.x release, changes to the cryptographic compatibility boundary must
be reviewed against:

1. `cargo xtask api-review --check`;
2. crate rustdoc and public documentation;
3. applicable feature and failure contracts;
4. downstream/package reconstruction checks;
5. protocol and serialization compatibility where applicable; and
6. the release audit.

Adding public API is permitted under SemVer but still requires intentional API
review so that accidental implementation exposure does not become permanent
compatibility debt.

Breaking changes to the supported boundary require a new major release unless
the change is a documented security or standards correction whose treatment has
been explicitly reviewed and recorded.
