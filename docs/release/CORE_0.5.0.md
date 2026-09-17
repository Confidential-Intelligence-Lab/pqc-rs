# pqc-rs-core 0.5.0 release candidate

`pqc-rs-core` `0.5.0` establishes the next pre-1.0 core API boundary for
PQC-rs.

## Compatibility boundary

The release changes the public `SignatureScheme` trait from associated
operations to instance-bound operations.

In `0.4.0`, implementations exposed:

- `SignatureScheme::keygen(...)`;
- `SignatureScheme::sign(...)`;
- `SignatureScheme::verify(...)`.

In `0.5.0`, these operations take `&self`. This allows a signature-scheme
object to carry algorithm or parameter-set selection and aligns the common
signature abstraction with crypto-agile implementations such as ML-DSA and
SLH-DSA.

Because existing trait implementations and callers may require source changes,
this is a new pre-1.0 minor-version boundary rather than a patch release.

## Shared error model

`PqcError` adds:

- `ParameterSetMismatch`;
- `InvalidInput`;
- `InternalError`.

These variants support consistent error mapping across parameter-bound and
crypto-agile signature implementations.

## Release dependency

`pqc-rs-slh-dsa` `0.5.0` requires the `0.5.0` core API and therefore must be
released only after `pqc-rs-core` `0.5.0` is available from the registry.

## Release provenance

This document describes the release candidate before registry publication.

Source commit, crate-specific tag, crates.io checksum, archive size,
publication date, and yank status must be recorded only after the final
candidate passes all release gates and registry publication is independently
verified.
