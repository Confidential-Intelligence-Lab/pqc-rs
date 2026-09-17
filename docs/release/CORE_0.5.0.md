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

- source revision: `c446714f9ae5a9210b1fb7959d8e640c03a15d39`;
- crate-specific tag: `pqc-rs-core-v0.5.0`;
- crates.io version: `pqc-rs-core 0.5.0`;
- registry archive SHA-256:
  `5cced2eb2acf74e1daa6172b17e184da391fe5e209dbada279a9e2188ebdbfc8`;
- local and registry crate archives: byte-for-byte identical by SHA-256;
- Rust MSRV: `1.80`.
