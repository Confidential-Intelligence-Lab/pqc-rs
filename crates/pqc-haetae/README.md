# HAETAE 1.2.0 — Experimental Rust signatures

[Back to the PQC-rs overview](../../README.md)

`pqc-rs-haetae` is a native Rust implementation of the HAETAE 1.2.0
post-quantum digital signature scheme. It is included in the Cargo workspace,
but is outside the PQC-rs stable 1.0 compatibility commitment.

**Experimental research software; not for production cryptographic use.**

## API and parameter sets

The [typed API](src/api.rs) exposes `Haetae`, `HaetaeKeyPair`,
`HaetaePublicKey`, `HaetaePrivateKey`, and `HaetaeSignature`. Its key operations
are `keygen`, `sign`, and `verify`, with a parameter-bound scheme and signing
context. Key generation and signing require caller-provided cryptographic
randomness.

The [parameter definitions](src/params.rs) cover `Haetae2`, `Haetae3`, and
`Haetae5` and define their signature and key sizes. The `internal-api` feature
exposes unstable engineering interfaces for reference testing and fuzzing;
these are not supported public compatibility interfaces.

## Local checks

From the repository root:

```sh
cargo fmt --all -- --check
cargo clippy -p pqc-rs-haetae --all-targets --all-features -- -D warnings
cargo test -p pqc-rs-haetae --lib
```

These are focused developer checks, not complete normative validation.

## Evidence and limitations

- [HAETAE assurance status](../../docs/security/HAETAE_ASSURANCE_STATUS.md)
- [Implementation entry point](src/lib.rs)
- [Typed API](src/api.rs)

The implementation has not undergone an independent production security audit.
Automated tests, reference comparisons, and memory-safety checks do not prove
complete normative conformity or resistance to side-channel attacks.
