# SMAUG-T 1.1.1 — Experimental Rust KEM

[Back to the PQC-rs overview](../../README.md)

`pqc-rs-smaug-t` is a native Rust implementation of the SMAUG-T 1.1.1
key-encapsulation mechanism. It is part of the Cargo workspace but outside
the stable 1.0 compatibility boundary. Its manifest specifies version `0.0.1`
and `publish = false`.

**Experimental research software; not for production cryptographic use.**

## API and parameter sets

The [KEM implementation](src/kem.rs) provides `keypair`,
`encapsulate_deterministic`, and `decapsulate`. Deterministic inputs are for
reproducibility and testing; these interfaces must not be treated as an
audited, production-ready KEM API. Other modules implement arithmetic,
sampling, encoding, and IND-CPA operations.

The [parameter definitions](src/lib.rs) include `SMAUG_T128`, `SMAUG_T192`,
`SMAUG_T256`, and `TIMER` (a test configuration).

## Local and reference validation

Run focused library tests from the repository root:

```sh
cargo test -p pqc-rs-smaug-t --lib
```

Oracle-dependent integration tests require a compiled pinned C reference
and the corresponding environment. The
[dedicated workflow](../../.github/workflows/smaug-t-reference-assurance.yml)
retrieves the pinned upstream reference and invokes
[the reference-validation script](scripts/validate-reference.sh).

## Evidence and limitations

- [Assurance evidence ledger](docs/ASSURANCE_EVIDENCE.md)
- [Gaussian discrepancy](docs/GAUSSIAN_REFERENCE_DISCREPANCY.md)
- [Gaussian assurance](docs/GAUSSIAN_ASSURANCE.md)

A Gaussian reference discrepancy remains documented. Agreement with a
corrected C oracle is not proof of normative conformity. Independent normative
verification, compiled-code constant-time/side-channel assessment, and
production security review remain outstanding.
