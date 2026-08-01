# pqc-rs-ml-dsa v0.4.0 Release Audit

- **Crate:** `pqc-rs-ml-dsa`
- **Version:** `0.4.0`
- **Audit date:** 2026-07-30
- **Audited repository commit:** `b832d3dd80703ada47affc25ea2e01ff1c78037d`
- **Audit branch:** `release/ml-dsa-v0.4.0-audit`
- **Result:** **Passed**
- **Corrective release required:** **No**

## Scope

This audit evaluates the published `pqc-rs-ml-dsa 0.4.0` crate and the
corresponding source in the PQC-rs repository. It covers the publication-facing
API, build and test gates, package construction, crates.io publication
metadata, and source equivalence between the published artifact and the
repository implementation.

The crate implements FIPS 204 ML-DSA-44, ML-DSA-65, and ML-DSA-87. Its public
API supports parameter-bound key generation, deterministic and hedged Pure
ML-DSA signing, HashML-DSA signing, verification, strict encoded-object
validation, and typed failure reporting.

This audit records engineering assurance. It does not claim an independent
security audit, FIPS 140 validation, formal verification, or certification of
the crate as a cryptographic module.

## Source and API review

The crate manifest enables publication and identifies Rust 1.80 as the minimum
supported Rust version. The crate requires the Rust standard library and does
not claim allocation-only or `no_std` support.

The ordinary publication-facing surface consists of:

- `MlDsa`
- `MlDsaKeyGenSeed`
- `MlDsaKeyPair`
- `MlDsaPublicKey`
- `MlDsaPrivateKey`
- `MlDsaSignature`
- `MlDsaParameterSet`
- `MlDsaParameters`
- `MlDsaError`
- `PreHashAlgorithm`

Implementation modules are private in ordinary builds. The non-default
`internal-api` feature exposes hidden implementation modules for repository
validation, interoperability, timing, fuzzing, generated-code, benchmark, and
primitive-regression tooling. It is not part of the publication-facing SemVer
contract.

The crate root enforces:

```rust
#![forbid(unsafe_code)]
#![deny(missing_docs)]
```

The source scan found no unresolved production `TODO` or `FIXME` markers
and no unsafe code. Panic-oriented calls found by the broad scan were confined
to tests, documentation examples, and test-only code.

## Release gates

The following release gates completed successfully:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo package -p pqc-rs-ml-dsa
cargo publish -p pqc-rs-ml-dsa --dry-run
```

Results:

| Gate | Result |
| --- | --- |
| Workspace formatting | Passed |
| Workspace Clippy with warnings denied | Passed |
| Full workspace tests with all features | Passed |
| ML-DSA package construction | Passed |
| Packaged-crate compilation | Passed |
| crates.io publication dry run | Passed |

The package contained 50 files and was approximately 217.5 KiB uncompressed
and 48.1 KiB compressed.

The packaged ordinary-feature build emitted dead-code warnings for private
implementation and audit helpers that are exercised through repository-only
validation paths or the non-default `internal-api` feature. These warnings did
not affect package verification, publication metadata, the public API, or the
workspace Clippy gate with all targets and all features enabled.

## Functional validation

The ML-DSA test suite passed across all supported parameter sets. Coverage
includes:

- modular arithmetic, NTT operations, and polynomial operations;
- matrix expansion and bounded secret sampling;
- strict coefficient, key, and signature decoding;
- challenge generation and sparse-challenge multiplication;
- rounding, decomposition, and hint generation;
- deterministic and hedged signing;
- Pure ML-DSA and HashML-DSA verification;
- malformed-input and parameter-mismatch behavior;
- randomness-failure propagation;
- secret-type trait restrictions and lifecycle handling;
- mutation and negative-verification tests;
- public API and documentation tests.

Repository tooling also provides ACVP adapters, interoperability drivers,
timing characterization, signing-rejection traces, primitive timing tools, and
challenge-work equivalence checks.

## Published-artifact comparison

The published crate was downloaded from crates.io and extracted:

```text
cargo download pqc-rs-ml-dsa==0.4.0 > pqc-rs-ml-dsa-0.4.0.crate
tar -xf pqc-rs-ml-dsa-0.4.0.crate
```

A recursive comparison was performed between the extracted
`pqc-rs-ml-dsa-0.4.0` artifact and
`crates/pqc-ml-dsa` in the audited repository.

No differences were found in:

- `src/`;
- `tests/`;
- `benches/`;
- the cryptographic implementation;
- the publication-facing API;
- algorithm behavior.

Observed differences were limited to:

1. Cargo-generated package artifacts:
   - `.cargo_vcs_info.json`
   - `Cargo.lock`
   - `Cargo.toml.orig`

2. Cargo's normalized `Cargo.toml`, which expands workspace-inherited
   metadata, rewrites path dependencies as registry dependencies, and
   explicitly enumerates automatically discovered targets.

3. Repository README updates made after publication:
   - changing the status from pre-release to pre-1.0;
   - documenting crates.io installation;
   - retaining path-based workspace installation instructions;
   - replacing repository-relative contract links with stable GitHub links.

These differences are packaging or documentation differences. They do not
alter the published implementation or public API.

## Findings

No release-blocking defect was identified.

The published `pqc-rs-ml-dsa 0.4.0` implementation matches the current
repository implementation. The release gates pass, the package verifies
against crates.io dependencies, and no source-level discrepancy requires a
maintenance release.

## Conclusion

**The `pqc-rs-ml-dsa 0.4.0` release audit passed.**

No corrective `0.4.1` release is required based on this audit. The crate
remains pre-1.0 software and should continue to carry the documented statement
that it has not received an independent security audit and is not a
FIPS-validated cryptographic module.
