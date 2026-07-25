# pqc-rs-ml-dsa

`pqc-rs-ml-dsa` is the FIPS 204 ML-DSA implementation in the
[PQC-rs](https://github.com/Confidential-Intelligence-Lab/pqc-rs) ecosystem.
It provides parameter-bound key generation, signing, verification, strict
encoded-object decoding, and HashML-DSA through a typed crate-root API.

> **Status:** This is pre-release software. It has not received an independent
> security audit and is not a FIPS-validated cryptographic module. Crates.io
> publication remains disabled until the complete release-candidate evidence
> and publication gates have passed.

## Supported parameter sets

| Parameter set | Public key | Private key | Signature |
| --- | ---: | ---: | ---: |
| ML-DSA-44 | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| ML-DSA-65 | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| ML-DSA-87 | 2,592 bytes | 4,896 bytes | 4,627 bytes |

The crate supports Pure ML-DSA and HashML-DSA, deterministic and hedged
signing, contexts of up to 255 bytes, and the prehash algorithms approved by
FIPS 204.

## Installation during pre-release evaluation

Until the crate is published, use a checked-out PQC-rs workspace or an
explicit path dependency:

```toml
[dependencies]
pqc-rs-ml-dsa = { path = "../pqc-rs/crates/pqc-ml-dsa" }
rand_core = { version = "0.6", features = ["getrandom"] }
```

The Rust library name is `pqc_ml_dsa`. This release requires the Rust standard
library. `--no-default-features` remains a `std` build; allocation-only and
`no_std` profiles are not currently supported.

## Quick start

```rust
use pqc_ml_dsa::{MlDsa, MlDsaParameterSet};
use rand_core::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let implementation = MlDsa::new(MlDsaParameterSet::MlDsa65);
    let mut rng = OsRng;
    let key_pair = implementation.keygen(&mut rng)?;

    let message = b"message to authenticate";
    let context = b"example-v1";
    let signature = implementation.sign_hedged(
        key_pair.private_key(),
        message,
        context,
        &mut rng,
    )?;

    assert!(implementation.verify(
        key_pair.public_key(),
        message,
        context,
        &signature,
    )?);
    Ok(())
}
```

The supported API consists of the crate-root types `MlDsa`, `MlDsaKeyGenSeed`,
`MlDsaKeyPair`, `MlDsaPublicKey`, `MlDsaPrivateKey`, `MlDsaSignature`,
`MlDsaParameterSet`, `MlDsaParameters`, `MlDsaError`, and
`PreHashAlgorithm`, together with the documented `api`, `error`, and `params`
modules. Arithmetic, encoding, sampling, signing, verification, and audit
internals are private in ordinary builds.

The non-default `internal-api` feature exposes hidden implementation modules
solely for repository ACVP, fuzzing, timing, generated-code, benchmark, and
primitive-regression tooling. It is not part of the publication-facing API or
SemVer stability contract. Applications must not enable or depend on it.

The exact reachable API, method signatures, enum variants, public parameter
fields, and trait commitments are recorded in the
[ML-DSA SemVer contract](../../docs/api/ML_DSA_SEMVER_CONTRACT.md). Changes to
that baseline require an explicit API review and synchronized contract update.

Malformed encodings, oversized contexts, parameter-set mismatches, and
randomness failures return typed errors. The
[ML-DSA failure contract](../../docs/api/ML_DSA_FAILURE_CONTRACT.md) records
the panic-free production-source rule and its adversarial-input tests.

Use `MlDsa::keygen` for ordinary randomized key generation. The compact
`MlDsaKeyGenSeed` and deterministic signing operations are explicit APIs for
reproducible validation and controlled provisioning. Prefer hedged signing
when fresh cryptographic randomness is available.

## Encoding and secret handling

`MlDsaPublicKey::from_bytes`, `MlDsaPrivateKey::from_bytes`, and
`MlDsaSignature::from_bytes` perform strict, parameter-bound decoding. A key or
signature cannot be used with a different `MlDsa` parameter set without a
`ParameterSetMismatch` error.

Key-generation seeds and expanded private keys use zeroizing storage and do
not implement `Clone` or `Debug`. Calls to `as_bytes` deliberately expose
secret bytes to the caller; applications remain responsible for copies,
persistence, access control, and lifecycle management outside these wrappers.

## Validation scope

Repository assurance includes NIST ACVP coverage, negative and malformed-input
tests, structured fuzzing, secret-lifetime checks, timing characterization, and
bidirectional interoperability with liboqs for ML-DSA-44, ML-DSA-65, and
ML-DSA-87. It also includes bidirectional Pure ML-DSA cross-verification and
negative-verification cases with a recorded OpenSSL 3.5-or-later provider.
These are engineering evidence, not a formal proof, certification, or
substitute for an independent review.

See the [PQC-rs security policy](https://github.com/Confidential-Intelligence-Lab/pqc-rs/blob/main/SECURITY.md)
and [FIPS 204 traceability documentation](https://github.com/Confidential-Intelligence-Lab/pqc-rs/blob/main/docs/standards/FIPS204.md)
for the supported-version policy, reporting instructions, and detailed
standards mapping.

## License

Licensed under either Apache-2.0 or MIT, at your option.
