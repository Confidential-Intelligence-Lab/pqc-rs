# ML-DSA SemVer contract

This document freezes the publication-facing API baseline for the first
`pqc-rs-ml-dsa` release candidate. It covers ordinary builds only. The hidden
surface enabled by `internal-api` exists solely for repository assurance and is
outside this compatibility commitment.

## Reachable modules and crate-root items

The only supported public modules are `api`, `error`, and `params`. The crate
root re-exports:

- `MlDsa`;
- `MlDsaKeyGenSeed`;
- `MlDsaKeyPair`;
- `MlDsaPrivateKey`;
- `MlDsaPublicKey`;
- `MlDsaSignature`;
- `MlDsaError`;
- `MlDsaParameterSet`;
- `MlDsaParameters`;
- `PreHashAlgorithm`; and
- `ML_DSA_KEYGEN_SEED_BYTES`.

## Operations

`MlDsaKeyGenSeed` provides `from_bytes`, `parameter_set`, `as_bytes`, and
`expand`.

`MlDsaPublicKey` and `MlDsaSignature` each provide `from_bytes`,
`parameter_set`, `as_bytes`, and `into_bytes`. `MlDsaPrivateKey` provides
`from_bytes`, `parameter_set`, and `as_bytes`. `MlDsaKeyPair` provides
`public_key`, `private_key`, and `into_parts`.

`MlDsa` provides `new`, `parameter_set`, `public_key_bytes`,
`private_key_bytes`, `signature_bytes`, `keygen`, `generate_keygen_seed`,
`keygen_from_seed`, `sign_deterministic`, `sign_hedged`, `verify`,
`hash_sign_deterministic`, `hash_sign_hedged`, and `hash_verify`.

`MlDsaParameterSet` provides `parameters` and `name`.

## Closed enums and public parameter fields

The supported `MlDsaParameterSet` variants are `MlDsa44`, `MlDsa65`, and
`MlDsa87`.

The supported `MlDsaError` variants are `InvalidPublicKey`,
`InvalidPrivateKey`, `InvalidSignature`, `ContextTooLong`,
`ParameterSetMismatch`, `RandomnessFailure`, `RejectionLimitExceeded`, and
`InternalError`.

The supported `PreHashAlgorithm` variants are `Sha2_224`, `Sha2_256`,
`Sha2_384`, `Sha2_512`, `Sha2_512_224`, `Sha2_512_256`, `Sha3_224`,
`Sha3_256`, `Sha3_384`, `Sha3_512`, `Shake128`, and `Shake256`.

`MlDsaParameters` exposes the fields `k`, `l`, `eta`, `tau`, `gamma1`,
`gamma2`, `omega`, `public_key_bytes`, `private_key_bytes`, and
`signature_bytes`.

## Trait and ownership commitments

`MlDsa`, `MlDsaParameterSet`, `MlDsaParameters`, `MlDsaError`, and
`PreHashAlgorithm` implement `Clone`, `Copy`, `Debug`, `Eq`, and `PartialEq`.
`MlDsaError` also implements `Display` and `std::error::Error`.

`MlDsaPublicKey` and `MlDsaSignature` implement `Clone`, `Debug`, `Eq`, and
`PartialEq`. `MlDsaKeyGenSeed` and `MlDsaPrivateKey` intentionally implement
neither `Clone` nor `Debug`. `MlDsaKeyPair` intentionally does not implement
`Debug`.

The seed and expanded private-key wrappers retain zeroizing ownership. Exposing
their bytes through `as_bytes` remains an explicit caller-controlled action.

## Failure behavior

Malformed encodings, oversized contexts, parameter-set mismatches, randomness
failures, rejection-limit exhaustion, and internal invariant failures remain
typed `MlDsaError` results. Invalid caller-controlled data must not panic. A
well-formed but unauthentic signature remains `Ok(false)`. The exact mapping
and enforcement rules are recorded in the
[ML-DSA failure contract](ML_DSA_FAILURE_CONTRACT.md).

## Change control

Removing an item, changing a signature, weakening a trait or ownership
commitment, adding a reachable item, or exposing an implementation module
requires an explicit API and SemVer review. The generated workspace inventory,
this contract, the downstream compile contract, rustdoc, and package
reconstruction must be updated together.
