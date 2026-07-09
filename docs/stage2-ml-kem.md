# Stage 2: ML-KEM API and Harness Scaffold

## Scope

Stage 2 introduces the ML-KEM crate as a typed, testable API boundary.

## Completed

- `MlKem512`, `MlKem768`, `MlKem1024`
- public constants for key, ciphertext, and shared-secret sizes
- `MlKemParameterSet`
- `Kem` trait implementations
- round-trip API tests
- malformed-length public-key decode tests
- KAT manifest shape

## Explicit non-goals

Stage 2 does not implement production ML-KEM arithmetic, compression,
decompression, sampling, NTT, or FIPS 203 KAT validation.

## Stage 3 handoff

Stage 3 should replace the placeholder internals with FIPS 203-compatible
arithmetic:

- polynomial ring representation
- centered binomial sampling
- XOF expansion
- NTT and inverse NTT
- matrix expansion
- compression and decompression
- keygen, encaps, decaps internals
- official KAT ingestion
