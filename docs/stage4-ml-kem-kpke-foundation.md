# Stage 4: ML-KEM NTT and K-PKE Foundation

## Scope

Stage 4 introduces the boundaries required for the FIPS 203 K-PKE layer.

## Added modules

- `ntt.rs`: baseline NTT-domain helper and tests
- `polyvec.rs`: polynomial-vector type and dot products
- `kpke.rs`: parameter-set-specific K-PKE API boundary

## Completed

- `NttPoly` representation
- baseline NTT/intt round-trip tests
- NTT-domain multiplication consistency test
- `PolyVec` rank-constrained vector helper
- `Kpke512`, `Kpke768`, `Kpke1024` API boundaries
- K-PKE message and randomness types
- deterministic K-PKE scaffold shape tests

## Explicit non-goals

Stage 4 does not yet claim production ML-KEM compliance.

Remaining work:

- FIPS 203 zeta ordering
- optimized Cooley-Tukey/inverse NTT butterflies
- matrix expansion from seed
- `sample_ntt`
- K-PKE keygen/encrypt/decrypt internals
- ML-KEM keygen/encaps/decaps integration
- official KAT validation

## Stage 5 handoff

Stage 5 should replace the baseline NTT and scaffold K-PKE internals with the
FIPS 203 arithmetic path and deterministic KAT-compatible APIs.
