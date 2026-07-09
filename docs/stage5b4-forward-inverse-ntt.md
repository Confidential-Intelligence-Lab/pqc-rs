# Stage 5B-4: Forward and Inverse FIPS NTT Path

## Scope

Stage 5B-4 replaces the previous identity NTT facade with a Kyber/ML-KEM-style
forward and inverse butterfly path using the compact zeta schedule introduced in
Stage 5B-2 and the word-level Montgomery arithmetic introduced in Stage 5B-3.

## Added

- forward NTT butterfly loop
- inverse NTT butterfly loop
- inverse-NTT scale factor
- canonical-output checks
- round-trip tests for zero, one, and structured polynomials

## Conservative boundary

The `multiply` helper still delegates to schoolbook multiplication. This keeps
the stage correctness-preserving while Stage 5B-5 focuses specifically on
verified NTT-domain base multiplication.

## Next increment

Stage 5B-5 should implement complete NTT-domain multiplication:

- pairwise `basemul` over NTT-domain degree-one factors
- correct zeta-index mapping for all 128 pairs
- comparison against schoolbook multiplication after inverse NTT
