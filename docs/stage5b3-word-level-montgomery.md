# Stage 5B-3: Word-Level Montgomery Reduction

## Scope

Stage 5B-3 upgrades the Montgomery arithmetic path from an API-compatible
placeholder to the word-level form needed by the real ML-KEM NTT.

## Added

- `reduce_centered`
- word-level `montgomery_reduce`
- tests for negative products
- tests for centered representatives

## Rationale

The real FIPS/ML-KEM NTT uses Montgomery-domain constants and multiplication
patterns. Before replacing the NTT facade, the arithmetic layer needs to
behave like the word-level Montgomery path used by Kyber/ML-KEM
implementations.

## Next increment

Stage 5B-4 should replace the NTT facade with the first real butterfly
implementation, using the zeta schedule from Stage 5B-2 and the Montgomery
reducer from this stage.
