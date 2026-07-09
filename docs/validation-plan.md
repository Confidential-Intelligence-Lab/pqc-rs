# Validation Plan

## Validation levels

1. Compile-level validation: workspace builds across feature combinations.
2. Trait-level validation: all algorithm crates implement common interfaces.
3. KAT validation: deterministic vectors from normative specifications.
4. Negative validation: malformed keys, ciphertexts, signatures, and contexts.
5. Protocol validation: shared-secret agreement, transcript binding, downgrade checks.
6. Fuzz validation: parsers and protocol transcript decoders.
7. Constant-time validation: code review, `subtle`, Miri where useful, dudect-style testing.
8. Benchmark validation: criterion microbenchmarks and end-to-end protocol benchmarks.

## Stage 5A ML-KEM validation

Stage 5A validates FIPS 203 implementation structure:

- parameter-set algorithm constants
- FIPS NTT facade round trips
- `basemul` shape
- deterministic matrix expansion
- transposed matrix expansion path
- canonical sampled coefficients
- message-polynomial-message round trips

Production ML-KEM validation still requires complete FIPS 203 K-PKE internals and
official known-answer tests.
