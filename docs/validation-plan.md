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

## Stage 3 ML-KEM validation

Stage 3 validates the arithmetic foundation:

- modular reduction and field operations
- coefficient compression and decompression
- polynomial encode/decode round trips
- schoolbook multiplication identity behavior
- CBD sampler range sanity
- SHA3/SHAKE determinism and domain separation

Production ML-KEM validation still requires official FIPS 203 known-answer tests.
