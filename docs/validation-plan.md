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

## Stage 4 ML-KEM validation

Stage 4 validates the K-PKE foundation:

- baseline NTT round-trip behavior
- baseline NTT multiplication compared with schoolbook multiplication
- polynomial-vector rank and dot-product behavior
- K-PKE key/ciphertext shape invariants
- previously introduced Stage 3 arithmetic tests

Production ML-KEM validation still requires FIPS 203 K-PKE internals and official
known-answer tests.
