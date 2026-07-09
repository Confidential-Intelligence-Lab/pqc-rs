# Optimization Plan

Optimization is staged after correctness.

## Order

1. Portable constant-time Rust.
2. Allocation reduction and stack discipline.
3. XOF and hash-state reuse.
4. Polynomial arithmetic specialization.
5. NTT optimization.
6. Feature-gated AVX2 and NEON backends.
7. Benchmark-driven protocol-level optimization.

## Stage 2 note

ML-KEM optimization does not begin until the production arithmetic path replaces
the Stage 2 scaffold implementation.
