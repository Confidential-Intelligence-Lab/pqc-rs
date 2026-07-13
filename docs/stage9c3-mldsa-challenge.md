# Stage 9C-3: ML-DSA Challenge Sampling

Stage 9C-3 implements the sparse polynomial sampler used for ML-DSA
challenges.

## Algorithm

The sampler:

1. initializes SHAKE256 with a 32-byte challenge seed;
2. reads 64 sign bits;
3. samples positions using rejection sampling;
4. performs the in-place sparse permutation procedure;
5. assigns exactly `tau` coefficients to `-1` or `1`.

## Supported weights

- ML-DSA-44: `tau = 39`
- ML-DSA-65: `tau = 49`
- ML-DSA-87: `tau = 60`

## Acceptance criteria

- exact Hamming weight equals `tau`;
- nonzero coefficients are only `-1` or `1`;
- fixed seed and `tau` are deterministic;
- different seeds produce different challenges;
- invalid `tau` values are rejected;
- formatting, Clippy, and all workspace tests remain clean.

## Claim boundary

This stage validates structural challenge properties and deterministic
behavior. Independent known-answer vectors remain required before a
conformance claim.
