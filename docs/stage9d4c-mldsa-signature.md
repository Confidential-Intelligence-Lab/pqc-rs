# Stage 9D-4C: Complete Deterministic Signing

This increment assembles the complete ML-DSA signing rejection loop:

1. sample `y` with `ExpandMask`;
2. compute `w = A * y`;
3. derive `w1` and `c_tilde`;
4. sample the sparse challenge `c`;
5. compute `z = y + c * s1`;
6. enforce the `gamma1 - beta` norm bound;
7. compute `r0 = LowBits(w) - c * s2`;
8. enforce the `gamma2 - beta` norm bound;
9. compute `c * t0` and enforce the `gamma2` norm bound;
10. generate hints and enforce the `omega` weight bound;
11. encode `sigma = c_tilde || z || h`.

The implementation supports deterministic signing with zero randomness and
hedged signing with caller-supplied 32-byte randomness.

The rejection loop includes a 10,000-attempt safety limit for explicit failure
during pre-conformance development.
