# Stage 9C-4: ML-DSA Rounding and Decomposition

Stage 9C-4 implements:

- `Power2Round`;
- `Decompose`;
- `HighBits`;
- `LowBits`.

Both FIPS 204 `gamma2` values are supported:

- `(Q - 1) / 88` for ML-DSA-44;
- `(Q - 1) / 32` for ML-DSA-65 and ML-DSA-87.

## Tested properties

- `Power2Round` recombines exactly;
- decomposition recombines modulo `Q`;
- high bits remain in their parameter-specific range;
- low bits remain in the centered interval;
- decomposition is periodic modulo `Q`;
- boundary points around `gamma2`, `2*gamma2`, and modulus wrap are covered.

## Claim boundary

These tests establish algebraic and boundary properties. Independent FIPS 204
known-answer vectors remain required before a conformance claim.
