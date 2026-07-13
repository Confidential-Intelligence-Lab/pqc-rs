# Stage 9C-5: ML-DSA Hints

Stage 9C-5 implements:

- scalar `MakeHint`;
- scalar `UseHint`;
- polynomial hint generation;
- polynomial hint application;
- hint Hamming-weight accounting.

Both standardized `gamma2` variants are supported.

## Tested properties

- zero hint preserves the original high bits;
- generated hints are binary;
- polynomial hint weight matches the number of nonzero hint coefficients;
- polynomial application matches scalar application;
- one-step high-bit adjustments are reproduced across boundary inputs.

## Claim boundary

This stage validates hint structure and algebraic behavior. Full signing and
verification integration, encoding, and independent FIPS 204 vectors remain
for later stages.
