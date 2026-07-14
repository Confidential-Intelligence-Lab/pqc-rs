# Stage 9D-4B: ML-DSA Signing Core

This increment corrects challenge sampling to accept the parameter-dependent
FIPS 204 challenge seed lengths:

- ML-DSA-44: 32 bytes;
- ML-DSA-65: 48 bytes;
- ML-DSA-87: 64 bytes.

It also adds the signing arithmetic needed by the final rejection loop:

- `A * y`;
- `HighBits` vector extraction;
- canonical `w1` encoding;
- challenge transcript derivation;
- sparse challenge multiplication;
- vector addition/subtraction with challenge products;
- infinity-norm checks;
- vector hint generation and weight accounting.

Stage 9D-4C will assemble these operations into the complete signing rejection
loop and final signature encoding.
