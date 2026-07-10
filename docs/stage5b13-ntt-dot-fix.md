# Stage 5B-13 NTT Dot-Product Fix

The initial `dot_to_poly` implementation converted every partial base
multiplication to coefficient space and then transformed the running sum back
into the NTT domain. That introduced a Montgomery-domain scaling mismatch.

The corrected implementation:

1. computes each pairwise base multiplication in the NTT domain,
2. accumulates the resulting NTT coefficients directly modulo `q`,
3. applies `invntt_tomont` exactly once after the full inner product.

This matches the arithmetic structure used by the verified polynomial
multiplication path.
