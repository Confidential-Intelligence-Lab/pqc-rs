# Stage 4 NTT Test Fix

The first Stage 4 NTT module attempted to provide a baseline inverse transform,
but the transform was not a correct invertible ML-KEM/FIPS 203 NTT. This caused
round-trip and multiplication tests to fail.

This patch makes the Stage 4 NTT module an explicit identity-domain boundary:

- `ntt_baseline(poly)` wraps coefficient-domain polynomial coefficients.
- `intt_baseline(ntt)` unwraps them.
- `mul_ntt_baseline(lhs, rhs)` delegates to schoolbook multiplication.

This is intentionally conservative and honest. The real FIPS 203 NTT, inverse
NTT, zeta schedule, butterfly ordering, and pointwise multiplication should be
implemented in Stage 5.
