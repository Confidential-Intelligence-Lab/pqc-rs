# Stage 5B-1: Montgomery and Barrett Arithmetic

## Scope

Stage 5B-1 begins the real FIPS 203 implementation path by hardening the
finite-field arithmetic layer used by ML-KEM.

FIPS 203 standardizes ML-KEM and specifies the three parameter sets
ML-KEM-512, ML-KEM-768, and ML-KEM-1024. The standard's algorithmic path uses
K-PKE as a subroutine under the ML-KEM transform. This stage prepares the
modular arithmetic layer needed by the K-PKE/NTT implementation.

## Added

- `MONTGOMERY_R`
- `MONTGOMERY_R_MOD_Q = 2285`
- `MONTGOMERY_R_INV_MOD_Q = 169`
- `MONTGOMERY_QINV = 3327`
- `BARRETT_V = 20159`
- `barrett_reduce`
- `montgomery_reduce`
- `to_montgomery`
- `from_montgomery`
- `montgomery_mul`

## Validation

Added tests verify:

- Barrett reduction agrees with canonical modular reduction.
- Montgomery constants are internally consistent.
- Montgomery conversion round trips.
- Montgomery-domain multiplication agrees with standard modular
  multiplication after conversion back to the standard domain.

## Non-goals

This stage does not yet replace the Stage 5A FIPS NTT facade. That is the
next increment.
