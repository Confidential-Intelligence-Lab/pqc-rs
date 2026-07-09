# Stage 5A: FIPS 203 ML-KEM Implementation Structure

## Scope

Stage 5A introduces the modules needed to move from scaffolding toward a real
FIPS 203 ML-KEM implementation.

## Added modules

- `fips_ntt.rs`: dedicated FIPS NTT facade
- `matrix.rs`: deterministic matrix expansion and rejection sampling structure
- `encoding.rs`: message-to-polynomial and polynomial-to-message helpers

## Completed

- parameter-set algorithm constants: `k`, `eta1`, `eta2`, `du`, `dv`
- FIPS NTT facade and `basemul` shape
- matrix expansion from `rho`
- transposed matrix expansion path
- rejection-sampling helper
- message encoding/decoding helpers
- tests for deterministic expansion, canonical coefficients, and round trips

## Explicit non-goals

Stage 5A still does not claim production ML-KEM compliance.

Remaining for Stage 5B/6:

- exact FIPS 203 zeta schedule
- forward NTT and inverse NTT butterfly implementation
- streaming rejection sampler until 256 coefficients are obtained
- K-PKE keygen/encrypt/decrypt
- ML-KEM keygen/encaps/decaps
- official FIPS 203 KAT validation
