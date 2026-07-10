# Stage 5B-15: Intermediate-Value Golden Fixtures

## Scope

Stage 5B-15 adds deterministic intermediate-value capture for the current K-PKE
implementation.

## Captured checkpoints

- key-generation seed
- `rho`
- `sigma`
- message
- encryption randomness
- digest of `A[0][0]`
- digest of `s[0]`
- digest of `e[0]`
- packed public key
- packed CPA secret-key component
- packed ciphertext

## Validation goals

The fixtures provide a stable regression oracle across:

- arithmetic refactoring
- representation changes
- packing changes
- future optimization
- SIMD implementations
- architecture-specific backends

## Conformance boundary

These fixtures are internal golden values. They are not official FIPS 203 KATs
and do not establish conformance.

Stage 5B-16 should add an authoritative vector import path and compare official
intermediate values against the same capture points.
