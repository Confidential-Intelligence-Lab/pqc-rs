# Stage 5B-13: Explicit NTT-Domain K-PKE Intermediates

## Scope

Stage 5B-13 introduces explicit NTT-domain types for polynomial vectors and
matrices. The working coefficient-domain K-PKE implementation remains
unchanged while these new representations are validated independently.

## Added

- `NttPolyVec`
- `NttPolyMatrix`
- coefficient-to-NTT vector conversion
- NTT-to-coefficient vector conversion
- NTT-domain vector inner product
- NTT-domain matrix-vector multiplication
- equivalence tests against coefficient-domain arithmetic

## Rationale

Stage 5B-12 routed polynomial products through the NTT while still converting
each product independently. Stage 5B-13 creates the representation boundary
required to keep secret vectors, public vectors, and matrices in the NTT
domain across multiple operations.

## Conservative boundary

The existing K-PKE keygen, encrypt, and decrypt functions are not switched to
these types yet. Stage 5B-14 should adopt these intermediates in keygen and
encryption only after the equivalence tests remain green.

## Conformance status

This remains internal validation. Authoritative FIPS 203 intermediate vectors
and official KATs are still pending.
