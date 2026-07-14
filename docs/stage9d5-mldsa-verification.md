# Stage 9D-5: Strict ML-DSA Verification

This stage implements:

- strict public-key decoding;
- strict signature decoding;
- canonical sparse-hint decoding;
- response-vector norm validation;
- public-key hashing and message-representative generation;
- challenge reconstruction;
- `A * z - c * t1 * 2^D`;
- hint application;
- challenge-transcript recomputation;
- constant-time challenge-seed comparison;
- positive and negative verification tests for all parameter sets.

Malformed encodings return explicit errors. Well-formed but mathematically
invalid signatures return `Ok(false)`.

The verification flow follows FIPS 204 Algorithm 8 and is cross-checked against
the official CRYSTALS-Dilithium reference implementation structure.
