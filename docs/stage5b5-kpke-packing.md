# Stage 5B-5: K-PKE Packing Helpers

## Scope

Stage 5B-5 adds byte packing helpers for the object shapes used by ML-KEM's
K-PKE component.

## Added

- `packing.rs`
- public-key component packing
- public-key component splitting
- CPA secret-key component packing
- ciphertext component packing
- ciphertext component splitting
- message byte encoding helper

## Validation

Tests verify:

- component lengths match ML-KEM-512, ML-KEM-768, and ML-KEM-1024 sizes
- public-key component packing/splitting
- secret-key component packing
- ciphertext component packing/splitting
- wrong-rank rejection
- wrong-length rejection

## Next increment

Stage 5B-6 should begin wiring these helpers into deterministic K-PKE key
generation and encryption/decryption structure.
