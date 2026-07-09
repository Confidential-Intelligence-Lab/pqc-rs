# Stage 5B-8: Deterministic K-PKE Decryption Structure

## Scope

Stage 5B-8 adds deterministic structural K-PKE decryption.

## Added

- `kpke_decrypt.rs`
- CPA secret-key component decoding
- ciphertext component decoding
- `compute_message_poly`
- `decrypt_to_message`

## Validation

Tests verify:

- secret-key decoding
- ciphertext decoding shape
- decryption output message shape for ML-KEM-512 and ML-KEM-768
- malformed ciphertext length rejection
- malformed secret-key length rejection

## Conservative boundary

This stage checks structural decryption shape, not official ML-KEM correctness.
Full correctness requires the verified FIPS-domain NTT/K-PKE arithmetic path and
official known-answer tests.
