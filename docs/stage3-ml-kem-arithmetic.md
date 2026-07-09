# Stage 3: ML-KEM Arithmetic Foundation

## Scope

Stage 3 introduces the first real implementation layer below the public ML-KEM
API.

## Added modules

- `arithmetic.rs`: field arithmetic modulo q = 3329
- `poly.rs`: polynomial representation, 12-bit encoding, compression
- `sampling.rs`: centered binomial samplers for eta = 2 and eta = 3
- `symmetric.rs`: SHA3/SHAKE helper functions

## Completed

- canonical modular reduction
- modular addition, subtraction, and multiplication
- coefficient compression/decompression
- polynomial add/subtract
- schoolbook negacyclic multiplication
- 12-bit polynomial encode/decode
- CBD eta2 and eta3 sampling
- SHA3-256, SHA3-512, SHAKE128, SHAKE256 helpers

## Explicit non-goals

Stage 3 does not yet implement:

- NTT or inverse NTT
- matrix expansion into NTT-domain polynomials
- FIPS 203 K-PKE key generation
- FIPS 203 K-PKE encryption/decryption
- ML-KEM keygen/encaps/decaps internals
- official KAT validation

## Stage 4 handoff

Stage 4 should implement the FIPS 203 K-PKE layer:

- NTT-domain representation
- NTT/inverse NTT
- matrix expansion
- vector-of-polynomial operations
- byte encoding for public keys, secret keys, and ciphertexts
- K-PKE keygen/encrypt/decrypt
