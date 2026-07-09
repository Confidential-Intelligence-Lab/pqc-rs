# Stage 5B-7: Deterministic K-PKE Encryption Structure

## Scope

Stage 5B-7 wires together public-key decoding, encryption noise sampling,
structural polynomial-vector arithmetic, message encoding, and ciphertext
packing.

## Added

- `kpke_encrypt.rs`
- `decode_polyvec_12`
- `decode_public_key_component`
- `sample_eta2_poly`
- `sample_eta2_vector`
- `compute_u_vector`
- `compute_v_poly`
- deterministic `encrypt_from_randomness`

## Validation

Tests verify:

- public-key component decoding
- eta2 vector rank
- deterministic encryption for ML-KEM-512/768/1024 component sizes
- wrong ciphertext length rejection
- malformed public-key rejection

## Conservative boundary

This remains structural. Stage 5B-8 should add ciphertext decoding and
deterministic K-PKE decryption structure.
