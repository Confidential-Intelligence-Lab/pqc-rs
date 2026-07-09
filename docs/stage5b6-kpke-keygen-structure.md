# Stage 5B-6: Deterministic K-PKE KeyGen Structure

## Scope

Stage 5B-6 wires together the previously introduced ML-KEM components into a
deterministic K-PKE key-generation structure.

## Added

- `kpke_keygen.rs`
- `expand_keygen_seed`
- `sample_noise_poly`
- `sample_noise_vector`
- `compute_public_vector`
- deterministic `keygen_from_seed`

## Validation

Tests verify:

- seed expansion determinism
- noise vector rank
- deterministic key generation for ML-KEM-512/768/1024 component sizes
- wrong keygen length rejection

## Conservative boundary

This is still structural. It uses the current matrix expansion, CBD sampling,
schoolbook polynomial arithmetic, and packing helpers. Stage 5B-7 should start
replacing the arithmetic path with the verified FIPS-domain path and/or wire
this into the K-PKE trait implementation.
