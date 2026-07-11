# Stage 7 HPKE Integration Profile

## Normative base

RFC 9180 defines the HPKE architecture, including:

- KEM, KDF, and AEAD composition;
- sender and receiver setup;
- Base, PSK, Auth, and AuthPSK modes;
- key schedule and context construction;
- nonce sequencing;
- encryption, decryption, and exporter interfaces.

## Pinned experimental PQ extension

Stage 7 pins:

```text
draft-ietf-hpke-pq-05
published: 2026-07-06
expires:   2027-01-07
```

Pure post-quantum KEM targets:

- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

PQ/traditional hybrid KEM targets:

- X25519 + ML-KEM-768
- P-256 + ML-KEM-768
- P-384 + ML-KEM-1024

## Planned implementation sequence

1. Stage 7B-1: RFC 9180 labeled extract/expand and suite identifiers.
2. Stage 7B-2: ML-KEM HPKE KEM adapter.
3. Stage 7B-3: Base-mode sender and receiver contexts.
4. Stage 7B-4: AEAD state, nonce sequencing, and exporter.
5. Stage 7B-5: pure ML-KEM HPKE vector validation.
6. Stage 7C: PQ/traditional hybrid KEM composition and vectors.

## Revision policy

Draft-specific identifiers and vectors must be isolated behind a named
revision module. Updating the pinned draft requires:

- a new revision identifier;
- a documented semantic diff;
- complete rerun of draft vectors;
- no silent reassignment of algorithm identifiers.
