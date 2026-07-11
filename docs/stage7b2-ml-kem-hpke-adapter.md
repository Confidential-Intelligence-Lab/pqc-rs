# Stage 7B-2: Pure ML-KEM HPKE KEM Adapter

This stage implements the pure ML-KEM KEM interface from
`draft-ietf-hpke-pq-05`.

## KEM identifiers and dimensions

| KEM | ID | Nsecret | Nenc | Npk | Nsk |
|---|---:|---:|---:|---:|---:|
| ML-KEM-512 | 0x0040 | 32 | 768 | 800 | 64 |
| ML-KEM-768 | 0x0041 | 32 | 1088 | 1184 | 64 |
| ML-KEM-1024 | 0x0042 | 32 | 1568 | 1568 | 64 |

`Nsk = 64` reflects the HPKE seed-format private key `d || z`, rather
than the expanded FIPS 203 decapsulation key.

## Implemented operations

- `DeriveKeyPair(ikm)` using SHAKE256 `LabeledDerive`;
- expansion of the 64-byte seed private key with
  `ML-KEM.KeyGen_internal`;
- identity public/private key serialization with length checks;
- deterministic encapsulation for validation;
- decapsulation after expansion of the seed private key;
- mapping of ML-KEM key-check failures to HPKE KEM errors.

## Deliberately pending

- randomized `GenerateKeyPair`;
- randomized public `Encap`;
- RFC 9180 sender/receiver contexts;
- AEAD state;
- full test-vector execution from the pinned draft;
- PQ/traditional hybrid KEMs.
