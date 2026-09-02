# OpenSSL PQC interoperability

PQC-rs includes a native OpenSSL interoperability provider using the OpenSSL 3
provider-oriented EVP APIs.

## Supported algorithms

The provider covers:

- ML-KEM-512;
- ML-KEM-768;
- ML-KEM-1024;
- ML-DSA-44;
- ML-DSA-65;
- ML-DSA-87.

OpenSSL 3.5 or later is required for the PQC provider functionality used by
this interoperability layer.

## ML-KEM interoperability

OpenSSL exposes the deterministic inputs required to exercise FIPS 203 through
its EVP provider API.

The PQC-rs interoperability contract maps:

    key-generation seed = d || z
    encapsulation input = m

The canonical interoperability gate requires byte-for-byte agreement between
PQC-rs, OpenSSL, wolfSSL, liboqs, and AWS-LC for all three ML-KEM
parameter sets.

Coverage includes:

- deterministic key generation;
- exact public-key encoding;
- exact secret-key encoding;
- deterministic encapsulation;
- exact ciphertext;
- exact shared secret;
- cross-provider decapsulation;
- exact implicit-rejection behavior for modified ciphertexts.

## ML-DSA interoperability

OpenSSL exposes the deterministic facilities needed for exact FIPS 204
comparison:

- seeded key generation;
- context-bound signing;
- explicit per-signature test entropy;
- raw public-key and secret-key import/export.

The canonical parity gate requires byte-for-byte agreement between PQC-rs,
wolfSSL, and OpenSSL for:

- public keys generated from the same seed;
- secret keys generated from the same seed;
- signatures generated from the same message, context, and explicit signing
  randomness.

OpenSSL also participates in the complete five-provider semantic matrix,
including:

- raw key interchange;
- bidirectional signature verification;
- the 255-byte context boundary;
- modified-message rejection;
- modified-context rejection;
- wrong-public-key rejection;
- signature mutation rejection;
- malformed signature handling;
- 256-byte context rejection;
- cross-parameter-set rejection.

## Rejection behavior

PQC-rs and OpenSSL need not reject malformed signatures at the same software
layer.

PQC-rs performs strict encoding checks for some malformed signatures, while
OpenSSL may consume the supplied byte string and return failed cryptographic
verification.

The canonical interoperability gate records the rejection mode separately and
requires the security-relevant outcome: the invalid signature must not be
accepted.

## Execution

The canonical five-provider interoperability gate is:

    cargo xtask interop-cross --strict

A focused OpenSSL interoperability runner remains available as a provider-
specific regression mechanism.

## Claim boundary

A successful OpenSSL interoperability result demonstrates the tested exact
ML-KEM, exact deterministic ML-DSA, and semantic/negative interoperability
properties for the recorded OpenSSL build and PQC-rs revision.

It does not constitute FIPS validation, Common Criteria certification, formal
verification, or an independent security audit.
