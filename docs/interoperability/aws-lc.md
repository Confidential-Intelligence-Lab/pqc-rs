# AWS-LC interoperability

PQC-rs includes an interoperability provider for AWS-LC covering the complete
ML-KEM and ML-DSA parameter-set families used by the canonical
software-provider parity framework.

## Tested source baseline

The integration is developed against the pinned AWS-LC source revision used by
the repository's interoperability environment.

The provider deliberately distinguishes facilities exposed through installed
public consumer APIs from facilities that exist only through lower-level or
internal interfaces. Exact interoperability claims are made only where the
tested interface permits the required deterministic inputs.

## Supported algorithms

The provider covers:

- ML-KEM-512;
- ML-KEM-768;
- ML-KEM-1024;
- ML-DSA-44;
- ML-DSA-65;
- ML-DSA-87.

## ML-KEM interoperability

AWS-LC exposes deterministic ML-KEM operations for the complete FIPS 203
parameter-set family used by the interoperability bridge.

The PQC-rs provider contract maps:

    key-generation seed = d || z
    encapsulation seed = m

The canonical gate requires byte-for-byte agreement between PQC-rs, AWS-LC,
wolfSSL, OpenSSL, and liboqs for:

- deterministic key generation;
- exact public-key encoding;
- exact secret-key encoding;
- deterministic encapsulation;
- exact ciphertext;
- exact shared secret;
- cross-provider decapsulation;
- exact implicit-rejection shared secrets for modified ciphertexts.

## ML-DSA seeded key generation

AWS-LC's public PQDSA interface accepts the 32-byte ML-DSA private-key seed and
derives the corresponding key pair. The provider exports the standardized
public key and expanded secret key through the public raw-key interfaces.

For ML-DSA-44, ML-DSA-65, and ML-DSA-87, the canonical gate requires exact
seeded public-key and expanded secret-key parity between PQC-rs, AWS-LC,
wolfSSL, and OpenSSL.

## ML-DSA signing and verification

AWS-LC's tested public EVP/PQDSA interface supports context-bound ML-DSA
signing and verification, raw standardized keys, and the FIPS 204 context
boundary.

The tested public consumer API does not expose caller-controlled
per-signature randomness. The provider therefore records:

    ml_dsa_explicit_signing_randomness = unsupported_by_public_api

AWS-LC does contain lower-level functionality that accepts controlled signing
randomness, but PQC-rs does not use a non-public interface merely to manufacture
an exact-signature parity result.

Consequently, AWS-LC is not included in the exact explicit-randomness signature
comparison. It participates in the semantic ML-DSA interoperability matrix.

The canonical gate validates:

- AWS-LC verification of PQC-rs signatures;
- PQC-rs verification of AWS-LC signatures;
- context-bound signature interoperability;
- the 255-byte context boundary;
- rejection of 256-byte contexts;
- modified-message rejection;
- modified-context rejection;
- wrong-public-key rejection;
- signature mutation rejection;
- malformed signature rejection;
- cross-parameter-set rejection.

## Public-API boundary

`unsupported_by_public_api` is a capability classification, not a statement
that AWS-LC lacks the corresponding cryptographic mechanism internally.

The distinction is important to the provider model: PQC-rs reports exact
deterministic parity only when the provider interface makes the required
deterministic input part of the tested interoperability contract.

## Execution

The canonical five-provider interoperability gate is:

    cargo xtask interop-cross --strict

The generated report records exact, semantic, boundary, and rejection results
under:

    target/interop-cross/report.json
    target/interop-cross/report.md

## Claim boundary

A successful AWS-LC interoperability result demonstrates the tested exact
ML-KEM, exact seeded-key ML-DSA, and semantic/negative ML-DSA interoperability
properties for the recorded AWS-LC build and PQC-rs revision.

It does not constitute FIPS validation, Common Criteria certification, formal
verification, or an independent security audit.
