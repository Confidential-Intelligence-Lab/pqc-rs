# Interoperability

PQC-rs uses a provider-oriented interoperability framework to compare the
native Rust implementation with independent cryptographic implementations.

The canonical software-provider parity gate is:

    cargo xtask interop-cross --strict

Reports are written to:

    target/interop-cross/report.json
    target/interop-cross/report.md

## Software providers

The current software-provider matrix contains:

- PQC-rs native Rust implementation;
- wolfSSL / wolfCrypt;
- OpenSSL 3.5 or later;
- Open Quantum Safe liboqs.

All providers expose the same primitive interoperability protocol for:

- ML-KEM-512, ML-KEM-768, and ML-KEM-1024;
- ML-DSA-44, ML-DSA-65, and ML-DSA-87.

## ML-KEM coverage

The canonical gate requires byte-for-byte agreement across PQC-rs, wolfSSL,
OpenSSL, and liboqs for all three ML-KEM parameter sets.

Coverage includes:

- deterministic key generation from `d` and `z`;
- exact public-key and secret-key encodings;
- deterministic encapsulation from `m`;
- exact ciphertext and shared-secret values;
- cross-provider decapsulation;
- implicit-rejection behavior for modified ciphertexts.

## ML-DSA coverage

PQC-rs, wolfSSL, and OpenSSL expose deterministic ML-DSA key generation and
explicit per-signature randomness through their public APIs.

The canonical gate therefore requires exact byte-for-byte agreement between
those three providers for:

- seeded key generation;
- public-key and secret-key encodings;
- explicit-randomness signing;
- signature encodings.

All four providers, including liboqs, participate in semantic interoperability
tests covering:

- raw key interchange;
- bidirectional signature verification;
- empty and non-empty contexts;
- the 255-byte FIPS 204 context boundary;
- modified-message rejection;
- modified-context rejection;
- wrong-public-key rejection;
- signature mutations;
- malformed signature handling;
- 256-byte context rejection;
- cross-parameter-set misuse.

liboqs does not expose deterministic ML-DSA key generation or explicit
per-signature randomness through its public API. The report records these
capabilities as `unsupported_by_public_api`; they are not treated as failures.

## Rejection behavior

Providers need not reject malformed inputs at the same software layer.

For example, PQC-rs may reject malformed ML-DSA encodings before verification,
while another provider may accept the byte sequence as input and return a
cryptographic verification failure.

The interoperability gate records the rejection mode but requires the
externally relevant property: invalid inputs must not be accepted.

## Provider protocol

Providers read one JSON request from standard input and write one JSON response
to standard output.

Protocol version 1 supports:

- capability discovery;
- ML-KEM key generation, encapsulation, and decapsulation;
- ML-DSA key generation, signing, and verification.

Diagnostics belong on standard error.

## Additional interoperability gates

The repository also contains focused interoperability and protocol-validation
gates, including:

- the generic provider protocol self-test;
- provider-specific liboqs and OpenSSL validation;
- HPKE interoperability.

These focused gates complement the canonical four-provider parity gate.

## Claim boundary

A successful software-provider parity report demonstrates the tested
interoperability properties for the named provider builds and PQC-rs revision.

It does not constitute FIPS validation, Common Criteria certification, formal
verification, or an independent security audit.
