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
- Open Quantum Safe liboqs;
- AWS-LC.

All providers expose the same primitive interoperability protocol for:

- ML-KEM-512, ML-KEM-768, and ML-KEM-1024;
- ML-DSA-44, ML-DSA-65, and ML-DSA-87.

The framework distinguishes exact deterministic parity from semantic
interoperability. A facility that is not exposed by a provider's tested public
consumer API is recorded as `unsupported_by_public_api` rather than treated as
an interoperability failure.

## Capability summary

| Property | PQC-rs | wolfSSL | OpenSSL | liboqs | AWS-LC |
| --- | --- | --- | --- | --- | --- |
| ML-KEM 512/768/1024 | yes | yes | yes | yes | yes |
| Seeded ML-KEM key generation | exact | exact | exact | exact | exact |
| Deterministic ML-KEM encapsulation | exact | exact | exact | exact | exact |
| Cross-decapsulation | yes | yes | yes | yes | yes |
| Implicit rejection | exact | exact | exact | exact | exact |
| ML-DSA 44/65/87 | yes | yes | yes | yes | yes |
| Seeded ML-DSA key generation | exact | exact | exact | public API gap | exact |
| Explicit ML-DSA signing randomness | yes | yes | yes | public API gap | public API gap |
| Exact explicit-randomness signatures | exact | exact | exact | not tested | not tested |
| Semantic signature interoperability | yes | yes | yes | yes | yes |
| Context and negative semantics | yes | yes | yes | yes | yes |

Here, `public API gap` means `unsupported_by_public_api` for the tested provider
interface. It does not imply that the underlying implementation lacks the
corresponding internal functionality.

## Public API capability gaps

The interoperability framework distinguishes a cryptographic implementation
capability from the controls exposed by a provider's public consumer API.

A result recorded as:

    unsupported_by_public_api

means that the tested provider interface does not expose an input or operation
required to perform that particular interoperability experiment. It does not,
by itself, mean that the underlying cryptographic implementation lacks the
corresponding functionality.

This distinction matters most for deterministic interoperability tests. Exact
byte-for-byte comparison requires all inputs that influence an operation to be
controlled by the test harness. For example, exact ML-DSA signature comparison
requires the providers to use the same key, message, context, and explicit
per-signature randomness. If a public API performs randomized signing but does
not allow the caller to supply that randomness, signatures can be
cryptographically interoperable without being byte-for-byte identical.

The current matrix contains two such public-API boundaries:

- liboqs does not expose deterministic ML-DSA key generation through the tested
  public generic signature API and does not expose caller-controlled
  per-signature randomness;
- AWS-LC exposes seeded ML-DSA key generation through its public PQDSA
  interface, but its tested public EVP/PQDSA signing interface does not expose
  caller-controlled per-signature randomness.

AWS-LC contains lower-level functionality capable of accepting controlled
signing randomness. The interoperability provider deliberately does not use
non-public interfaces merely to obtain an exact-parity result.

Accordingly, `unsupported_by_public_api` is not counted as a failed
interoperability test. The canonical report instead tests the strongest
property supported by the provider's public interface: exact deterministic
parity where the required controls are public, and semantic interoperability
where they are not.

## ML-KEM coverage

The canonical gate requires byte-for-byte agreement across all five software
providers for all three ML-KEM parameter sets.

Coverage includes:

- deterministic key generation from `d` and `z`;
- exact public-key and secret-key encodings;
- deterministic encapsulation from `m`;
- exact ciphertext and shared-secret values;
- cross-provider decapsulation;
- exact implicit-rejection shared secrets for modified ciphertexts.

## ML-DSA coverage

PQC-rs, wolfSSL, OpenSSL, and AWS-LC expose deterministic ML-DSA key generation
through the tested provider interface. The canonical gate therefore requires
byte-for-byte agreement among those four providers for seeded public-key and
expanded secret-key generation.

PQC-rs, wolfSSL, and OpenSSL additionally expose caller-controlled
per-signature randomness through their tested public interfaces. Exact
signature parity is therefore required among those three providers.

liboqs does not expose deterministic ML-DSA key generation or caller-controlled
per-signature randomness through its tested public API. AWS-LC exposes seeded
key generation but does not expose caller-controlled signing randomness through
its tested public EVP/PQDSA interface. These capability boundaries are recorded
as `unsupported_by_public_api`.

All five providers participate in semantic interoperability tests covering:

- raw key interchange;
- cross-provider signature verification;
- empty and non-empty contexts;
- the 255-byte FIPS 204 context boundary;
- modified-message rejection;
- modified-context rejection;
- wrong-public-key rejection;
- signature mutations;
- malformed signature handling;
- 256-byte context rejection;
- cross-parameter-set misuse.

## Rejection behavior

Providers need not reject malformed inputs at the same software layer.

For example, PQC-rs may reject a malformed ML-DSA encoding at an API or
encoding boundary while another provider may consume the supplied bytes and
return a cryptographic verification failure.

The interoperability gate records the rejection mode but requires the
security-relevant property: invalid inputs must not be accepted.

## Provider protocol

Providers read one JSON request from standard input and write one JSON response
to standard output.

Protocol version 1 supports:

- capability discovery;
- ML-KEM key generation, encapsulation, and decapsulation;
- ML-DSA key generation, signing, and verification.

Diagnostics belong on standard error.

## HPKE provider substitution

The HPKE interoperability gate extends software-provider substitution above
the primitive ML-KEM boundary.

The current matrix exercises ML-KEM provider substitution bidirectionally
between PQC-rs and each external software provider:

- PQC-rs <-> liboqs;
- PQC-rs <-> OpenSSL;
- PQC-rs <-> wolfSSL / wolfCrypt;
- PQC-rs <-> AWS-LC.

The matrix covers ML-KEM-512, ML-KEM-768, and ML-KEM-1024, for a total of
24 directed HPKE interoperability cases.

For each case, recipient key generation, encapsulation, and decapsulation are
performed through the selected ML-KEM providers. The resulting 32-byte KEM
shared secret then crosses a fixed HPKE boundary.

The HPKE layer remains unchanged across provider substitutions:

- native PQC-rs HPKE implementation;
- RFC 9180 Base mode;
- HKDF-SHA256;
- AES-128-GCM;
- application `info`, AAD, and plaintext semantics;
- exporter behavior;
- sender and receiver sequence semantics.

The resulting native Rust transcript is compared against an independent Python
RFC 9180 reference implementation. Each passing case compares the derived key,
base nonce, exporter secret, key-schedule context, ciphertext, recovered
plaintext, exported secret, and sender/receiver sequence numbers.

The canonical HPKE gate is:

    cargo xtask interop-hpke --strict

The current five-provider matrix passes:

    executed=24
    passed=24
    failed=0

The same 24/24 result is reproduced by the GitHub Actions HPKE
interoperability workflow.

This demonstrates KEM execution-provider substitution without redefining the
HPKE protocol or application-facing secure-channel semantics. It does not
claim RFC 9180 Auth or AuthPSK interoperability.

## Additional interoperability gates

The repository also contains focused interoperability and protocol-validation
gates, including:

- the generic provider protocol self-test;
- provider-specific regression mechanisms;
- HPKE interoperability.

These focused gates complement the canonical five-provider parity gate.

## Provider-specific documentation

- [liboqs interoperability](liboqs.md)
- [OpenSSL PQC interoperability](OPENSSL_ML_DSA.md)
- [AWS-LC interoperability](aws-lc.md)

## Claim boundary

A successful software-provider parity report demonstrates the tested
interoperability properties for the named provider builds and PQC-rs revision.

It does not constitute FIPS validation, Common Criteria certification, formal
verification, or an independent security audit.
