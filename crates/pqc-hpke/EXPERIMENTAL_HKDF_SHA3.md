# Experimental HKDF-SHA3-256 for HPKE

## Status

PQC-rs provides an opt-in experimental HPKE key-schedule
extension based on HKDF with HMAC-SHA3-256.

Enable the Cargo feature:

    experimental-hkdf-sha3

The feature is disabled by default.

The local experimental KDF identifier is 0xff01.
It is not an IANA assignment and is not claimed to
belong to a reserved private-use range.

Its availability was checked against the IANA HPKE
KDF registry during development, but is not guaranteed
indefinitely.

Applications must explicitly agree on the experimental
suite definition. This extension must not be advertised
as a standardized HPKE ciphersuite.

## Cryptographic construction

- Extract: HMAC-SHA3-256.
- Expand: RFC 5869 HKDF using HMAC-SHA3-256.
- Hash output length: 32 bytes.
- Maximum expansion length: 8160 bytes.
- HPKE labeled operations: RFC 9180 encoding.
- Suite identifiers: existing HPKE suite encoding with
  the explicit experimental KDF identifier.

The existing SHA-2 KDF identifiers and implementations
remain unchanged.

The extension reuses existing RustCrypto SHA3 and HKDF
dependencies. No new runtime cryptographic dependency
is required.

The extension changes the HPKE key-schedule KDF.
It does not change KEM key derivation, the hybrid
combiner, or the AEAD algorithm.

## Supported combinations

When explicitly enabled, the experimental KDF can be
used with existing pure ML-KEM Base and PSK interfaces,
and hybrid Base interfaces.

The existing supported_kdfs() enumeration is unchanged.
It does not advertise the experimental KDF.

Applications must explicitly select:

    KdfId::EXPERIMENTAL_HKDF_SHA3_256

Hybrid PSK support is not introduced.

## Example

    use pqc_hpke::{
        AeadId, HpkeSuite, KdfId, MlKemHpke,
    };

    let suite = HpkeSuite::new(
        MlKemHpke::MlKem768,
        KdfId::EXPERIMENTAL_HKDF_SHA3_256,
        AeadId::AES_256_GCM,
    )?;

The suite can be used with the existing sender and
receiver setup interfaces.

Hybrid setup accepts an explicit HpkeSuiteId containing
the experimental KDF identifier.

## Validation

The extension has been evaluated using:

- Independent labeled HKDF reference vectors.
- Twelve independent Base and PSK key-schedule vectors.
- Twenty-seven experimental mode/suite configurations.
- Twenty-seven corresponding SHA256 controls.
- Bidirectional cross-KDF authentication rejection.
- Modified ciphertext and associated-data rejection.
- Recipient key and application-context binding checks.
- Malformed encapsulation and PSK negative tests.
- Exporter boundary checks.
- Randomized sender round trips.
- Default-feature isolation.
- Independent-provider Base-mode interoperability.

The independent-provider campaign covers ML-KEM-768
and ML-KEM-768 combined with X25519, using AES-256-GCM
and both SHA256 and experimental SHA3-256 KDFs.

The reference independently composes OpenSSL-backed
ML-KEM, X25519 and AES-GCM operations with Python SHA3,
HMAC and HPKE key-schedule code.

It is an independent reference composition, not an
off-the-shelf standardized SHA3 HPKE implementation.

## Reproduce tests

From the workspace root:

    cargo test --locked -p pqc-rs-hpke

    cargo test --locked -p pqc-rs-hpke \
      --features experimental-hkdf-sha3,internal-api

    cargo test --release --locked -p pqc-rs-hpke \
      --features experimental-hkdf-sha3,internal-api

    cargo clippy --locked -p pqc-rs-hpke \
      --all-targets --all-features -- -D warnings

## Reproduce independent key-schedule vectors

    python3 \
      crates/pqc-hpke/tests/fixtures/generate_sha3_key_schedule.py \
      > /tmp/sha3-key-schedule.tsv

    cmp /tmp/sha3-key-schedule.tsv \
      crates/pqc-hpke/tests/fixtures/sha3_key_schedule.tsv

## Independent-provider interoperability

Create an isolated Python reference environment:

    python3 -m venv /tmp/pqc-rs-sha3-reference

    /tmp/pqc-rs-sha3-reference/bin/python -m pip install \
      -r crates/pqc-hpke/tests/interop/sha3-reference-requirements.txt

Build the Rust harness:

    cargo build --release --locked -p pqc-rs-hpke \
      --features experimental-hkdf-sha3 \
      --example sha3_provider_interop

Execute the independent reference:

    /tmp/pqc-rs-sha3-reference/bin/python \
      crates/pqc-hpke/tests/interop/sha3_openssl_reference.py \
      target/release/examples/sha3_provider_interop \
      /tmp/sha3-provider-interop.json

The campaign executes 256 bidirectional exchanges,
512 authenticated message recoveries and 768 expected
authentication rejections.

The harness uses synthetic test keys. It must not be
used with operational private keys or sensitive data.

The Python reference is not a PQC-rs runtime dependency.

## Performance characterization

    cargo build --release --locked -p pqc-rs-hpke \
      --features experimental-hkdf-sha3,internal-api \
      --example sha3_kdf_characterization

    mkdir -p /tmp/sha3-performance

    target/release/examples/sha3_kdf_characterization \
      > /tmp/sha3-performance/results.csv

    python3 \
      crates/pqc-hpke/tests/interop/analyze_sha3_performance.py \
      /tmp/sha3-performance

The benchmark characterizes:

1. Labeled HKDF Extract and Expand.
2. Complete Base-mode HPKE key schedule.
3. Sender setup, Seal, receiver setup and Open.

The complete HPKE campaign covers six KEM
constructions, two KDFs and AES-256-GCM.

Each configuration has 200 warm-up iterations and
10000 measured iterations. KDF execution order
alternates between paired trials.

Recipient key generation is excluded. Sender setup
includes fresh OS randomness.

Combined measurements are sums of separately timed
operations, not contiguous wall-clock intervals.

The benchmark excludes application serialization,
native ABI overhead, transport and network processing.

Absolute performance is platform- and build-dependent.

## Security boundaries

This is an experimental cryptographic capability.

The validation establishes functional correctness and
interoperability within the evaluated scope.

It does not establish formal security certification,
side-channel resistance, production readiness,
or compatibility with a future standardized KDF
identifier.

Within-context replay rejection does not establish
application-level replay protection across independent
HPKE contexts.
