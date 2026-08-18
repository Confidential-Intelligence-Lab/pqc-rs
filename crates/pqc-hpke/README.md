# pqc-rs-hpke

`pqc-rs-hpke` is part of the **PQC-rs cryptographic foundation** and provides
the HPKE implementation used by PQC-Forge secure-channel activation.

It provides Hybrid Public Key Encryption context and key-schedule machinery
based on RFC 9180, together with revision-pinned post-quantum and hybrid KEM
integration.

## Current scope

The crate provides:

- Base-mode and PSK-mode sender and receiver setup;
- ML-KEM-512, ML-KEM-768, and ML-KEM-1024 integration;
- validated HPKE ciphersuite selection;
- AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305;
- HKDF-SHA-256, HKDF-SHA-384, and HKDF-SHA-512;
- stateful sender and receiver contexts;
- exporter support;
- deterministic entry points for test vectors and interoperability;
- RNG-backed key generation and Base-mode sender setup for application use.

## Basic API

The primary application-facing API is available from the crate root:

```text
use pqc_hpke::{
    setup_base_receiver_with_suite, setup_base_sender_with_suite, AeadId,
    HpkeSuite, KdfId, MlKemHpke,
};
use rand_core::OsRng;

let kem = MlKemHpke::MlKem768;
let suite = HpkeSuite::new(
    kem,
    KdfId::HKDF_SHA256,
    AeadId::CHACHA20_POLY1305,
)?;

let recipient = kem.generate_key_pair(&mut OsRng)?;

let sender = setup_base_sender_with_suite(
    kem,
    suite,
    &recipient.public_key,
    b"application context",
    &mut OsRng,
)?;

let receiver = setup_base_receiver_with_suite(
    kem,
    suite,
    recipient.private_key_seed.as_bytes(),
    &sender.encapsulated_key,
    b"application context",
)?;
```

The deterministic setup APIs remain available for reproducible vectors,
interoperability testing, and protocol validation.

## Reference applications

The crate includes an executable HPKE secure-messaging application:

```text
examples/03_hpke_secure_messaging.rs
```

Run it from the workspace root:

```bash
cargo run -p pqc-rs-hpke --example 03_hpke_secure_messaging --all-features
```

The application demonstrates ML-KEM-768 recipient key generation, validated
HPKE ciphersuite selection, randomized Base-mode sender setup, stateful
authenticated messaging, associated-data binding, modified-ciphertext
rejection, and preservation of receiver state after failed authentication.

### Cryptographic agility

The agility application keeps the messaging workflow unchanged while a
policy selects the KEM, KDF, and AEAD:

```text
examples/04_hpke_crypto_agility.rs
```

Run it from the workspace root:

```bash
cargo run -p pqc-rs-hpke --example 04_hpke_crypto_agility --all-features
```

It exercises compact, balanced, and high-security policies using ML-KEM-512,
ML-KEM-768, and ML-KEM-1024 respectively. The same sender and receiver
application logic is reused for every policy.

Both HPKE applications currently execute sender and receiver roles within
one process and use in-memory values instead of network transport. Future
versions will separate those roles into independently executable clients
and servers with explicit serialization and framing.

## Status

This is a pre-1.0 cryptographic library. Review the repository security policy,
standards traceability, release audits, and interoperability evidence before
production deployment.

## License

Licensed under the MIT License.
