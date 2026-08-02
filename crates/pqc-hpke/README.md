# pqc-rs-hpke

`pqc-rs-hpke` provides Hybrid Public Key Encryption context and key-schedule
machinery based on RFC 9180, together with revision-pinned post-quantum and
hybrid KEM integration.

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

## Status

This is a pre-1.0 cryptographic library. Review the repository security policy,
standards traceability, release audits, and interoperability evidence before
production deployment.

## License

Licensed under the MIT License.
