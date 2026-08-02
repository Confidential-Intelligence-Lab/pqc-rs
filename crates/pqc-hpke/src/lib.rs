#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Hybrid Public Key Encryption with post-quantum KEM integration.
//!
//! The crate provides RFC 9180 context and key-schedule machinery together
//! with revision-pinned ML-KEM and hybrid KEM integration. Deterministic
//! entry points remain available for test vectors and interoperability,
//! while RNG-backed entry points support ordinary application use.
//!
//! # Application-facing API
//!
//! The principal Base-mode types and setup functions are re-exported from
//! the crate root. Applications can generate an ML-KEM recipient key pair,
//! select a validated [`HpkeSuite`], create sender and receiver contexts,
//! and then use [`SenderContext::seal`] and [`ReceiverContext::open`].
//!
//! RNG-backed entry points are intended for ordinary application use.
//! Deterministic entry points remain available for test vectors and
//! interoperability validation.
//!
//! # Reference application
//!
//! The crate includes an executable HPKE secure-messaging application:
//!
//! ```text
//! crates/pqc-hpke/examples/03_hpke_secure_messaging.rs
//! ```
//!
//! Run it from the workspace root:
//!
//! ```text
//! cargo run -p pqc-rs-hpke --example 03_hpke_secure_messaging --all-features
//! ```
//!
//! The application demonstrates randomized Base-mode setup, ordered
//! authenticated messaging, associated-data binding, ciphertext-tamper
//! rejection, and receiver-state preservation after failed authentication.
//!
//!
//! ## Cryptographic agility
//!
//! The crate also includes a policy-driven agility example:
//!
//! ```text
//! crates/pqc-hpke/examples/04_hpke_crypto_agility.rs
//! ```
//!
//! It selects the KEM, KDF, and AEAD through configuration while reusing
//! one unchanged sender and receiver workflow. Both protocol roles execute
//! locally; future examples will introduce separate processes and explicit
//! transport serialization.
//!
pub mod aead;
pub mod context;
pub mod error;
pub mod hybrid_kem;
pub mod hybrid_setup;
pub mod identifiers;
pub mod kdf;
pub mod key_schedule;
pub mod ml_kem;
pub mod setup;
pub mod suite;

pub use context::{ReceiverContext, SenderContext};
pub use error::HpkeError;
pub use identifiers::{AeadId, HpkeSuiteId, KdfId, KemId};
pub use ml_kem::{MlKemHpke, MlKemHpkeEncapsulation, MlKemHpkeError, MlKemHpkeKeyPair};
pub use setup::{
    setup_base_receiver_with_suite, setup_base_sender_with_suite,
    setup_base_sender_with_suite_deterministic, BaseSenderSetup, SenderSetup,
};
pub use suite::{supported_aeads, supported_kdfs, HpkeSuite};
