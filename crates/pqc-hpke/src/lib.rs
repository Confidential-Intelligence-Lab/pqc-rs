#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! HPKE integration hooks for post-quantum KEMs.

/// Placeholder type for compile validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpkePlaceholder;
pub mod error;
pub mod identifiers;
pub mod kdf;
pub mod key_schedule;

pub use error::HpkeError;
pub mod aead;
pub mod context;
pub mod hybrid_kem;
pub mod hybrid_setup;
pub mod ml_kem;
pub mod setup;
