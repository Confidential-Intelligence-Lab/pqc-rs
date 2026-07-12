#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Shared traits, typed buffers, errors, and validation utilities for the
//! `pqc-rfc9958-rs` workspace.

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod bytes;
pub mod codec;
pub mod error;
pub mod kem;
pub mod signature;

pub use bytes::{
    CiphertextBytes, ContextBytes, PublicKeyBytes, SecretKeyBytes, SharedSecretBytes,
    SignatureBytes,
};
pub use codec::Decode;
#[cfg(feature = "alloc")]
pub use codec::Encode;
pub use error::{PqcError, PqcResult};
pub use kem::Kem;
pub use signature::SignatureScheme;
pub mod secret;
