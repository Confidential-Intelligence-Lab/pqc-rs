#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! NIST FIPS 205 SLH-DSA implementation.
//!
//! This crate implements all twelve standardized SLH-DSA parameter sets,
//! including the SHA-2 and SHAKE families at security categories 1, 3, and 5.
//!
//! The application-facing API provides:
//!
//! - cryptographic key generation;
//! - deterministic key generation from a parameter-bound seed;
//! - deterministic Pure SLH-DSA signing;
//! - hedged Pure SLH-DSA signing;
//! - Pure SLH-DSA signature verification;
//! - typed key, seed, and signature import and export.
//!
//! # Parameter binding
//!
//! Keys, signatures, and key-generation seeds are bound to a specific
//! [`SlhDsaParameterSet`]. Operations reject objects created for a different
//! parameter set.
//!
//! # Validation-only interfaces
//!
//! The `internal-api` feature exposes low-level implementation and
//! conformance-testing interfaces. It is unstable and is not part of the
//! supported application-facing API.
//!
//! # Assurance boundary
//!
//! Agreement with NIST ACVP sample vectors is implementation-validation
//! evidence. It is not CMVP validation, FIPS 140 validation, certification,
//! or an independent security audit.

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod address;

#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod address;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod conversion;

#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod conversion;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod hash;

#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod hash;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod hash_suite;

#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod hash_suite;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod fors;

#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod fors;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod message_digest;

#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod message_digest;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod wots;

#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod wots;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod xmss;

#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod xmss;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod hypertree;

#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod hypertree;

pub mod api;
pub mod error;
pub mod params;

pub use api::{
    SlhDsa, SlhDsaKeyGenSeed, SlhDsaKeyPair, SlhDsaPrivateKey, SlhDsaPublicKey, SlhDsaSignature,
};
pub use error::SlhDsaError;
pub use params::{SlhDsaHashFamily, SlhDsaParameterSet, SlhDsaParameters};
