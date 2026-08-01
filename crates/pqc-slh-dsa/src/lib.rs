#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! FIPS 205 SLH-DSA implementation crate.
//!
//! The current stage establishes the approved parameter sets and the
//! publication-facing typed object model. Cryptographic key generation,
//! signing, and verification are introduced in subsequent stages.

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
