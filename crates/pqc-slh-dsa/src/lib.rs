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

pub mod api;
pub mod error;
pub mod params;

pub use api::{
    SlhDsa, SlhDsaKeyGenSeed, SlhDsaKeyPair, SlhDsaPrivateKey, SlhDsaPublicKey, SlhDsaSignature,
};
pub use error::SlhDsaError;
pub use params::{SlhDsaHashFamily, SlhDsaParameterSet, SlhDsaParameters};
