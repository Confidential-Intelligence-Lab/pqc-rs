#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! FIPS 204 ML-DSA implementation crate.
//!
//! This initial public contract requires the Rust standard library. The crate
//! does not currently advertise allocation-only or `no_std` support.
//!
//! # Reference application
//!
//! The crate includes an executable ML-DSA document-signing application:
//!
//! ```text
//! crates/pqc-ml-dsa/examples/02_mldsa_document_signing.rs
//! ```
//!
//! Run it from the workspace root:
//!
//! ```text
//! cargo run -p pqc-rs-ml-dsa --example 02_mldsa_document_signing --all-features
//! ```
//!
//! The application demonstrates ML-DSA-65 key generation, hedged Pure ML-DSA
//! signing, context-bound verification, modified-document rejection, and
//! modified-signature rejection.
//!
pub mod api;
pub mod error;
pub mod params;
pub use api::{
    MlDsa, MlDsaKeyGenSeed, MlDsaKeyPair, MlDsaPrivateKey, MlDsaPublicKey, MlDsaSignature,
    ML_DSA_KEYGEN_SEED_BYTES,
};
pub use error::MlDsaError;
pub use hash_mldsa::PreHashAlgorithm;
pub use params::{MlDsaParameterSet, MlDsaParameters};
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod audit;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod audit;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod challenge;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod challenge;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod constants;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod constants;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod encoding;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod encoding;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod expand_a;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod expand_a;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod hash_mldsa;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod hash_mldsa;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod hint;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod hint;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod keygen;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod keygen;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod ntt;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod ntt;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod poly;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod poly;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod reduce;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod reduce;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod rounding;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod rounding;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod sample;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod sample;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod signature;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod signature;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod signing;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod signing;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod signing_core;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod signing_core;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod verification;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod verification;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod xof;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod xof;
