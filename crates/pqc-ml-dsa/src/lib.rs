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

mod audit;
mod challenge;
mod constants;
mod encoding;
mod expand_a;
mod hash_mldsa;
mod hint;
/// Unstable engineering and assurance API.
///
/// This surface is feature-gated and excluded from the crate's SemVer
/// compatibility commitment.
#[cfg(feature = "internal-api")]
pub mod internal_api;
mod keygen;
mod ntt;
mod poly;
mod reduce;
mod rounding;
mod sample;
mod signature;
mod signing;
mod signing_core;
mod verification;
mod xof;
