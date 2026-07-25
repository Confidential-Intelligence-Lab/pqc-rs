#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! FIPS 204 ML-DSA implementation crate.
//!
//! This initial public contract requires the Rust standard library. The crate
//! does not currently advertise allocation-only or `no_std` support.

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
pub mod audit;
pub mod challenge;
pub mod constants;
pub mod encoding;
pub mod expand_a;
pub mod hash_mldsa;
pub mod hint;
pub mod keygen;
pub mod ntt;
pub mod poly;
pub mod reduce;
pub mod rounding;
pub mod sample;
pub mod signature;
pub mod signing;
pub mod signing_core;
pub mod verification;
pub mod xof;
