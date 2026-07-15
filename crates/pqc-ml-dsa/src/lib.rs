#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! ML-DSA implementation crate.

/// Placeholder type for compile validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlDsaPlaceholder;
pub mod api;
pub mod error;
pub mod params;
pub use api::MlDsa;
pub use error::MlDsaError;
pub use params::{MlDsaParameterSet, MlDsaParameters};
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
