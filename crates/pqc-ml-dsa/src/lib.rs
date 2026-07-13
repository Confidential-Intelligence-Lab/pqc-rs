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
pub mod constants;
pub mod ntt;
pub mod poly;
pub mod reduce;
pub mod sample;
pub mod xof;
