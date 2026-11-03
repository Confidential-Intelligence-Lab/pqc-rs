//! Experimental native Rust implementation of HAETAE 1.2.0.
//!
//! This crate is under development and must not be used for
//! production cryptographic operations.

//! The `internal-api` feature exposes unstable implementation
//! interfaces for reference-parity testing and fuzzing.
//! These interfaces are not part of the supported public API.

#![forbid(unsafe_code)]

pub mod api;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod packing;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod packing;
pub mod params;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod signing_init;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod signing_init;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod arithmetic;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod arithmetic;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod decompose;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod decompose;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod montgomery;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod montgomery;
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
pub mod polymat;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod polymat;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod polyvec;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod polyvec;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod sampling;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod sampling;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod fixed_fft;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod fixed_fft;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod keygen_arithmetic;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod keygen_arithmetic;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod keygen_loop;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod keygen_loop;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod keygen_prepare;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod keygen_prepare;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod keygen_rejection;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod keygen_rejection;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod keygen_seed;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod keygen_seed;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod singular_value;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod singular_value;

#[allow(dead_code)]
mod gaussian;
#[allow(dead_code)]
mod hyperball_fixed;

#[allow(dead_code)]
mod hyperball;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod challenge;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod challenge;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod rans;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod rans;
#[cfg(test)]
mod rans_reference_parity;
#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod signature_packing;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod signature_packing;

#[allow(dead_code)]
mod signing_challenge_prepare;
#[allow(dead_code)]
mod signing_response;

#[cfg(test)]
mod signing_retry_cursor;

#[allow(dead_code)]
mod signing;
#[allow(dead_code)]
mod signing_signature_assembly;

#[cfg(feature = "internal-api")]
#[doc(hidden)]
pub mod verification;
#[cfg(not(feature = "internal-api"))]
#[allow(dead_code)]
mod verification;
