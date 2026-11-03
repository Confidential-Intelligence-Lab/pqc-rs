//! Experimental native Rust implementation of HAETAE 1.2.0.
//!
//! This crate is under development and must not be used for
//! production cryptographic operations.

#![forbid(unsafe_code)]

pub mod api;
pub mod packing;
pub mod params;
pub mod signing_init;

pub mod arithmetic;
pub mod decompose;
pub mod montgomery;
pub mod ntt;
pub mod poly;
pub mod polymat;
pub mod polyvec;

pub mod sampling;

pub mod fixed_fft;
pub mod keygen_arithmetic;
pub mod keygen_loop;
pub mod keygen_prepare;
pub mod keygen_rejection;
pub mod keygen_seed;
pub mod singular_value;

#[allow(dead_code)]
mod gaussian;
#[allow(dead_code)]
mod hyperball_fixed;

#[allow(dead_code)]
mod hyperball;

pub mod challenge;
pub mod rans;
#[cfg(test)]
mod rans_reference_parity;
pub mod signature_packing;

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

pub mod verification;
