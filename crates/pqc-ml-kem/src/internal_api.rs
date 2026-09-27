//! Unstable ML-KEM engineering and assurance API.
//!
//! This module exists for repository assurance tooling, conformance tests,
//! profiling, and validation infrastructure. It is available only with the
//! `internal-api` feature and is explicitly excluded from the crate's SemVer
//! compatibility commitment.

pub use crate::arithmetic::{reduce, N, Q};
pub use crate::conformance::{
    component_status, parameter_set_status, ComponentStatus, ConformanceLevel, ParameterSetStatus,
    COMPONENT_STATUS,
};
pub use crate::matrix::{expand_matrix, PolyMatrix};
pub use crate::poly::Poly;

#[cfg(feature = "std")]
pub use crate::ml_kem_trace::{
    trace_ml_kem_1024_keygen, trace_ml_kem_512_keygen, trace_ml_kem_768_keygen, MlKemKeygenTrace,
};

/// FIPS 203 `H` helper used by assurance tooling.
pub fn h(input: &[u8]) -> [u8; 32] {
    crate::symmetric::h(input)
}

/// FIPS-domain NTT representation used by diagnostic and profiling paths.
pub use crate::fips_ntt::FipsNttPoly;

/// Diagnostic bounded-arithmetic NTT variants.
///
/// These routines exist for optimization, differential testing, and assurance
/// work. They are not part of the stable application-facing ML-KEM API.
pub use crate::fips_ntt::{
    basemul_bounded, basemul_polynomials_bounded, invntt_tomont_bounded_montgomery,
    ntt_bounded_montgomery,
};

#[cfg(feature = "std")]
pub use crate::fips_ntt::{invntt_tomont_bounded, ntt_bounded};
