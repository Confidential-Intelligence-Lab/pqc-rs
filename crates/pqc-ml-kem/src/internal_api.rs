//! Unstable ML-KEM engineering and assurance API.
//!
//! This module exists for repository assurance tooling, conformance tests,
//! profiling, and validation infrastructure. It is available only with the
//! `internal-api` feature and is explicitly excluded from the crate's SemVer
//! compatibility commitment.

pub use crate::arithmetic::reduce;
pub use crate::conformance::{
    component_status, parameter_set_status, ComponentStatus, ConformanceLevel, ParameterSetStatus,
    COMPONENT_STATUS,
};

#[cfg(feature = "std")]
pub use crate::ml_kem_trace::{
    trace_ml_kem_1024_keygen, trace_ml_kem_512_keygen, trace_ml_kem_768_keygen, MlKemKeygenTrace,
};

/// FIPS 203 `H` helper used by assurance tooling.
pub fn h(input: &[u8]) -> [u8; 32] {
    crate::symmetric::h(input)
}
