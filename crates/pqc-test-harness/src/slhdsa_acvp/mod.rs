//! Reusable models and parsers for NIST ACVP FIPS 205 SLH-DSA vectors.

use serde::de::DeserializeOwned;
use std::path::Path;

pub mod common;
pub mod keygen;
pub mod registration;
pub mod siggen;
pub mod sigver;
pub mod validation;

pub use common::{
    AcvpEnvelope, AcvpParameterSet, AcvpTestType, PreHashMode, SignatureInterface, SlhDsaAcvpError,
};

/// Load and decode an ACVP JSON document from disk.
pub fn load_json<T>(path: impl AsRef<Path>) -> Result<T, SlhDsaAcvpError>
where
    T: DeserializeOwned,
{
    let json = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&json)?)
}

/// Serialize an ACVP document using compact JSON.
pub fn to_json<T>(value: &T) -> Result<String, SlhDsaAcvpError>
where
    T: serde::Serialize,
{
    Ok(serde_json::to_string(value)?)
}
