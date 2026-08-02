//! Common types used by the SLH-DSA ACVP data model.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Algorithm identifier used by the FIPS 205 ACVP vectors.
pub const SLH_DSA_ALGORITHM: &str = "SLH-DSA";

/// Revision identifier used by the FIPS 205 ACVP vectors.
pub const FIPS_205_REVISION: &str = "FIPS205";

/// Generic ACVP vector-set envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcvpEnvelope<TGroup> {
    /// ACVP vector-set identifier.
    pub vs_id: u64,

    /// Algorithm identifier.
    pub algorithm: String,

    /// Operation mode, such as `keyGen`, `sigGen`, or `sigVer`.
    pub mode: String,

    /// Algorithm revision.
    pub revision: String,

    /// Whether this is a sample vector set.
    #[serde(default)]
    pub is_sample: bool,

    /// Operation-specific test groups.
    pub test_groups: Vec<TGroup>,
}

impl<TGroup> AcvpEnvelope<TGroup> {
    /// Validate the common FIPS 205 envelope metadata.
    pub fn validate_metadata(&self, expected_mode: &'static str) -> Result<(), SlhDsaAcvpError> {
        if self.algorithm != SLH_DSA_ALGORITHM {
            return Err(SlhDsaAcvpError::MetadataMismatch {
                field: "algorithm",
                expected: SLH_DSA_ALGORITHM,
                actual: self.algorithm.clone(),
            });
        }

        if self.revision != FIPS_205_REVISION {
            return Err(SlhDsaAcvpError::MetadataMismatch {
                field: "revision",
                expected: FIPS_205_REVISION,
                actual: self.revision.clone(),
            });
        }

        if self.mode != expected_mode {
            return Err(SlhDsaAcvpError::MetadataMismatch {
                field: "mode",
                expected: expected_mode,
                actual: self.mode.clone(),
            });
        }

        Ok(())
    }
}

/// Supported SLH-DSA ACVP parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AcvpParameterSet {
    /// SLH-DSA-SHA2-128s.
    #[serde(rename = "SLH-DSA-SHA2-128s")]
    Sha2_128s,

    /// SLH-DSA-SHA2-128f.
    #[serde(rename = "SLH-DSA-SHA2-128f")]
    Sha2_128f,

    /// SLH-DSA-SHA2-192s.
    #[serde(rename = "SLH-DSA-SHA2-192s")]
    Sha2_192s,

    /// SLH-DSA-SHA2-192f.
    #[serde(rename = "SLH-DSA-SHA2-192f")]
    Sha2_192f,

    /// SLH-DSA-SHA2-256s.
    #[serde(rename = "SLH-DSA-SHA2-256s")]
    Sha2_256s,

    /// SLH-DSA-SHA2-256f.
    #[serde(rename = "SLH-DSA-SHA2-256f")]
    Sha2_256f,

    /// SLH-DSA-SHAKE-128s.
    #[serde(rename = "SLH-DSA-SHAKE-128s")]
    Shake128s,

    /// SLH-DSA-SHAKE-128f.
    #[serde(rename = "SLH-DSA-SHAKE-128f")]
    Shake128f,

    /// SLH-DSA-SHAKE-192s.
    #[serde(rename = "SLH-DSA-SHAKE-192s")]
    Shake192s,

    /// SLH-DSA-SHAKE-192f.
    #[serde(rename = "SLH-DSA-SHAKE-192f")]
    Shake192f,

    /// SLH-DSA-SHAKE-256s.
    #[serde(rename = "SLH-DSA-SHAKE-256s")]
    Shake256s,

    /// SLH-DSA-SHAKE-256f.
    #[serde(rename = "SLH-DSA-SHAKE-256f")]
    Shake256f,
}

/// ACVP test type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AcvpTestType {
    /// Algorithm functional test.
    #[serde(rename = "AFT")]
    Aft,
}

/// SLH-DSA signature interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignatureInterface {
    /// External FIPS 205 interface.
    External,

    /// Internal FIPS 205 interface.
    Internal,
}

/// External signature mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreHashMode {
    /// Pure SLH-DSA through the external interface.
    #[serde(rename = "pure")]
    Pure,

    /// HashSLH-DSA through the external interface.
    #[serde(rename = "preHash")]
    PreHash,

    /// Internal-interface mode with no external prehash selection.
    #[serde(rename = "none")]
    None,
}

/// Error produced while loading or validating SLH-DSA ACVP data.
#[derive(Debug)]
pub enum SlhDsaAcvpError {
    /// File-system error.
    Io(std::io::Error),

    /// JSON decoding error.
    Json(serde_json::Error),

    /// Common envelope metadata did not match the expected value.
    MetadataMismatch {
        /// Metadata field.
        field: &'static str,

        /// Expected value.
        expected: &'static str,

        /// Parsed value.
        actual: String,
    },
}

impl fmt::Display for SlhDsaAcvpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "SLH-DSA ACVP I/O error: {error}"),
            Self::Json(error) => {
                write!(formatter, "SLH-DSA ACVP JSON error: {error}")
            }
            Self::MetadataMismatch {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "SLH-DSA ACVP metadata mismatch for {field}: \
                 expected {expected}, found {actual}"
            ),
        }
    }
}

impl std::error::Error for SlhDsaAcvpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::MetadataMismatch { .. } => None,
        }
    }
}

impl From<std::io::Error> for SlhDsaAcvpError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for SlhDsaAcvpError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
