//! SLH-DSA ACVP signature-generation models.

use serde::{Deserialize, Serialize};

use super::common::{
    AcvpEnvelope, AcvpParameterSet, AcvpTestType, PreHashMode, SignatureInterface, SlhDsaAcvpError,
};

/// ACVP mode name for signature generation.
pub const SIGGEN_MODE: &str = "sigGen";

/// SLH-DSA SigGen prompt.
pub type SigGenPrompt = AcvpEnvelope<SigGenPromptGroup>;

/// SLH-DSA SigGen expected results.
pub type SigGenExpected = AcvpEnvelope<SigGenExpectedGroup>;

/// SLH-DSA SigGen internal projection.
pub type SigGenProjection = AcvpEnvelope<SigGenProjectionGroup>;

/// SigGen prompt group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigGenPromptGroup {
    /// Test-group identifier.
    pub tg_id: u64,

    /// Parameter set.
    pub parameter_set: AcvpParameterSet,

    /// Test type.
    pub test_type: AcvpTestType,

    /// Whether signatures are deterministic.
    pub deterministic: bool,

    /// Signature interface.
    pub signature_interface: SignatureInterface,

    /// Pure or prehash mode for the external interface.
    #[serde(default)]
    pub pre_hash: Option<PreHashMode>,

    /// Prompt test cases.
    #[serde(default)]
    pub tests: Vec<SigGenPromptCase>,
}

/// SigGen prompt test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigGenPromptCase {
    /// Test-case identifier.
    pub tc_id: u64,

    /// Encoded private key.
    pub sk: String,

    /// Message, encoded as hexadecimal.
    pub message: String,

    /// Context, encoded as hexadecimal.
    #[serde(default)]
    pub context: Option<String>,

    /// Prehash algorithm.
    #[serde(default)]
    pub hash_alg: Option<String>,

    /// Optional randomness for non-deterministic signing.
    #[serde(default)]
    pub additional_randomness: Option<String>,
}

/// SigGen expected-results group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigGenExpectedGroup {
    /// Test-group identifier.
    pub tg_id: u64,

    /// Expected cases.
    #[serde(default)]
    pub tests: Vec<SigGenExpectedCase>,
}

/// SigGen expected test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigGenExpectedCase {
    /// Test-case identifier.
    pub tc_id: u64,

    /// Expected signature.
    pub signature: String,
}

/// SigGen internal-projection group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigGenProjectionGroup {
    /// Test-group identifier.
    pub tg_id: u64,

    /// Parameter set.
    pub parameter_set: AcvpParameterSet,

    /// Test type.
    pub test_type: AcvpTestType,

    /// Whether signatures are deterministic.
    pub deterministic: bool,

    /// Signature interface.
    pub signature_interface: SignatureInterface,

    /// Pure or prehash mode.
    #[serde(default)]
    pub pre_hash: Option<PreHashMode>,

    /// Projected cases.
    #[serde(default)]
    pub tests: Vec<SigGenProjectionCase>,
}

/// SigGen internal-projection test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigGenProjectionCase {
    /// Test-case identifier.
    pub tc_id: u64,

    /// Whether the result is deferred.
    pub deferred: bool,

    /// Private key.
    pub sk: String,

    /// Public key.
    pub pk: String,

    /// Message.
    pub message: String,

    /// Context.
    #[serde(default)]
    pub context: Option<String>,

    /// Effective hash algorithm or pure-mode marker.
    pub hash_alg: String,

    /// Optional signing randomness.
    #[serde(default)]
    pub additional_randomness: Option<String>,

    /// Generated signature.
    pub signature: String,
}

/// Parse a SigGen prompt.
pub fn parse_prompt(json: &str) -> Result<SigGenPrompt, SlhDsaAcvpError> {
    let prompt: SigGenPrompt = serde_json::from_str(json)?;
    prompt.validate_metadata(SIGGEN_MODE)?;
    Ok(prompt)
}

/// Parse SigGen expected results.
pub fn parse_expected(json: &str) -> Result<SigGenExpected, SlhDsaAcvpError> {
    let expected: SigGenExpected = serde_json::from_str(json)?;
    expected.validate_metadata(SIGGEN_MODE)?;
    Ok(expected)
}

/// Parse a SigGen internal projection.
pub fn parse_projection(json: &str) -> Result<SigGenProjection, SlhDsaAcvpError> {
    let projection: SigGenProjection = serde_json::from_str(json)?;
    projection.validate_metadata(SIGGEN_MODE)?;
    Ok(projection)
}
