//! SLH-DSA ACVP signature-verification models.

use serde::{Deserialize, Serialize};

use super::common::{
    AcvpEnvelope, AcvpParameterSet, AcvpTestType, PreHashMode, SignatureInterface, SlhDsaAcvpError,
};

/// ACVP mode name for signature verification.
pub const SIGVER_MODE: &str = "sigVer";

/// SLH-DSA SigVer prompt.
pub type SigVerPrompt = AcvpEnvelope<SigVerPromptGroup>;

/// SLH-DSA SigVer expected results.
pub type SigVerExpected = AcvpEnvelope<SigVerExpectedGroup>;

/// SLH-DSA SigVer internal projection.
pub type SigVerProjection = AcvpEnvelope<SigVerProjectionGroup>;

/// SigVer prompt group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigVerPromptGroup {
    /// Test-group identifier.
    pub tg_id: u64,

    /// Parameter set.
    pub parameter_set: AcvpParameterSet,

    /// Test type.
    pub test_type: AcvpTestType,

    /// Signature interface.
    pub signature_interface: SignatureInterface,

    /// Pure or prehash mode.
    #[serde(default)]
    pub pre_hash: Option<PreHashMode>,

    /// Prompt cases.
    #[serde(default)]
    pub tests: Vec<SigVerPromptCase>,
}

/// SigVer prompt test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigVerPromptCase {
    /// Test-case identifier.
    pub tc_id: u64,

    /// Public key.
    pub pk: String,

    /// Message.
    pub message: String,

    /// Signature.
    pub signature: String,

    /// Context.
    #[serde(default)]
    pub context: Option<String>,

    /// Prehash algorithm.
    #[serde(default)]
    pub hash_alg: Option<String>,
}

/// SigVer expected-results group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigVerExpectedGroup {
    /// Test-group identifier.
    pub tg_id: u64,

    /// Expected cases.
    #[serde(default)]
    pub tests: Vec<SigVerExpectedCase>,
}

/// SigVer expected test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigVerExpectedCase {
    /// Test-case identifier.
    pub tc_id: u64,

    /// Expected verification result.
    pub test_passed: bool,
}

/// SigVer internal-projection group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigVerProjectionGroup {
    /// Test-group identifier.
    pub tg_id: u64,

    /// Parameter set.
    pub parameter_set: AcvpParameterSet,

    /// Test type.
    pub test_type: AcvpTestType,

    /// Signature interface.
    pub signature_interface: SignatureInterface,

    /// Pure or prehash mode.
    #[serde(default)]
    pub pre_hash: Option<PreHashMode>,

    /// Projected cases.
    #[serde(default)]
    pub tests: Vec<SigVerProjectionCase>,
}

/// SigVer internal-projection test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigVerProjectionCase {
    /// Test-case identifier.
    pub tc_id: u64,

    /// Whether the result is deferred.
    pub deferred: bool,

    /// Private key retained by the projection.
    pub sk: String,

    /// Public key.
    pub pk: String,

    /// Message.
    pub message: String,

    /// Signature.
    pub signature: String,

    /// Context.
    #[serde(default)]
    pub context: Option<String>,

    /// Effective hash algorithm.
    pub hash_alg: String,

    /// Optional randomness retained by the projection.
    pub additional_randomness: String,

    /// Expected verification result.
    pub test_passed: bool,

    /// Human-readable mutation or failure reason.
    pub reason: String,
}

/// Parse a SigVer prompt.
pub fn parse_prompt(json: &str) -> Result<SigVerPrompt, SlhDsaAcvpError> {
    let prompt: SigVerPrompt = serde_json::from_str(json)?;
    prompt.validate_metadata(SIGVER_MODE)?;
    Ok(prompt)
}

/// Parse SigVer expected results.
pub fn parse_expected(json: &str) -> Result<SigVerExpected, SlhDsaAcvpError> {
    let expected: SigVerExpected = serde_json::from_str(json)?;
    expected.validate_metadata(SIGVER_MODE)?;
    Ok(expected)
}

/// Parse a SigVer internal projection.
pub fn parse_projection(json: &str) -> Result<SigVerProjection, SlhDsaAcvpError> {
    let projection: SigVerProjection = serde_json::from_str(json)?;
    projection.validate_metadata(SIGVER_MODE)?;
    Ok(projection)
}
