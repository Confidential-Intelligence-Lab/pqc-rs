//! SLH-DSA ACVP key-generation models.

use serde::{Deserialize, Serialize};

use super::common::{AcvpEnvelope, AcvpParameterSet, AcvpTestType, SlhDsaAcvpError};

/// ACVP mode name for SLH-DSA key generation.
pub const KEYGEN_MODE: &str = "keyGen";

/// SLH-DSA KeyGen prompt.
pub type KeyGenPrompt = AcvpEnvelope<KeyGenPromptGroup>;

/// SLH-DSA KeyGen expected results.
pub type KeyGenExpected = AcvpEnvelope<KeyGenExpectedGroup>;

/// SLH-DSA KeyGen internal projection.
pub type KeyGenProjection = AcvpEnvelope<KeyGenProjectionGroup>;

/// KeyGen prompt group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenPromptGroup {
    /// Test-group identifier.
    pub tg_id: u64,

    /// Parameter set.
    pub parameter_set: AcvpParameterSet,

    /// Test type.
    pub test_type: AcvpTestType,

    /// Prompt test cases.
    #[serde(default)]
    pub tests: Vec<KeyGenPromptCase>,
}

/// KeyGen prompt test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenPromptCase {
    /// Test-case identifier.
    pub tc_id: u64,

    /// Secret seed, encoded as hexadecimal.
    pub sk_seed: String,

    /// Secret PRF seed, encoded as hexadecimal.
    pub sk_prf: String,

    /// Public seed, encoded as hexadecimal.
    pub pk_seed: String,
}

/// KeyGen expected-results group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenExpectedGroup {
    /// Test-group identifier.
    pub tg_id: u64,

    /// Expected test cases.
    #[serde(default)]
    pub tests: Vec<KeyGenExpectedCase>,
}

/// KeyGen expected test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenExpectedCase {
    /// Test-case identifier.
    pub tc_id: u64,

    /// Expected public key, encoded as hexadecimal.
    pub pk: String,

    /// Expected private key, encoded as hexadecimal.
    pub sk: String,
}

/// KeyGen internal-projection group.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenProjectionGroup {
    /// Test-group identifier.
    pub tg_id: u64,

    /// Parameter set.
    pub parameter_set: AcvpParameterSet,

    /// Test type.
    pub test_type: AcvpTestType,

    /// Projected test cases.
    #[serde(default)]
    pub tests: Vec<KeyGenProjectionCase>,
}

/// KeyGen internal-projection test case.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenProjectionCase {
    /// Test-case identifier.
    pub tc_id: u64,

    /// Whether the result is deferred.
    pub deferred: bool,

    /// Secret seed.
    pub sk_seed: String,

    /// Secret PRF seed.
    pub sk_prf: String,

    /// Public seed.
    pub pk_seed: String,

    /// Generated public key.
    pub pk: String,

    /// Generated private key.
    pub sk: String,
}

/// Parse a KeyGen prompt.
pub fn parse_prompt(json: &str) -> Result<KeyGenPrompt, SlhDsaAcvpError> {
    let prompt: KeyGenPrompt = serde_json::from_str(json)?;
    prompt.validate_metadata(KEYGEN_MODE)?;
    Ok(prompt)
}

/// Parse KeyGen expected results.
pub fn parse_expected(json: &str) -> Result<KeyGenExpected, SlhDsaAcvpError> {
    let expected: KeyGenExpected = serde_json::from_str(json)?;
    expected.validate_metadata(KEYGEN_MODE)?;
    Ok(expected)
}

/// Parse a KeyGen internal projection.
pub fn parse_projection(json: &str) -> Result<KeyGenProjection, SlhDsaAcvpError> {
    let projection: KeyGenProjection = serde_json::from_str(json)?;
    projection.validate_metadata(KEYGEN_MODE)?;
    Ok(projection)
}
