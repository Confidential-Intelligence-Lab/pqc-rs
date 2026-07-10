#![allow(clippy::module_name_repetitions)]
//! NIST ACVP ML-KEM vector parsing and provenance.
//!
//! This module parses the FIPS 203 ML-KEM key-generation schema published by
//! NIST's ACVP-Server repository. Parsing a vector does not imply that the
//! implementation has passed it.

use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Pinned upstream source metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcvpSource {
    /// Upstream repository.
    pub repository: &'static str,
    /// Pinned tag or commit.
    pub revision: &'static str,
    /// Relative path to the key-generation prompt.
    pub keygen_prompt_path: &'static str,
    /// Relative path to the key-generation expected results.
    pub keygen_expected_path: &'static str,
    /// Relative path to the encapsulation/decapsulation prompt.
    pub encap_decap_prompt_path: &'static str,
    /// Relative path to the encapsulation/decapsulation expected results.
    pub encap_decap_expected_path: &'static str,
}

/// NIST ACVP-Server source pinned by Stage 5B-16.
pub const NIST_ACVP_SOURCE: AcvpSource = AcvpSource {
    repository: "https://github.com/usnistgov/ACVP-Server.git",
    revision: "RELEASE/v1.1.0.42",
    keygen_prompt_path: "gen-val/json-files/ML-KEM-keyGen-FIPS203/prompt.json",
    keygen_expected_path: "gen-val/json-files/ML-KEM-keyGen-FIPS203/expectedResults.json",
    encap_decap_prompt_path: "gen-val/json-files/ML-KEM-encapDecap-FIPS203/prompt.json",
    encap_decap_expected_path: "gen-val/json-files/ML-KEM-encapDecap-FIPS203/expectedResults.json",
};

/// Parsed ML-KEM key-generation prompt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MlKemKeygenPrompt {
    /// ACVP vector-set identifier.
    pub vs_id: u64,
    /// Algorithm name.
    pub algorithm: String,
    /// Algorithm mode.
    pub mode: String,
    /// Revision string.
    pub revision: String,
    /// Whether the set is a sample.
    #[serde(default)]
    pub is_sample: bool,
    /// Test groups.
    pub test_groups: Vec<MlKemKeygenPromptGroup>,
}

/// One ML-KEM key-generation prompt group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MlKemKeygenPromptGroup {
    /// Test-group identifier.
    pub tg_id: u64,
    /// Test type, usually `AFT`.
    pub test_type: String,
    /// Parameter-set name.
    pub parameter_set: String,
    /// Test cases.
    pub tests: Vec<MlKemKeygenPromptCase>,
}

/// One ML-KEM key-generation prompt case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MlKemKeygenPromptCase {
    /// Test-case identifier.
    pub tc_id: u64,
    /// 32-byte implicit-rejection value, encoded as hex.
    pub z: String,
    /// 32-byte key-generation randomness, encoded as hex.
    pub d: String,
}

/// Parsed ML-KEM key-generation expected results.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MlKemKeygenExpected {
    /// ACVP vector-set identifier.
    pub vs_id: u64,
    /// Algorithm name.
    pub algorithm: String,
    /// Algorithm mode.
    pub mode: String,
    /// Revision string.
    pub revision: String,
    /// Test groups.
    pub test_groups: Vec<MlKemKeygenExpectedGroup>,
}

/// One ML-KEM key-generation expected-results group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MlKemKeygenExpectedGroup {
    /// Test-group identifier.
    pub tg_id: u64,
    /// Test cases.
    pub tests: Vec<MlKemKeygenExpectedCase>,
}

/// One ML-KEM key-generation expected result.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MlKemKeygenExpectedCase {
    /// Test-case identifier.
    pub tc_id: u64,
    /// Encapsulation key, encoded as hex.
    pub ek: String,
    /// Decapsulation key, encoded as hex.
    pub dk: String,
}

/// Joined key-generation case with prompt and expected outputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlKemKeygenCase {
    /// Parameter-set name.
    pub parameter_set: String,
    /// Test-group identifier.
    pub tg_id: u64,
    /// Test-case identifier.
    pub tc_id: u64,
    /// Decoded `z`.
    pub z: Vec<u8>,
    /// Decoded `d`.
    pub d: Vec<u8>,
    /// Decoded encapsulation key.
    pub ek: Vec<u8>,
    /// Decoded decapsulation key.
    pub dk: Vec<u8>,
}

/// ACVP parsing or joining error.
#[derive(Debug)]
pub enum AcvpError {
    /// File-system failure.
    Io(std::io::Error),
    /// JSON parsing failure.
    Json(serde_json::Error),
    /// Hex decoding failure.
    Hex(hex::FromHexError),
    /// Prompt and expected metadata do not agree.
    MetadataMismatch(&'static str),
    /// A prompt case has no matching expected result.
    MissingExpectedCase {
        /// Test-group identifier.
        tg_id: u64,
        /// Test-case identifier.
        tc_id: u64,
    },
}

impl core::fmt::Display for AcvpError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::Hex(error) => write!(formatter, "hex error: {error}"),
            Self::MetadataMismatch(field) => {
                write!(formatter, "ACVP metadata mismatch: {field}")
            }
            Self::MissingExpectedCase { tg_id, tc_id } => write!(
                formatter,
                "missing expected result for tgId={tg_id}, tcId={tc_id}"
            ),
        }
    }
}

impl std::error::Error for AcvpError {}

impl From<std::io::Error> for AcvpError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for AcvpError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<hex::FromHexError> for AcvpError {
    fn from(error: hex::FromHexError) -> Self {
        Self::Hex(error)
    }
}

/// Parse a key-generation prompt from JSON text.
pub fn parse_keygen_prompt(json: &str) -> Result<MlKemKeygenPrompt, AcvpError> {
    Ok(serde_json::from_str(json)?)
}

/// Parse key-generation expected results from JSON text.
pub fn parse_keygen_expected(json: &str) -> Result<MlKemKeygenExpected, AcvpError> {
    Ok(serde_json::from_str(json)?)
}

/// Load and join key-generation prompt and expected-result files.
pub fn load_keygen_cases(
    prompt_path: impl AsRef<Path>,
    expected_path: impl AsRef<Path>,
) -> Result<Vec<MlKemKeygenCase>, AcvpError> {
    let prompt = parse_keygen_prompt(&std::fs::read_to_string(prompt_path)?)?;
    let expected = parse_keygen_expected(&std::fs::read_to_string(expected_path)?)?;
    join_keygen_cases(&prompt, &expected)
}

/// Join parsed key-generation prompt and expected results.
pub fn join_keygen_cases(
    prompt: &MlKemKeygenPrompt,
    expected: &MlKemKeygenExpected,
) -> Result<Vec<MlKemKeygenCase>, AcvpError> {
    validate_metadata(prompt, expected)?;

    let mut joined = Vec::new();

    for prompt_group in &prompt.test_groups {
        let expected_group = expected
            .test_groups
            .iter()
            .find(|group| group.tg_id == prompt_group.tg_id);

        for prompt_case in &prompt_group.tests {
            let expected_case = expected_group
                .and_then(|group| {
                    group
                        .tests
                        .iter()
                        .find(|case| case.tc_id == prompt_case.tc_id)
                })
                .ok_or(AcvpError::MissingExpectedCase {
                    tg_id: prompt_group.tg_id,
                    tc_id: prompt_case.tc_id,
                })?;

            joined.push(MlKemKeygenCase {
                parameter_set: prompt_group.parameter_set.clone(),
                tg_id: prompt_group.tg_id,
                tc_id: prompt_case.tc_id,
                z: hex::decode(&prompt_case.z)?,
                d: hex::decode(&prompt_case.d)?,
                ek: hex::decode(&expected_case.ek)?,
                dk: hex::decode(&expected_case.dk)?,
            });
        }
    }

    Ok(joined)
}

/// Return the local path expected for one fetched ACVP source file.
pub fn local_vector_path(
    repository_root: impl AsRef<Path>,
    upstream_relative_path: &str,
) -> PathBuf {
    repository_root
        .as_ref()
        .join("tests")
        .join("kat")
        .join("acvp")
        .join("upstream")
        .join(upstream_relative_path)
}

fn validate_metadata(
    prompt: &MlKemKeygenPrompt,
    expected: &MlKemKeygenExpected,
) -> Result<(), AcvpError> {
    if prompt.vs_id != expected.vs_id {
        return Err(AcvpError::MetadataMismatch("vsId"));
    }
    if prompt.algorithm != expected.algorithm {
        return Err(AcvpError::MetadataMismatch("algorithm"));
    }
    if prompt.mode != expected.mode {
        return Err(AcvpError::MetadataMismatch("mode"));
    }
    if prompt.revision != expected.revision {
        return Err(AcvpError::MetadataMismatch("revision"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROMPT: &str = r#"{
      "vsId": 42,
      "algorithm": "ML-KEM",
      "mode": "keyGen",
      "revision": "FIPS203",
      "isSample": false,
      "testGroups": [{
        "tgId": 1,
        "testType": "AFT",
        "parameterSet": "ML-KEM-512",
        "tests": [{
          "tcId": 1,
          "z": "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
          "d": "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
        }]
      }]
    }"#;

    const EXPECTED: &str = r#"{
      "vsId": 42,
      "algorithm": "ML-KEM",
      "mode": "keyGen",
      "revision": "FIPS203",
      "testGroups": [{
        "tgId": 1,
        "tests": [{
          "tcId": 1,
          "ek": "AABB",
          "dk": "CCDD"
        }]
      }]
    }"#;

    #[test]
    fn parses_and_joins_keygen_case() {
        let prompt = parse_keygen_prompt(PROMPT).unwrap();
        let expected = parse_keygen_expected(EXPECTED).unwrap();
        let cases = join_keygen_cases(&prompt, &expected).unwrap();

        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].parameter_set, "ML-KEM-512");
        assert_eq!(cases[0].z.len(), 32);
        assert_eq!(cases[0].d.len(), 32);
        assert_eq!(cases[0].ek, vec![0xaa, 0xbb]);
        assert_eq!(cases[0].dk, vec![0xcc, 0xdd]);
    }

    #[test]
    fn rejects_metadata_mismatch() {
        let prompt = parse_keygen_prompt(PROMPT).unwrap();
        let mut expected = parse_keygen_expected(EXPECTED).unwrap();
        expected.revision = "other".to_owned();

        assert!(matches!(
            join_keygen_cases(&prompt, &expected),
            Err(AcvpError::MetadataMismatch("revision"))
        ));
    }

    #[test]
    fn constructs_local_upstream_path() {
        let path = local_vector_path("/repo", NIST_ACVP_SOURCE.keygen_prompt_path);
        assert!(path.ends_with(
            "tests/kat/acvp/upstream/gen-val/json-files/ML-KEM-keyGen-FIPS203/prompt.json"
        ));
    }
}
