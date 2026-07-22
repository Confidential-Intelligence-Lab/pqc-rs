#![allow(clippy::module_name_repetitions)]
//! NIST ACVP ML-KEM encapsulation/decapsulation vector parsing.
//!
//! Stage 6.5A parses, validates, joins, and inventories the official
//! `ML-KEM-encapDecap-FIPS203` prompt and expected-result files. It does not
//! execute cryptographic operations or claim that any vector has passed.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// Supported ACVP ML-KEM encapsulation/decapsulation function.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EncapDecapFunction {
    /// FIPS 203 `ML-KEM.Encaps_internal`.
    Encapsulation,
    /// FIPS 203 `ML-KEM.Decaps_internal`.
    Decapsulation,
    /// FIPS 203 Section 7.2 encapsulation-key check.
    EncapsulationKeyCheck,
    /// FIPS 203 Section 7.3 decapsulation-key check.
    DecapsulationKeyCheck,
}

impl EncapDecapFunction {
    /// Parse an ACVP function string.
    pub fn parse(value: &str) -> Result<Self, EncapDecapError> {
        match value {
            "encapsulation" => Ok(Self::Encapsulation),
            "decapsulation" => Ok(Self::Decapsulation),
            "encapsulationKeyCheck" => Ok(Self::EncapsulationKeyCheck),
            "decapsulationKeyCheck" => Ok(Self::DecapsulationKeyCheck),
            other => Err(EncapDecapError::UnsupportedFunction(other.to_owned())),
        }
    }

    /// Return the canonical ACVP function name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Encapsulation => "encapsulation",
            Self::Decapsulation => "decapsulation",
            Self::EncapsulationKeyCheck => "encapsulationKeyCheck",
            Self::DecapsulationKeyCheck => "decapsulationKeyCheck",
        }
    }
}

/// Parsed ACVP encapsulation/decapsulation prompt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EncapDecapPrompt {
    /// ACVP vector-set identifier.
    pub vs_id: u64,
    /// Algorithm name.
    pub algorithm: String,
    /// Mode name.
    pub mode: String,
    /// Revision identifier.
    pub revision: String,
    /// Whether this is a sample vector set.
    #[serde(default)]
    pub is_sample: bool,
    /// Test groups.
    pub test_groups: Vec<EncapDecapPromptGroup>,
}

/// One prompt test group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EncapDecapPromptGroup {
    /// Test-group identifier.
    pub tg_id: u64,
    /// Test type, such as `AFT` or `VAL`.
    pub test_type: String,
    /// ML-KEM parameter-set name.
    pub parameter_set: String,
    /// Requested function.
    pub function: String,
    /// Prompt test cases.
    pub tests: Vec<EncapDecapPromptCase>,
}

/// One prompt test case.
///
/// Fields are optional at the JSON layer because their presence depends on the
/// group's function. [`join_encap_decap_cases`] enforces the normative
/// function-specific requirements.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EncapDecapPromptCase {
    /// Test-case identifier.
    pub tc_id: u64,
    /// Decapsulation key, as hexadecimal.
    pub dk: Option<String>,
    /// Encapsulation key, as hexadecimal.
    pub ek: Option<String>,
    /// Encapsulation randomness/message input, as hexadecimal.
    pub m: Option<String>,
    /// Ciphertext, as hexadecimal.
    pub c: Option<String>,
}

impl core::fmt::Debug for EncapDecapPromptCase {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EncapDecapPromptCase")
            .field("tc_id", &self.tc_id)
            .field("sensitive_fields", &"<redacted>")
            .finish()
    }
}

/// Parsed ACVP expected results.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EncapDecapExpected {
    /// ACVP vector-set identifier.
    pub vs_id: u64,
    /// Algorithm name.
    pub algorithm: String,
    /// Mode name.
    pub mode: String,
    /// Revision identifier.
    pub revision: String,
    /// Expected-result groups.
    pub test_groups: Vec<EncapDecapExpectedGroup>,
}

/// One expected-result group.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EncapDecapExpectedGroup {
    /// Test-group identifier.
    pub tg_id: u64,
    /// Expected test cases.
    pub tests: Vec<EncapDecapExpectedCase>,
}

/// One expected result.
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EncapDecapExpectedCase {
    /// Test-case identifier.
    pub tc_id: u64,
    /// Expected ciphertext for encapsulation.
    pub c: Option<String>,
    /// Expected shared secret for encapsulation or decapsulation.
    pub k: Option<String>,
    /// Expected key-check result.
    pub test_passed: Option<bool>,
}

impl core::fmt::Debug for EncapDecapExpectedCase {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EncapDecapExpectedCase")
            .field("tc_id", &self.tc_id)
            .field("c", &self.c.as_ref().map(|_| "<redacted>"))
            .field("k", &self.k.as_ref().map(|_| "<redacted>"))
            .field("test_passed", &self.test_passed)
            .finish()
    }
}

/// Joined, decoded ACVP case.
#[derive(Clone, Eq, PartialEq)]
pub struct EncapDecapCase {
    /// Test-group identifier.
    pub tg_id: u64,
    /// Test-case identifier.
    pub tc_id: u64,
    /// Test type.
    pub test_type: String,
    /// Parameter set.
    pub parameter_set: String,
    /// Function.
    pub function: EncapDecapFunction,
    /// Decapsulation key, when supplied.
    pub dk: Option<Vec<u8>>,
    /// Encapsulation key, when supplied.
    pub ek: Option<Vec<u8>>,
    /// Encapsulation randomness/message, when supplied.
    pub m: Option<Vec<u8>>,
    /// Input ciphertext, when supplied.
    pub input_ciphertext: Option<Vec<u8>>,
    /// Expected ciphertext, when supplied.
    pub expected_ciphertext: Option<Vec<u8>>,
    /// Expected shared secret, when supplied.
    pub expected_shared_secret: Option<Vec<u8>>,
    /// Expected key-check result, when supplied.
    pub expected_test_passed: Option<bool>,
}

impl core::fmt::Debug for EncapDecapCase {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("EncapDecapCase")
            .field("tg_id", &self.tg_id)
            .field("tc_id", &self.tc_id)
            .field("test_type", &self.test_type)
            .field("parameter_set", &self.parameter_set)
            .field("function", &self.function)
            .field("sensitive_fields", &"<redacted>")
            .field("expected_test_passed", &self.expected_test_passed)
            .finish()
    }
}

/// Inventory information for a parsed vector set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncapDecapInventory {
    /// Total joined cases.
    pub total_cases: usize,
    /// Counts by function.
    pub by_function: BTreeMap<EncapDecapFunction, usize>,
    /// Counts by parameter set.
    pub by_parameter_set: BTreeMap<String, usize>,
}

/// Parser or schema-validation error.
#[derive(Debug)]
pub enum EncapDecapError {
    /// File-system error.
    Io(std::io::Error),
    /// JSON decoding error.
    Json(serde_json::Error),
    /// Hex decoding error.
    Hex(hex::FromHexError),
    /// Prompt and expected-result metadata differ.
    MetadataMismatch(&'static str),
    /// Unsupported function string.
    UnsupportedFunction(String),
    /// Missing expected group or case.
    MissingExpectedCase {
        /// Test-group identifier.
        tg_id: u64,
        /// Test-case identifier.
        tc_id: u64,
    },
    /// A function-specific field is missing.
    MissingField {
        /// Test-group identifier.
        tg_id: u64,
        /// Test-case identifier.
        tc_id: u64,
        /// Missing JSON field.
        field: &'static str,
    },
    /// A decoded field has an invalid byte length.
    InvalidLength {
        /// Test-group identifier.
        tg_id: u64,
        /// Test-case identifier.
        tc_id: u64,
        /// Field name.
        field: &'static str,
        /// Expected length.
        expected: usize,
        /// Actual length.
        actual: usize,
    },
}

impl core::fmt::Display for EncapDecapError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::Hex(error) => write!(formatter, "hex error: {error}"),
            Self::MetadataMismatch(field) => {
                write!(formatter, "ACVP metadata mismatch: {field}")
            }
            Self::UnsupportedFunction(function) => {
                write!(formatter, "unsupported ACVP function: {function}")
            }
            Self::MissingExpectedCase { tg_id, tc_id } => write!(
                formatter,
                "missing expected result for tgId={tg_id}, tcId={tc_id}"
            ),
            Self::MissingField {
                tg_id,
                tc_id,
                field,
            } => write!(
                formatter,
                "missing field {field} for tgId={tg_id}, tcId={tc_id}"
            ),
            Self::InvalidLength {
                tg_id,
                tc_id,
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "invalid {field} length for tgId={tg_id}, tcId={tc_id}: \
                 expected {expected}, actual {actual}"
            ),
        }
    }
}

impl std::error::Error for EncapDecapError {}

impl From<std::io::Error> for EncapDecapError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for EncapDecapError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<hex::FromHexError> for EncapDecapError {
    fn from(error: hex::FromHexError) -> Self {
        Self::Hex(error)
    }
}

/// Parse an encapsulation/decapsulation prompt.
pub fn parse_encap_decap_prompt(json: &str) -> Result<EncapDecapPrompt, EncapDecapError> {
    Ok(serde_json::from_str(json)?)
}

/// Parse encapsulation/decapsulation expected results.
pub fn parse_encap_decap_expected(json: &str) -> Result<EncapDecapExpected, EncapDecapError> {
    Ok(serde_json::from_str(json)?)
}

/// Load and join prompt and expected-result files.
pub fn load_encap_decap_cases(
    prompt_path: impl AsRef<Path>,
    expected_path: impl AsRef<Path>,
) -> Result<Vec<EncapDecapCase>, EncapDecapError> {
    let prompt = parse_encap_decap_prompt(&std::fs::read_to_string(prompt_path)?)?;
    let expected = parse_encap_decap_expected(&std::fs::read_to_string(expected_path)?)?;
    join_encap_decap_cases(&prompt, &expected)
}

/// Join, decode, and validate prompt and expected-result cases.
pub fn join_encap_decap_cases(
    prompt: &EncapDecapPrompt,
    expected: &EncapDecapExpected,
) -> Result<Vec<EncapDecapCase>, EncapDecapError> {
    validate_metadata(prompt, expected)?;

    let mut joined = Vec::new();

    for prompt_group in &prompt.test_groups {
        let function = EncapDecapFunction::parse(&prompt_group.function)?;
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
                .ok_or(EncapDecapError::MissingExpectedCase {
                    tg_id: prompt_group.tg_id,
                    tc_id: prompt_case.tc_id,
                })?;

            let case = decode_case(prompt_group, prompt_case, expected_case, function)?;
            validate_case_lengths(&case)?;
            joined.push(case);
        }
    }

    Ok(joined)
}

/// Produce inventory counts for joined cases.
pub fn inventory(cases: &[EncapDecapCase]) -> EncapDecapInventory {
    let mut by_function = BTreeMap::new();
    let mut by_parameter_set = BTreeMap::new();

    for case in cases {
        *by_function.entry(case.function).or_insert(0) += 1;
        *by_parameter_set
            .entry(case.parameter_set.clone())
            .or_insert(0) += 1;
    }

    EncapDecapInventory {
        total_cases: cases.len(),
        by_function,
        by_parameter_set,
    }
}

fn decode_case(
    group: &EncapDecapPromptGroup,
    prompt: &EncapDecapPromptCase,
    expected: &EncapDecapExpectedCase,
    function: EncapDecapFunction,
) -> Result<EncapDecapCase, EncapDecapError> {
    let tg_id = group.tg_id;
    let tc_id = prompt.tc_id;

    let required_prompt =
        |value: &Option<String>, field: &'static str| -> Result<Vec<u8>, EncapDecapError> {
            value
                .as_ref()
                .ok_or(EncapDecapError::MissingField {
                    tg_id,
                    tc_id,
                    field,
                })
                .and_then(|encoded| Ok(hex::decode(encoded)?))
        };

    let required_expected =
        |value: &Option<String>, field: &'static str| -> Result<Vec<u8>, EncapDecapError> {
            value
                .as_ref()
                .ok_or(EncapDecapError::MissingField {
                    tg_id,
                    tc_id,
                    field,
                })
                .and_then(|encoded| Ok(hex::decode(encoded)?))
        };

    let mut case = EncapDecapCase {
        tg_id,
        tc_id,
        test_type: group.test_type.clone(),
        parameter_set: group.parameter_set.clone(),
        function,
        dk: None,
        ek: None,
        m: None,
        input_ciphertext: None,
        expected_ciphertext: None,
        expected_shared_secret: None,
        expected_test_passed: None,
    };

    match function {
        EncapDecapFunction::Encapsulation => {
            case.ek = Some(required_prompt(&prompt.ek, "ek")?);
            case.m = Some(required_prompt(&prompt.m, "m")?);
            case.expected_ciphertext = Some(required_expected(&expected.c, "c")?);
            case.expected_shared_secret = Some(required_expected(&expected.k, "k")?);
        }
        EncapDecapFunction::Decapsulation => {
            case.dk = Some(required_prompt(&prompt.dk, "dk")?);
            case.input_ciphertext = Some(required_prompt(&prompt.c, "c")?);
            case.expected_shared_secret = Some(required_expected(&expected.k, "k")?);
        }
        EncapDecapFunction::EncapsulationKeyCheck => {
            case.ek = Some(required_prompt(&prompt.ek, "ek")?);
            case.expected_test_passed =
                Some(expected.test_passed.ok_or(EncapDecapError::MissingField {
                    tg_id,
                    tc_id,
                    field: "testPassed",
                })?);
        }
        EncapDecapFunction::DecapsulationKeyCheck => {
            case.dk = Some(required_prompt(&prompt.dk, "dk")?);
            case.expected_test_passed =
                Some(expected.test_passed.ok_or(EncapDecapError::MissingField {
                    tg_id,
                    tc_id,
                    field: "testPassed",
                })?);
        }
    }

    Ok(case)
}

fn validate_metadata(
    prompt: &EncapDecapPrompt,
    expected: &EncapDecapExpected,
) -> Result<(), EncapDecapError> {
    if prompt.vs_id != expected.vs_id {
        return Err(EncapDecapError::MetadataMismatch("vsId"));
    }
    if prompt.algorithm != expected.algorithm {
        return Err(EncapDecapError::MetadataMismatch("algorithm"));
    }
    if prompt.mode != expected.mode {
        return Err(EncapDecapError::MetadataMismatch("mode"));
    }
    if prompt.revision != expected.revision {
        return Err(EncapDecapError::MetadataMismatch("revision"));
    }
    Ok(())
}

fn validate_case_lengths(case: &EncapDecapCase) -> Result<(), EncapDecapError> {
    let (ek, dk, ciphertext) = parameter_lengths(&case.parameter_set)?;

    match case.function {
        EncapDecapFunction::Encapsulation => {
            validate_optional_length(case, "ek", case.ek.as_deref(), ek)?;
            validate_optional_length(case, "m", case.m.as_deref(), 32)?;
            validate_optional_length(
                case,
                "expected ciphertext",
                case.expected_ciphertext.as_deref(),
                ciphertext,
            )?;
            validate_optional_length(
                case,
                "expected shared secret",
                case.expected_shared_secret.as_deref(),
                32,
            )?;
        }

        EncapDecapFunction::Decapsulation => {
            validate_optional_length(case, "dk", case.dk.as_deref(), dk)?;
            validate_optional_length(
                case,
                "input ciphertext",
                case.input_ciphertext.as_deref(),
                ciphertext,
            )?;
            validate_optional_length(
                case,
                "expected shared secret",
                case.expected_shared_secret.as_deref(),
                32,
            )?;
        }

        EncapDecapFunction::EncapsulationKeyCheck => {
            // The ACVP server deliberately supplies potentially malformed
            // encapsulation keys. Preserve the input exactly and let the
            // implementation under test determine validity.
            if case.ek.is_none() {
                return Err(EncapDecapError::MissingField {
                    tg_id: case.tg_id,
                    tc_id: case.tc_id,
                    field: "ek",
                });
            }
        }

        EncapDecapFunction::DecapsulationKeyCheck => {
            // The ACVP server deliberately supplies potentially malformed
            // decapsulation keys. Do not enforce the normal parameter-set
            // length during parsing.
            if case.dk.is_none() {
                return Err(EncapDecapError::MissingField {
                    tg_id: case.tg_id,
                    tc_id: case.tc_id,
                    field: "dk",
                });
            }
        }
    }

    Ok(())
}

fn validate_optional_length(
    case: &EncapDecapCase,
    field: &'static str,
    value: Option<&[u8]>,
    expected: usize,
) -> Result<(), EncapDecapError> {
    if let Some(bytes) = value {
        if bytes.len() != expected {
            return Err(EncapDecapError::InvalidLength {
                tg_id: case.tg_id,
                tc_id: case.tc_id,
                field,
                expected,
                actual: bytes.len(),
            });
        }
    }
    Ok(())
}

fn parameter_lengths(parameter_set: &str) -> Result<(usize, usize, usize), EncapDecapError> {
    match parameter_set {
        "ML-KEM-512" => Ok((800, 1632, 768)),
        "ML-KEM-768" => Ok((1184, 2400, 1088)),
        "ML-KEM-1024" => Ok((1568, 3168, 1568)),
        other => Err(EncapDecapError::UnsupportedFunction(format!(
            "parameter set {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROMPT: &str = r#"{
      "vsId": 9,
      "algorithm": "ML-KEM",
      "mode": "encapDecap",
      "revision": "FIPS203",
      "testGroups": [
        {
          "tgId": 1,
          "testType": "AFT",
          "parameterSet": "ML-KEM-512",
          "function": "encapsulation",
          "tests": [{
            "tcId": 1,
            "ek": "00",
            "m": "00"
          }]
        }
      ]
    }"#;

    const EXPECTED: &str = r#"{
      "vsId": 9,
      "algorithm": "ML-KEM",
      "mode": "encapDecap",
      "revision": "FIPS203",
      "testGroups": [{
        "tgId": 1,
        "tests": [{
          "tcId": 1,
          "c": "00",
          "k": "00"
        }]
      }]
    }"#;

    #[test]
    fn parses_schema_before_length_validation() {
        let prompt = parse_encap_decap_prompt(PROMPT).unwrap();
        let expected = parse_encap_decap_expected(EXPECTED).unwrap();

        assert_eq!(prompt.test_groups[0].function, "encapsulation");
        assert_eq!(expected.test_groups[0].tests[0].tc_id, 1);
    }

    #[test]
    fn rejects_wrong_function_specific_lengths() {
        let prompt = parse_encap_decap_prompt(PROMPT).unwrap();
        let expected = parse_encap_decap_expected(EXPECTED).unwrap();

        assert!(matches!(
            join_encap_decap_cases(&prompt, &expected),
            Err(EncapDecapError::InvalidLength { field: "ek", .. })
        ));
    }

    #[test]
    fn function_names_round_trip() {
        for function in [
            EncapDecapFunction::Encapsulation,
            EncapDecapFunction::Decapsulation,
            EncapDecapFunction::EncapsulationKeyCheck,
            EncapDecapFunction::DecapsulationKeyCheck,
        ] {
            assert_eq!(
                EncapDecapFunction::parse(function.as_str()).unwrap(),
                function
            );
        }
    }
}
