#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Shared testing helpers for KATs, negative tests, protocol tests, and benchmarks.

pub mod acvp;
pub mod acvp_encap_decap;
pub mod standards_scope;

/// A parsed known-answer-test vector.
#[derive(Clone, Eq, PartialEq)]
pub struct KatVector {
    /// Vector name or identifier.
    pub id: String,
    /// Parameter set name.
    pub parameter_set: String,
    /// Input seed bytes.
    pub seed: Vec<u8>,
    /// Public-key bytes.
    pub public_key: Vec<u8>,
    /// Secret-key bytes.
    pub secret_key: Vec<u8>,
    /// Ciphertext bytes.
    pub ciphertext: Vec<u8>,
    /// Expected shared-secret bytes.
    pub shared_secret: Vec<u8>,
}

impl core::fmt::Debug for KatVector {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KatVector")
            .field("id", &self.id)
            .field("parameter_set", &self.parameter_set)
            .field("sensitive_fields", &"<redacted>")
            .finish()
    }
}

/// K-PKE intermediate-value record.
#[derive(Clone, Eq, PartialEq)]
pub struct KpkeIntermediateVector {
    /// Vector name.
    pub id: String,
    /// Parameter set name.
    pub parameter_set: String,
    /// Key-generation seed.
    pub keygen_seed: Vec<u8>,
    /// Matrix seed.
    pub rho: Vec<u8>,
    /// Noise seed.
    pub sigma: Vec<u8>,
    /// Plaintext message.
    pub message: Vec<u8>,
    /// Encryption randomness.
    pub encryption_randomness: Vec<u8>,
    /// Encoded public-key component.
    pub public_key: Vec<u8>,
    /// Encoded CPA secret-key component.
    pub secret_key: Vec<u8>,
    /// Encoded ciphertext component.
    pub ciphertext: Vec<u8>,
}

impl core::fmt::Debug for KpkeIntermediateVector {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("KpkeIntermediateVector")
            .field("id", &self.id)
            .field("parameter_set", &self.parameter_set)
            .field("sensitive_fields", &"<redacted>")
            .finish()
    }
}

/// Validation category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationCategory {
    /// Structural/API validation only.
    Structural,
    /// Internal deterministic validation.
    Internal,
    /// Official known-answer-test validation.
    OfficialKat,
}

/// Result of validating one vector.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationResult {
    /// Vector identifier.
    pub vector_id: String,
    /// Validation category.
    pub category: ValidationCategory,
    /// Whether validation passed.
    pub passed: bool,
    /// Diagnostic summary.
    pub detail: String,
}

impl ValidationResult {
    /// Construct a passing result.
    pub fn pass(
        vector_id: impl Into<String>,
        category: ValidationCategory,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            vector_id: vector_id.into(),
            category,
            passed: true,
            detail: detail.into(),
        }
    }

    /// Construct a failing result.
    pub fn fail(
        vector_id: impl Into<String>,
        category: ValidationCategory,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            vector_id: vector_id.into(),
            category,
            passed: false,
            detail: detail.into(),
        }
    }
}

/// Decode a hex string into bytes.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(input)
}

/// Check that a byte slice has an expected length.
pub fn validate_length(
    vector_id: &str,
    field: &str,
    actual: usize,
    expected: usize,
    category: ValidationCategory,
) -> ValidationResult {
    if actual == expected {
        ValidationResult::pass(
            vector_id,
            category,
            format!("{field} length is {expected} bytes"),
        )
    } else {
        ValidationResult::fail(
            vector_id,
            category,
            format!("{field} length is {actual} bytes; expected {expected}"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex() {
        assert_eq!(decode_hex("aabb").unwrap(), vec![0xaa, 0xbb]);
    }

    #[test]
    fn length_validation_passes_and_fails_deterministically() {
        let pass = validate_length(
            "vector-1",
            "public_key",
            800,
            800,
            ValidationCategory::Structural,
        );
        assert!(pass.passed);

        let fail = validate_length(
            "vector-2",
            "public_key",
            799,
            800,
            ValidationCategory::Structural,
        );
        assert!(!fail.passed);
        assert!(fail.detail.contains("799"));
        assert!(fail.detail.contains("800"));
    }
}
pub mod hpke_pq_vectors;
