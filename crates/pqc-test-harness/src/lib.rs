#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Shared testing helpers for KATs, negative tests, protocol tests, and benchmarks.

/// A parsed known-answer-test vector.
#[derive(Clone, Debug, Eq, PartialEq)]
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

/// Decode a hex string into bytes.
pub fn decode_hex(input: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex() {
        assert_eq!(decode_hex("aabb").unwrap(), vec![0xaa, 0xbb]);
    }
}
