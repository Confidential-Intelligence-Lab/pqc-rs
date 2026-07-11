//! Parser for the pinned `draft-ietf-hpke-pq-05` JSON vectors.

use serde::Deserialize;
use std::path::Path;

/// One HPKE-PQ test-vector suite.
#[derive(Clone, Debug, Deserialize)]
pub struct HpkePqVector {
    /// HPKE mode.
    pub mode: u8,
    /// KEM identifier.
    pub kem_id: u16,
    /// KDF identifier.
    pub kdf_id: u16,
    /// AEAD identifier.
    pub aead_id: u16,
    /// HPKE info.
    pub info: String,
    /// Deterministic encapsulation input.
    #[serde(rename = "ikmE")]
    pub ikm_e: String,
    /// Recipient key-derivation input.
    #[serde(rename = "ikmR")]
    pub ikm_r: String,
    /// Serialized recipient private key.
    #[serde(rename = "skRm")]
    pub sk_rm: String,
    /// Serialized recipient public key.
    #[serde(rename = "pkRm")]
    pub pk_rm: String,
    /// KEM encapsulation.
    pub enc: String,
    /// KEM shared secret.
    pub shared_secret: String,
    /// Key-schedule context.
    #[serde(default)]
    pub key_schedule_context: String,
    /// HPKE key-schedule secret.
    #[serde(default)]
    pub secret: String,
    /// AEAD key.
    #[serde(default)]
    pub key: String,
    /// Base nonce.
    #[serde(default)]
    pub base_nonce: String,
    /// Exporter secret.
    #[serde(default)]
    pub exporter_secret: String,
    /// Message-encryption vectors.
    #[serde(default)]
    pub encryptions: Vec<HpkeEncryptionVector>,
    /// Secret-export vectors.
    #[serde(default)]
    pub exports: Vec<HpkeExportVector>,
}

/// One HPKE message-encryption vector.
#[derive(Clone, Debug, Deserialize)]
pub struct HpkeEncryptionVector {
    /// Optional explicit sequence number.
    ///
    /// The pinned HPKE-PQ corpus normally implies the sequence number from
    /// the encryption entry's position.
    #[serde(default)]
    pub seq: Option<u64>,
    /// Derived nonce.
    pub nonce: String,
    /// Plaintext.
    pub pt: String,
    /// Additional authenticated data.
    pub aad: String,
    /// Ciphertext.
    pub ct: String,
}

/// One HPKE exporter vector.
#[derive(Clone, Debug, Deserialize)]
pub struct HpkeExportVector {
    /// Exporter context.
    pub exporter_context: String,
    /// Output length.
    #[serde(rename = "L")]
    pub length: usize,
    /// Exported value.
    pub exported_value: String,
}

/// Vector parser error.
#[derive(Debug)]
pub enum HpkePqVectorError {
    /// File-system error.
    Io(std::io::Error),
    /// JSON parsing error.
    Json(serde_json::Error),
    /// Hex decoding error.
    Hex(hex::FromHexError),
}

impl core::fmt::Display for HpkePqVectorError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
            Self::Hex(error) => write!(formatter, "hex error: {error}"),
        }
    }
}

impl std::error::Error for HpkePqVectorError {}

impl From<std::io::Error> for HpkePqVectorError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for HpkePqVectorError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<hex::FromHexError> for HpkePqVectorError {
    fn from(error: hex::FromHexError) -> Self {
        Self::Hex(error)
    }
}

/// Load the pinned HPKE-PQ JSON vectors.
pub fn load_vectors(path: impl AsRef<Path>) -> Result<Vec<HpkePqVector>, HpkePqVectorError> {
    let json = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&json)?)
}

/// Decode one hexadecimal field.
pub fn decode_hex(value: &str) -> Result<Vec<u8>, HpkePqVectorError> {
    Ok(hex::decode(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_vector_shape() {
        let json = r#"[{
              "mode": 0,
              "kem_id": 64,
              "kdf_id": 1,
              "aead_id": 1,
              "info": "",
              "ikmE": "00",
              "ikmR": "00",
              "skRm": "00",
              "pkRm": "00",
              "enc": "00",
              "shared_secret": "00",
              "encryptions": [{
                "seq": 0,
                "nonce": "00",
                "pt": "00",
                "aad": "",
                "ct": "00"
              }],
              "exports": [{
                "exporter_context": "",
                "L": 1,
                "exported_value": "00"
              }]
            }]"#;

        let vectors: Vec<HpkePqVector> = serde_json::from_str(json).unwrap();
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].kem_id, 64);
        assert_eq!(vectors[0].exports[0].length, 1);
    }
}
