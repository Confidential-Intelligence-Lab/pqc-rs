//! RFC 9180 AEAD operations used by HPKE contexts.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce,
};
use chacha20poly1305::ChaCha20Poly1305;

use crate::identifiers::AeadId;
use crate::HpkeError;

/// AEAD implementation selected by an HPKE ciphersuite.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AeadAlgorithm {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20Poly1305.
    ChaCha20Poly1305,
    /// Export-only mode, which cannot seal or open messages.
    ExportOnly,
}

impl AeadAlgorithm {
    /// Resolve an RFC 9180 AEAD identifier.
    pub const fn from_id(id: AeadId) -> Option<Self> {
        match id.0 {
            0x0001 => Some(Self::Aes128Gcm),
            0x0002 => Some(Self::Aes256Gcm),
            0x0003 => Some(Self::ChaCha20Poly1305),
            0xffff => Some(Self::ExportOnly),
            _ => None,
        }
    }

    /// Return the AEAD key length.
    pub const fn key_length(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20Poly1305 => 32,
            Self::ExportOnly => 0,
        }
    }

    /// Return the AEAD nonce length.
    pub const fn nonce_length(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::Aes256Gcm | Self::ChaCha20Poly1305 => 12,
            Self::ExportOnly => 0,
        }
    }

    /// Seal one plaintext.
    pub fn seal(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        self.validate_lengths(key, nonce)?;
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| HpkeError::InvalidAeadKey)?
                .encrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| HpkeError::SealError),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| HpkeError::InvalidAeadKey)?
                .encrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| HpkeError::SealError),
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| HpkeError::InvalidAeadKey)?
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                .map_err(|_| HpkeError::SealError),
            Self::ExportOnly => Err(HpkeError::ExportOnly),
        }
    }

    /// Open one ciphertext.
    pub fn open(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, HpkeError> {
        self.validate_lengths(key, nonce)?;
        let payload = Payload {
            msg: ciphertext,
            aad,
        };
        match self {
            Self::Aes128Gcm => Aes128Gcm::new_from_slice(key)
                .map_err(|_| HpkeError::InvalidAeadKey)?
                .decrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| HpkeError::OpenError),
            Self::Aes256Gcm => Aes256Gcm::new_from_slice(key)
                .map_err(|_| HpkeError::InvalidAeadKey)?
                .decrypt(Nonce::from_slice(nonce), payload)
                .map_err(|_| HpkeError::OpenError),
            Self::ChaCha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| HpkeError::InvalidAeadKey)?
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                .map_err(|_| HpkeError::OpenError),
            Self::ExportOnly => Err(HpkeError::ExportOnly),
        }
    }

    fn validate_lengths(self, key: &[u8], nonce: &[u8]) -> Result<(), HpkeError> {
        if key.len() != self.key_length() {
            return Err(HpkeError::InvalidAeadKey);
        }
        if nonce.len() != self.nonce_length() {
            return Err(HpkeError::InvalidAeadNonce);
        }
        Ok(())
    }
}
