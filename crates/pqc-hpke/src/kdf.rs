//! RFC 9180 labeled HKDF operations.

use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};

use crate::identifiers::KdfId;
use crate::HpkeError;

const VERSION_LABEL: &[u8] = b"HPKE-v1";

/// Supported RFC 9180 HKDF algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KdfAlgorithm {
    /// HKDF-SHA256.
    HkdfSha256,
    /// HKDF-SHA384.
    HkdfSha384,
    /// HKDF-SHA512.
    HkdfSha512,
}

impl KdfAlgorithm {
    /// Resolve an RFC 9180 KDF identifier.
    pub const fn from_id(id: KdfId) -> Option<Self> {
        match id.0 {
            0x0001 => Some(Self::HkdfSha256),
            0x0002 => Some(Self::HkdfSha384),
            0x0003 => Some(Self::HkdfSha512),
            _ => None,
        }
    }

    /// Return the HPKE KDF identifier.
    pub const fn id(self) -> KdfId {
        match self {
            Self::HkdfSha256 => KdfId::HKDF_SHA256,
            Self::HkdfSha384 => KdfId::HKDF_SHA384,
            Self::HkdfSha512 => KdfId::HKDF_SHA512,
        }
    }

    /// Return `Nh`.
    pub const fn hash_length(self) -> usize {
        match self {
            Self::HkdfSha256 => 32,
            Self::HkdfSha384 => 48,
            Self::HkdfSha512 => 64,
        }
    }

    /// RFC 9180 `LabeledExtract`.
    pub fn labeled_extract(
        self,
        suite_id: &[u8],
        salt: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> Vec<u8> {
        let mut labeled_ikm =
            Vec::with_capacity(VERSION_LABEL.len() + suite_id.len() + label.len() + ikm.len());
        labeled_ikm.extend_from_slice(VERSION_LABEL);
        labeled_ikm.extend_from_slice(suite_id);
        labeled_ikm.extend_from_slice(label);
        labeled_ikm.extend_from_slice(ikm);

        match self {
            Self::HkdfSha256 => {
                let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled_ikm);
                prk.as_slice().to_vec()
            }
            Self::HkdfSha384 => {
                let (prk, _) = Hkdf::<Sha384>::extract(Some(salt), &labeled_ikm);
                prk.as_slice().to_vec()
            }
            Self::HkdfSha512 => {
                let (prk, _) = Hkdf::<Sha512>::extract(Some(salt), &labeled_ikm);
                prk.as_slice().to_vec()
            }
        }
    }

    /// RFC 9180 `LabeledExpand`.
    pub fn labeled_expand(
        self,
        suite_id: &[u8],
        prk: &[u8],
        label: &[u8],
        info: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, HpkeError> {
        let length_u16 = u16::try_from(length).map_err(|_| HpkeError::OutputTooLong)?;

        let mut labeled_info =
            Vec::with_capacity(2 + VERSION_LABEL.len() + suite_id.len() + label.len() + info.len());
        labeled_info.extend_from_slice(&length_u16.to_be_bytes());
        labeled_info.extend_from_slice(VERSION_LABEL);
        labeled_info.extend_from_slice(suite_id);
        labeled_info.extend_from_slice(label);
        labeled_info.extend_from_slice(info);

        let mut output = vec![0u8; length];

        match self {
            Self::HkdfSha256 => {
                Hkdf::<Sha256>::from_prk(prk)
                    .map_err(|_| HpkeError::InvalidPrk)?
                    .expand(&labeled_info, &mut output)
                    .map_err(|_| HpkeError::OutputTooLong)?;
            }
            Self::HkdfSha384 => {
                Hkdf::<Sha384>::from_prk(prk)
                    .map_err(|_| HpkeError::InvalidPrk)?
                    .expand(&labeled_info, &mut output)
                    .map_err(|_| HpkeError::OutputTooLong)?;
            }
            Self::HkdfSha512 => {
                Hkdf::<Sha512>::from_prk(prk)
                    .map_err(|_| HpkeError::InvalidPrk)?
                    .expand(&labeled_info, &mut output)
                    .map_err(|_| HpkeError::OutputTooLong)?;
            }
        }

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::{AeadId, HpkeSuiteId, KemId};

    #[test]
    fn labels_domain_separate_outputs() {
        let suite = HpkeSuiteId {
            kem_id: KemId(0x0020),
            kdf_id: KdfId::HKDF_SHA256,
            aead_id: AeadId::AES_128_GCM,
        }
        .to_bytes();

        let left = KdfAlgorithm::HkdfSha256.labeled_extract(&suite, b"", b"left", b"ikm");
        let right = KdfAlgorithm::HkdfSha256.labeled_extract(&suite, b"", b"right", b"ikm");

        assert_ne!(left, right);
    }

    #[test]
    fn expand_rejects_non_prk_input() {
        let result =
            KdfAlgorithm::HkdfSha256.labeled_expand(b"suite", b"short", b"key", b"context", 16);

        assert_eq!(result, Err(HpkeError::InvalidPrk));
    }
}
