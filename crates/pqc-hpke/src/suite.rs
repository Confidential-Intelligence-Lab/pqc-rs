//! Typed HPKE ciphersuite selection and validation.

use crate::aead::AeadAlgorithm;
use crate::identifiers::{AeadId, HpkeSuiteId, KdfId};
use crate::kdf::KdfAlgorithm;
use crate::key_schedule::AeadParameters;
use crate::ml_kem::MlKemHpke;
use crate::HpkeError;

/// A validated HPKE ciphersuite and its resolved algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HpkeSuite {
    id: HpkeSuiteId,
    kdf: KdfAlgorithm,
    aead: AeadAlgorithm,
    aead_parameters: AeadParameters,
}

impl HpkeSuite {
    /// Resolve and validate a ciphersuite for the selected ML-KEM parameter set.
    pub fn new(kem: MlKemHpke, kdf_id: KdfId, aead_id: AeadId) -> Result<Self, HpkeError> {
        Self::from_id(
            kem,
            HpkeSuiteId {
                kem_id: kem.kem_id(),
                kdf_id,
                aead_id,
            },
        )
    }

    /// Resolve and validate an existing HPKE suite identifier.
    pub fn from_id(kem: MlKemHpke, id: HpkeSuiteId) -> Result<Self, HpkeError> {
        if id.kem_id != kem.kem_id() {
            return Err(HpkeError::KemIdentifierMismatch);
        }

        let kdf = KdfAlgorithm::from_id(id.kdf_id).ok_or(HpkeError::UnsupportedKdf)?;
        let aead = AeadAlgorithm::from_id(id.aead_id).ok_or(HpkeError::UnsupportedAead)?;
        let aead_parameters =
            AeadParameters::for_id(id.aead_id).ok_or(HpkeError::UnsupportedAead)?;

        Ok(Self {
            id,
            kdf,
            aead,
            aead_parameters,
        })
    }

    /// Return the serialized HPKE suite identifier.
    pub const fn id(self) -> HpkeSuiteId {
        self.id
    }

    /// Return the resolved KDF implementation.
    pub const fn kdf(self) -> KdfAlgorithm {
        self.kdf
    }

    /// Return the resolved AEAD implementation.
    pub const fn aead(self) -> AeadAlgorithm {
        self.aead
    }

    /// Return the AEAD key and nonce dimensions.
    pub const fn aead_parameters(self) -> AeadParameters {
        self.aead_parameters
    }
}

/// Return all message-capable KDF identifiers supported by this crate.
pub const fn supported_kdfs() -> [KdfId; 3] {
    [KdfId::HKDF_SHA256, KdfId::HKDF_SHA384, KdfId::HKDF_SHA512]
}

/// Return all message-capable AEAD identifiers supported by this crate.
pub const fn supported_aeads() -> [AeadId; 3] {
    [
        AeadId::AES_128_GCM,
        AeadId::AES_256_GCM,
        AeadId::CHACHA20_POLY1305,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::KemId;

    #[test]
    fn registry_contains_nine_message_suites_per_kem() {
        let kem = MlKemHpke::MlKem768;
        let mut count = 0;
        for kdf in supported_kdfs() {
            for aead in supported_aeads() {
                let suite = HpkeSuite::new(kem, kdf, aead).unwrap();
                assert_eq!(suite.id().kem_id, kem.kem_id());
                count += 1;
            }
        }
        assert_eq!(count, 9);
    }

    #[test]
    fn unsupported_identifiers_are_rejected() {
        let kem = MlKemHpke::MlKem512;
        assert_eq!(
            HpkeSuite::new(kem, KdfId(0xfffe), AeadId::AES_128_GCM),
            Err(HpkeError::UnsupportedKdf)
        );
        assert_eq!(
            HpkeSuite::new(kem, KdfId::HKDF_SHA256, AeadId(0xfffe)),
            Err(HpkeError::UnsupportedAead)
        );
        assert_eq!(
            HpkeSuite::from_id(
                kem,
                HpkeSuiteId {
                    kem_id: KemId(0x0042),
                    kdf_id: KdfId::HKDF_SHA256,
                    aead_id: AeadId::AES_128_GCM,
                },
            ),
            Err(HpkeError::KemIdentifierMismatch)
        );
    }
}
