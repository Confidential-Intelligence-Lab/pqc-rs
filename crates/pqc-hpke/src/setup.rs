//! RFC 9180 Base-mode sender and receiver setup.

use crate::aead::AeadAlgorithm;
use crate::context::{ReceiverContext, SenderContext};
use crate::identifiers::HpkeSuiteId;
use crate::kdf::KdfAlgorithm;
use crate::key_schedule::{key_schedule, AeadParameters, HpkeMode, KeyScheduleInputs};
use crate::ml_kem::{MlKemHpke, MlKemHpkeError};
use crate::HpkeError;

/// Result of deterministic Base-mode sender setup.
pub struct BaseSenderSetup {
    /// Serialized KEM encapsulation.
    pub encapsulated_key: Vec<u8>,
    /// Sender context.
    pub context: SenderContext,
}

/// Deterministically execute `SetupBaseS` for an ML-KEM HPKE suite.
pub fn setup_base_sender_deterministic(
    kem: MlKemHpke,
    suite: HpkeSuiteId,
    recipient_public_key: &[u8],
    info: &[u8],
    randomness: &[u8; 32],
) -> Result<BaseSenderSetup, HpkeError> {
    validate_suite(kem, suite)?;
    let kdf = KdfAlgorithm::from_id(suite.kdf_id).ok_or(HpkeError::UnsupportedKdf)?;
    let aead = AeadAlgorithm::from_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;
    let parameters = AeadParameters::for_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;
    let encapsulation = kem
        .encapsulate_deterministic(recipient_public_key, randomness)
        .map_err(map_kem_error)?;
    let schedule = key_schedule(
        suite,
        kdf,
        parameters,
        KeyScheduleInputs {
            mode: HpkeMode::Base,
            shared_secret: encapsulation.shared_secret.as_bytes(),
            info,
            psk: b"",
            psk_id: b"",
        },
    )?;
    Ok(BaseSenderSetup {
        encapsulated_key: encapsulation.encapsulated_key,
        context: SenderContext::new(suite, kdf, aead, schedule),
    })
}

/// Execute `SetupBaseR` for an ML-KEM HPKE suite.
pub fn setup_base_receiver(
    kem: MlKemHpke,
    suite: HpkeSuiteId,
    recipient_private_key_seed: &[u8],
    encapsulated_key: &[u8],
    info: &[u8],
) -> Result<ReceiverContext, HpkeError> {
    validate_suite(kem, suite)?;
    let kdf = KdfAlgorithm::from_id(suite.kdf_id).ok_or(HpkeError::UnsupportedKdf)?;
    let aead = AeadAlgorithm::from_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;
    let parameters = AeadParameters::for_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;
    let shared_secret = kem
        .decapsulate(recipient_private_key_seed, encapsulated_key)
        .map_err(map_kem_error)?;
    let schedule = key_schedule(
        suite,
        kdf,
        parameters,
        KeyScheduleInputs {
            mode: HpkeMode::Base,
            shared_secret: &shared_secret,
            info,
            psk: b"",
            psk_id: b"",
        },
    )?;
    Ok(ReceiverContext::new(suite, kdf, aead, schedule))
}

fn validate_suite(kem: MlKemHpke, suite: HpkeSuiteId) -> Result<(), HpkeError> {
    if suite.kem_id != kem.kem_id() {
        return Err(HpkeError::KemIdentifierMismatch);
    }
    Ok(())
}

fn map_kem_error(_error: MlKemHpkeError) -> HpkeError {
    HpkeError::KemError
}
