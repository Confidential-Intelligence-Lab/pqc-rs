//! RFC 9180 Base- and PSK-mode sender and receiver setup.

use crate::aead::AeadAlgorithm;
use crate::context::{ReceiverContext, SenderContext};
use crate::identifiers::HpkeSuiteId;
use crate::kdf::KdfAlgorithm;
use crate::key_schedule::{key_schedule, AeadParameters, HpkeMode, KeyScheduleInputs};
use crate::ml_kem::{MlKemHpke, MlKemHpkeError};
use crate::HpkeError;

/// Result of deterministic sender setup.
pub struct SenderSetup {
    /// Serialized KEM encapsulation.
    pub encapsulated_key: Vec<u8>,
    /// Sender context.
    pub context: SenderContext,
}

/// Backward-compatible name for Base-mode sender setup.
pub type BaseSenderSetup = SenderSetup;

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
    Ok(SenderSetup {
        encapsulated_key: encapsulation.encapsulated_key,
        context: SenderContext::new(suite, kdf, aead, schedule),
    })
}

/// Build a Base-mode sender context from an already established KEM shared secret.
///
/// This entry point is intended for interoperability harnesses and protocol
/// integrations that obtain the KEM shared secret from an external provider.
pub fn setup_base_sender_from_shared_secret(
    suite: HpkeSuiteId,
    shared_secret: &[u8],
    info: &[u8],
) -> Result<SenderContext, HpkeError> {
    let kdf = KdfAlgorithm::from_id(suite.kdf_id).ok_or(HpkeError::UnsupportedKdf)?;
    let aead = AeadAlgorithm::from_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;
    let parameters = AeadParameters::for_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;
    let schedule = key_schedule(
        suite,
        kdf,
        parameters,
        KeyScheduleInputs {
            mode: HpkeMode::Base,
            shared_secret,
            info,
            psk: b"",
            psk_id: b"",
        },
    )?;
    Ok(SenderContext::new(suite, kdf, aead, schedule))
}

/// Build a Base-mode receiver context from an already established KEM shared secret.
///
/// This is the receiver-side counterpart to
/// [`setup_base_sender_from_shared_secret`].
pub fn setup_base_receiver_from_shared_secret(
    suite: HpkeSuiteId,
    shared_secret: &[u8],
    info: &[u8],
) -> Result<ReceiverContext, HpkeError> {
    let kdf = KdfAlgorithm::from_id(suite.kdf_id).ok_or(HpkeError::UnsupportedKdf)?;
    let aead = AeadAlgorithm::from_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;
    let parameters = AeadParameters::for_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;
    let schedule = key_schedule(
        suite,
        kdf,
        parameters,
        KeyScheduleInputs {
            mode: HpkeMode::Base,
            shared_secret,
            info,
            psk: b"",
            psk_id: b"",
        },
    )?;
    Ok(ReceiverContext::new(suite, kdf, aead, schedule))
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

/// Deterministically execute `SetupPSKS` for an ML-KEM HPKE suite.
///
/// RFC 9180 requires both `psk` and `psk_id` to be non-empty in PSK mode.
pub fn setup_psk_sender_deterministic(
    kem: MlKemHpke,
    suite: HpkeSuiteId,
    recipient_public_key: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
    randomness: &[u8; 32],
) -> Result<SenderSetup, HpkeError> {
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
            mode: HpkeMode::Psk,
            shared_secret: encapsulation.shared_secret.as_bytes(),
            info,
            psk,
            psk_id,
        },
    )?;
    Ok(SenderSetup {
        encapsulated_key: encapsulation.encapsulated_key,
        context: SenderContext::new(suite, kdf, aead, schedule),
    })
}

/// Execute `SetupPSKR` for an ML-KEM HPKE suite.
///
/// RFC 9180 requires both `psk` and `psk_id` to be non-empty in PSK mode.
pub fn setup_psk_receiver(
    kem: MlKemHpke,
    suite: HpkeSuiteId,
    recipient_private_key_seed: &[u8],
    encapsulated_key: &[u8],
    info: &[u8],
    psk: &[u8],
    psk_id: &[u8],
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
            mode: HpkeMode::Psk,
            shared_secret: &shared_secret,
            info,
            psk,
            psk_id,
        },
    )?;
    Ok(ReceiverContext::new(suite, kdf, aead, schedule))
}
