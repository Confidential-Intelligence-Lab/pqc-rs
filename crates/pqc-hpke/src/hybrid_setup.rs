//! Base-mode HPKE setup for PQ/traditional hybrid KEMs.

use rand_core::{CryptoRng, RngCore};

use crate::aead::AeadAlgorithm;
use crate::context::{ReceiverContext, SenderContext};
use crate::hybrid_kem::{HybridKem, HybridKemError};
use crate::identifiers::HpkeSuiteId;
use crate::kdf::KdfAlgorithm;
use crate::key_schedule::{key_schedule, AeadParameters, HpkeMode, KeyScheduleInputs};
use crate::HpkeError;

/// Result of deterministic hybrid Base sender setup.
pub struct HybridBaseSenderSetup {
    /// Serialized hybrid KEM ciphertext.
    pub encapsulated_key: Vec<u8>,
    /// Sender context.
    pub context: SenderContext,
}

/// Set up a hybrid Base-mode sender using fresh caller-supplied
/// cryptographic randomness.
pub fn setup_hybrid_base_sender<R>(
    kem: HybridKem,
    suite: HpkeSuiteId,
    recipient_public_key: &[u8],
    info: &[u8],
    rng: &mut R,
) -> Result<HybridBaseSenderSetup, HpkeError>
where
    R: CryptoRng + RngCore,
{
    let mut randomness = vec![0_u8; kem.randomness_length()];
    rng.try_fill_bytes(&mut randomness)
        .map_err(|_| HpkeError::RandomnessFailure)?;

    setup_hybrid_base_sender_deterministic(kem, suite, recipient_public_key, info, &randomness)
}

/// Deterministically set up a hybrid Base-mode sender.
pub fn setup_hybrid_base_sender_deterministic(
    kem: HybridKem,
    suite: HpkeSuiteId,
    recipient_public_key: &[u8],
    info: &[u8],
    randomness: &[u8],
) -> Result<HybridBaseSenderSetup, HpkeError> {
    validate_suite(kem, suite)?;
    let kdf = KdfAlgorithm::from_id(suite.kdf_id).ok_or(HpkeError::UnsupportedKdf)?;
    let aead = AeadAlgorithm::from_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;
    let parameters = AeadParameters::for_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;

    let encapsulation = kem
        .encapsulate_deterministic(recipient_public_key, randomness)
        .map_err(map_hybrid_error)?;

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

    Ok(HybridBaseSenderSetup {
        encapsulated_key: encapsulation.encapsulated_key,
        context: SenderContext::new(suite, kdf, aead, schedule),
    })
}

/// Set up a hybrid Base-mode receiver.
pub fn setup_hybrid_base_receiver(
    kem: HybridKem,
    suite: HpkeSuiteId,
    recipient_private_seed: &[u8],
    encapsulated_key: &[u8],
    info: &[u8],
) -> Result<ReceiverContext, HpkeError> {
    validate_suite(kem, suite)?;
    let kdf = KdfAlgorithm::from_id(suite.kdf_id).ok_or(HpkeError::UnsupportedKdf)?;
    let aead = AeadAlgorithm::from_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;
    let parameters = AeadParameters::for_id(suite.aead_id).ok_or(HpkeError::UnsupportedAead)?;

    let shared_secret = kem
        .decapsulate(recipient_private_seed, encapsulated_key)
        .map_err(map_hybrid_error)?;

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

fn validate_suite(kem: HybridKem, suite: HpkeSuiteId) -> Result<(), HpkeError> {
    if suite.kem_id != kem.kem_id() {
        return Err(HpkeError::KemIdentifierMismatch);
    }
    Ok(())
}

fn map_hybrid_error(_error: HybridKemError) -> HpkeError {
    HpkeError::KemError
}
