//! RFC 9180 sender and receiver context state.

use zeroize::Zeroize;

use crate::aead::AeadAlgorithm;
use crate::identifiers::HpkeSuiteId;
use crate::kdf::KdfAlgorithm;
use crate::key_schedule::KeyScheduleOutput;
use crate::HpkeError;

/// Sender-side HPKE context.
pub struct SenderContext {
    state: ContextState,
}

/// Receiver-side HPKE context.
pub struct ReceiverContext {
    state: ContextState,
}

struct ContextState {
    suite: HpkeSuiteId,
    kdf: KdfAlgorithm,
    aead: AeadAlgorithm,
    key: Vec<u8>,
    base_nonce: Vec<u8>,
    sequence_number: u64,
    exporter_secret: Vec<u8>,
    exhausted: bool,
}

impl SenderContext {
    pub(crate) fn new(
        suite: HpkeSuiteId,
        kdf: KdfAlgorithm,
        aead: AeadAlgorithm,
        schedule: KeyScheduleOutput,
    ) -> Self {
        Self {
            state: ContextState::new(suite, kdf, aead, schedule),
        }
    }

    /// Encrypt and authenticate one plaintext and advance the sequence.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let nonce = self.state.compute_nonce()?;
        let ciphertext = self
            .state
            .aead
            .seal(&self.state.key, &nonce, aad, plaintext)?;
        self.state.increment_sequence()?;
        Ok(ciphertext)
    }

    /// Export a secret from this context.
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, HpkeError> {
        self.state.export(exporter_context, length)
    }

    /// Return the sequence number that will be used by the next message operation.
    ///
    /// When [`Self::is_exhausted`] is true, this value is the final sequence number
    /// that was consumed and must not be used again.
    pub const fn sequence_number(&self) -> u64 {
        self.state.sequence_number
    }

    /// Return whether the context has consumed its final sequence number.
    pub const fn is_exhausted(&self) -> bool {
        self.state.exhausted
    }
}

impl ReceiverContext {
    pub(crate) fn new(
        suite: HpkeSuiteId,
        kdf: KdfAlgorithm,
        aead: AeadAlgorithm,
        schedule: KeyScheduleOutput,
    ) -> Self {
        Self {
            state: ContextState::new(suite, kdf, aead, schedule),
        }
    }

    /// Authenticate and decrypt one ciphertext and advance the sequence.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let nonce = self.state.compute_nonce()?;
        let plaintext = self
            .state
            .aead
            .open(&self.state.key, &nonce, aad, ciphertext)?;
        self.state.increment_sequence()?;
        Ok(plaintext)
    }

    /// Export a secret from this context.
    pub fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, HpkeError> {
        self.state.export(exporter_context, length)
    }

    /// Return the sequence number that will be used by the next message operation.
    ///
    /// When [`Self::is_exhausted`] is true, this value is the final sequence number
    /// that was consumed and must not be used again.
    pub const fn sequence_number(&self) -> u64 {
        self.state.sequence_number
    }

    /// Return whether the context has consumed its final sequence number.
    pub const fn is_exhausted(&self) -> bool {
        self.state.exhausted
    }
}

impl ContextState {
    fn new(
        suite: HpkeSuiteId,
        kdf: KdfAlgorithm,
        aead: AeadAlgorithm,
        schedule: KeyScheduleOutput,
    ) -> Self {
        Self {
            suite,
            kdf,
            aead,
            key: schedule.key.as_bytes().to_vec(),
            base_nonce: schedule.base_nonce,
            sequence_number: schedule.sequence_number,
            exporter_secret: schedule.exporter_secret.as_bytes().to_vec(),
            exhausted: false,
        }
    }

    fn compute_nonce(&self) -> Result<Vec<u8>, HpkeError> {
        if self.exhausted {
            return Err(HpkeError::MessageLimitReached);
        }
        if self.base_nonce.len() < core::mem::size_of::<u64>() {
            return Err(HpkeError::InvalidAeadNonce);
        }
        let mut encoded_sequence = vec![0u8; self.base_nonce.len()];
        let sequence = self.sequence_number.to_be_bytes();
        let offset = encoded_sequence.len() - sequence.len();
        encoded_sequence[offset..].copy_from_slice(&sequence);
        Ok(self
            .base_nonce
            .iter()
            .zip(encoded_sequence)
            .map(|(a, b)| a ^ b)
            .collect())
    }

    fn increment_sequence(&mut self) -> Result<(), HpkeError> {
        if self.sequence_number == u64::MAX {
            self.exhausted = true;
        } else {
            self.sequence_number += 1;
        }
        Ok(())
    }

    fn export(&self, exporter_context: &[u8], length: usize) -> Result<Vec<u8>, HpkeError> {
        self.kdf.labeled_expand(
            &self.suite.to_bytes(),
            &self.exporter_secret,
            b"sec",
            exporter_context,
            length,
        )
    }
}

impl Drop for ContextState {
    fn drop(&mut self) {
        self.key.zeroize();
        self.base_nonce.zeroize();
        self.exporter_secret.zeroize();
        self.sequence_number.zeroize();
        self.exhausted = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identifiers::{AeadId, KdfId, KemId};
    use crate::key_schedule::KeyScheduleOutput;
    use pqc_core::secret::SecretVec;

    fn context_state(sequence_number: u64) -> ContextState {
        ContextState::new(
            HpkeSuiteId {
                kem_id: KemId(0x0041),
                kdf_id: KdfId::HKDF_SHA256,
                aead_id: AeadId::AES_128_GCM,
            },
            KdfAlgorithm::HkdfSha256,
            AeadAlgorithm::Aes128Gcm,
            KeyScheduleOutput {
                key: SecretVec::new(vec![0u8; 16]),
                base_nonce: vec![0u8; 12],
                sequence_number,
                exporter_secret: SecretVec::new(vec![0u8; 32]),
                key_schedule_context: Vec::new(),
                secret: SecretVec::new(vec![0u8; 32]),
            },
        )
    }

    #[test]
    fn final_sequence_number_is_used_once_then_exhausted() {
        let mut state = context_state(u64::MAX);
        assert!(state.compute_nonce().is_ok());
        state.increment_sequence().unwrap();
        assert!(state.exhausted);
        assert_eq!(state.compute_nonce(), Err(HpkeError::MessageLimitReached));
        assert_eq!(state.increment_sequence(), Ok(()));
    }
}
