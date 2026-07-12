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

    /// Return the next sequence number.
    pub const fn sequence_number(&self) -> u64 {
        self.state.sequence_number
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

    /// Return the next sequence number.
    pub const fn sequence_number(&self) -> u64 {
        self.state.sequence_number
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
        }
    }

    fn compute_nonce(&self) -> Result<Vec<u8>, HpkeError> {
        if self.sequence_number == u64::MAX {
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
        self.sequence_number = self
            .sequence_number
            .checked_add(1)
            .ok_or(HpkeError::MessageLimitReached)?;
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
    }
}
