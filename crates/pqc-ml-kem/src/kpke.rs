//! K-PKE abstraction for ML-KEM.

use pqc_core::{PqcResult, SharedSecretBytes};

use crate::MlKemParameterSet;

/// K-PKE plaintext message size in bytes.
pub const MESSAGE_BYTES: usize = 32;

/// K-PKE randomness size in bytes.
pub const RANDOMNESS_BYTES: usize = 32;

/// K-PKE plaintext message.
pub type Message = SharedSecretBytes<MESSAGE_BYTES>;

/// K-PKE encryption randomness.
pub type EncryptionRandomness = SharedSecretBytes<RANDOMNESS_BYTES>;

/// Trait implemented by parameter-set-specific K-PKE backends.
pub trait Kpke {
    /// Public encryption key.
    type PublicKey;
    /// Secret decryption key.
    type SecretKey;
    /// Ciphertext.
    type Ciphertext;

    /// Parameter set.
    const PARAMETER_SET: MlKemParameterSet;

    /// Generate a K-PKE key pair from seed material.
    fn keygen_from_seed(seed: &[u8; 32]) -> PqcResult<(Self::PublicKey, Self::SecretKey)>;

    /// Encrypt a message with explicit randomness.
    fn encrypt(
        public_key: &Self::PublicKey,
        message: &Message,
        randomness: &EncryptionRandomness,
    ) -> PqcResult<Self::Ciphertext>;

    /// Decrypt a ciphertext.
    fn decrypt(secret_key: &Self::SecretKey, ciphertext: &Self::Ciphertext) -> PqcResult<Message>;
}
