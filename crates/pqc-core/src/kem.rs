//! KEM abstraction.

use rand_core::{CryptoRng, RngCore};

use crate::error::PqcResult;

/// Key encapsulation mechanism interface.
pub trait Kem {
    /// Public key type.
    type PublicKey;
    /// Secret key type.
    type SecretKey;
    /// Ciphertext type.
    type Ciphertext;
    /// Shared-secret type.
    type SharedSecret;

    /// Generate a key pair.
    fn keygen<R>(rng: &mut R) -> PqcResult<(Self::PublicKey, Self::SecretKey)>
    where
        R: CryptoRng + RngCore;

    /// Encapsulate to a public key.
    fn encaps<R>(
        public_key: &Self::PublicKey,
        rng: &mut R,
    ) -> PqcResult<(Self::Ciphertext, Self::SharedSecret)>
    where
        R: CryptoRng + RngCore;

    /// Decapsulate a ciphertext.
    fn decaps(
        secret_key: &Self::SecretKey,
        ciphertext: &Self::Ciphertext,
    ) -> PqcResult<Self::SharedSecret>;
}
