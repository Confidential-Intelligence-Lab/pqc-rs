//! Digital signature abstraction.

use rand_core::{CryptoRng, RngCore};

use crate::error::PqcResult;

/// Digital signature scheme interface.
pub trait SignatureScheme {
    /// Public verification key type.
    type PublicKey;
    /// Secret signing key type.
    type SecretKey;
    /// Signature type.
    type Signature;

    /// Generate a signing key pair.
    fn keygen<R>(&self, rng: &mut R) -> PqcResult<(Self::PublicKey, Self::SecretKey)>
    where
        R: CryptoRng + RngCore;

    /// Sign a message with an optional context string.
    fn sign<R>(
        &self,
        secret_key: &Self::SecretKey,
        message: &[u8],
        context: &[u8],
        rng: &mut R,
    ) -> PqcResult<Self::Signature>
    where
        R: CryptoRng + RngCore;

    /// Verify a signature with an optional context string.
    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        context: &[u8],
        signature: &Self::Signature,
    ) -> PqcResult<()>;
}
