//! K-PKE boundary for ML-KEM.
//!
//! This module defines the typed sizes and API boundary for the public-key
//! encryption component underneath ML-KEM. The implementation remains a scaffold
//! until Stage 5 wires in matrix expansion, NTT-domain arithmetic, and official
//! FIPS 203 test vectors.

use pqc_core::{CiphertextBytes, PqcResult, PublicKeyBytes, SecretKeyBytes, SharedSecretBytes};

use crate::{
    MlKem1024Ciphertext, MlKem1024PublicKey, MlKem1024SecretKey, MlKem512Ciphertext,
    MlKem512PublicKey, MlKem512SecretKey, MlKem768Ciphertext, MlKem768PublicKey, MlKem768SecretKey,
    MlKemParameterSet,
};

/// K-PKE plaintext message size in bytes.
pub const MESSAGE_BYTES: usize = 32;

/// K-PKE randomness size in bytes.
pub const RANDOMNESS_BYTES: usize = 32;

/// K-PKE plaintext message.
pub type Message = SharedSecretBytes<MESSAGE_BYTES>;

/// K-PKE encryption randomness.
pub type EncryptionRandomness = SharedSecretBytes<RANDOMNESS_BYTES>;

/// Trait implemented by parameter-set-specific K-PKE boundaries.
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

/// ML-KEM-512 K-PKE boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Kpke512;

/// ML-KEM-768 K-PKE boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Kpke768;

/// ML-KEM-1024 K-PKE boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Kpke1024;

macro_rules! impl_kpke_scaffold {
    ($scheme:ident, $param:expr, $pk:ty, $sk:ty, $ct:ty, $pk_len:expr, $sk_len:expr, $ct_len:expr) => {
        impl Kpke for $scheme {
            type PublicKey = $pk;
            type SecretKey = $sk;
            type Ciphertext = $ct;

            const PARAMETER_SET: MlKemParameterSet = $param;

            fn keygen_from_seed(seed: &[u8; 32]) -> PqcResult<(Self::PublicKey, Self::SecretKey)> {
                let mut pk = [0u8; $pk_len];
                let mut sk = [0u8; $sk_len];

                fill_scaffold(Self::PARAMETER_SET.name().as_bytes(), seed, b"pk", &mut pk);
                fill_scaffold(Self::PARAMETER_SET.name().as_bytes(), seed, b"sk", &mut sk);

                let copy_len = core::cmp::min($pk_len, $sk_len);
                sk[..copy_len].copy_from_slice(&pk[..copy_len]);

                Ok((PublicKeyBytes::new(pk), SecretKeyBytes::new(sk)))
            }

            fn encrypt(
                public_key: &Self::PublicKey,
                message: &Message,
                randomness: &EncryptionRandomness,
            ) -> PqcResult<Self::Ciphertext> {
                let mut ct = [0u8; $ct_len];
                let mut seed = [0u8; 32];

                let mut i = 0;
                while i < 32 {
                    seed[i] = message.as_bytes()[i] ^ randomness.as_bytes()[i];
                    i += 1;
                }

                fill_scaffold(
                    Self::PARAMETER_SET.name().as_bytes(),
                    &seed,
                    public_key.as_bytes(),
                    &mut ct,
                );

                Ok(CiphertextBytes::new(ct))
            }

            fn decrypt(
                _secret_key: &Self::SecretKey,
                _ciphertext: &Self::Ciphertext,
            ) -> PqcResult<Message> {
                Ok(Message::new([0u8; MESSAGE_BYTES]))
            }
        }
    };
}

impl_kpke_scaffold!(
    Kpke512,
    MlKemParameterSet::MlKem512,
    MlKem512PublicKey,
    MlKem512SecretKey,
    MlKem512Ciphertext,
    800,
    1632,
    768
);

impl_kpke_scaffold!(
    Kpke768,
    MlKemParameterSet::MlKem768,
    MlKem768PublicKey,
    MlKem768SecretKey,
    MlKem768Ciphertext,
    1184,
    2400,
    1088
);

impl_kpke_scaffold!(
    Kpke1024,
    MlKemParameterSet::MlKem1024,
    MlKem1024PublicKey,
    MlKem1024SecretKey,
    MlKem1024Ciphertext,
    1568,
    3168,
    1568
);

fn fill_scaffold(domain: &[u8], seed: &[u8; 32], label: &[u8], out: &mut [u8]) {
    let mut state = [0u8; 32];

    let mut i = 0;
    while i < 32 {
        state[i] = seed[i] ^ domain[i % domain.len()] ^ label[i % label.len()];
        i += 1;
    }

    let mut pos = 0usize;
    let mut ctr = 0u8;
    while pos < out.len() {
        let mut block_input = [0u8; 64];
        block_input[..32].copy_from_slice(&state);
        block_input[32] = ctr;
        let block = crate::symmetric::h(&block_input);

        let take = core::cmp::min(32, out.len() - pos);
        out[pos..pos + take].copy_from_slice(&block[..take]);
        pos += take;
        ctr = ctr.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kpke_keygen_shapes_are_correct() {
        let seed = [9u8; 32];

        let (pk512, sk512) = Kpke512::keygen_from_seed(&seed).unwrap();
        assert_eq!(pk512.as_bytes().len(), 800);
        assert_eq!(sk512.as_bytes().len(), 1632);

        let (pk768, sk768) = Kpke768::keygen_from_seed(&seed).unwrap();
        assert_eq!(pk768.as_bytes().len(), 1184);
        assert_eq!(sk768.as_bytes().len(), 2400);

        let (pk1024, sk1024) = Kpke1024::keygen_from_seed(&seed).unwrap();
        assert_eq!(pk1024.as_bytes().len(), 1568);
        assert_eq!(sk1024.as_bytes().len(), 3168);
    }

    #[test]
    fn kpke_encrypt_shapes_are_correct() {
        let seed = [3u8; 32];
        let msg = Message::new([1u8; 32]);
        let rnd = EncryptionRandomness::new([2u8; 32]);

        let (pk, _) = Kpke768::keygen_from_seed(&seed).unwrap();
        let ct = Kpke768::encrypt(&pk, &msg, &rnd).unwrap();

        assert_eq!(ct.as_bytes().len(), 1088);
    }
}
