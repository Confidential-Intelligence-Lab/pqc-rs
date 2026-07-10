//! Structural K-PKE trait implementations.

use pqc_core::{CiphertextBytes, PqcResult, PublicKeyBytes, SecretKeyBytes};

use crate::kpke::{EncryptionRandomness, Kpke, Message};
use crate::{kpke_decrypt, kpke_encrypt, kpke_keygen};
use crate::{
    MlKem1024Ciphertext, MlKem1024PublicKey, MlKem512Ciphertext, MlKem512PublicKey,
    MlKem768Ciphertext, MlKem768PublicKey, MlKemParameterSet,
};

/// Structural ML-KEM-512 CPA secret-key component.
pub type StructuralKpke512SecretKey = SecretKeyBytes<768>;

/// Structural ML-KEM-768 CPA secret-key component.
pub type StructuralKpke768SecretKey = SecretKeyBytes<1152>;

/// Structural ML-KEM-1024 CPA secret-key component.
pub type StructuralKpke1024SecretKey = SecretKeyBytes<1536>;

/// Structural ML-KEM-512 K-PKE backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StructuralKpke512;

/// Structural ML-KEM-768 K-PKE backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StructuralKpke768;

/// Structural ML-KEM-1024 K-PKE backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StructuralKpke1024;

macro_rules! impl_structural_kpke {
    (
        $scheme:ident,
        $param:expr,
        $pk:ty,
        $sk:ty,
        $ct:ty,
        $pk_len:expr,
        $sk_len:expr,
        $ct_len:expr
    ) => {
        impl Kpke for $scheme {
            type PublicKey = $pk;
            type SecretKey = $sk;
            type Ciphertext = $ct;

            const PARAMETER_SET: MlKemParameterSet = $param;

            fn keygen_from_seed(seed: &[u8; 32]) -> PqcResult<(Self::PublicKey, Self::SecretKey)> {
                let out =
                    kpke_keygen::keygen_from_seed::<$pk_len, $sk_len>(Self::PARAMETER_SET, seed)?;

                Ok((
                    PublicKeyBytes::new(out.public_key),
                    SecretKeyBytes::new(out.secret_key),
                ))
            }

            fn encrypt(
                public_key: &Self::PublicKey,
                message: &Message,
                randomness: &EncryptionRandomness,
            ) -> PqcResult<Self::Ciphertext> {
                let out = kpke_encrypt::encrypt_from_randomness::<$ct_len>(
                    Self::PARAMETER_SET,
                    public_key.as_bytes(),
                    message,
                    randomness,
                )?;

                Ok(CiphertextBytes::new(out.ciphertext))
            }

            fn decrypt(
                secret_key: &Self::SecretKey,
                ciphertext: &Self::Ciphertext,
            ) -> PqcResult<Message> {
                let out = kpke_decrypt::decrypt_to_message(
                    Self::PARAMETER_SET,
                    secret_key.as_bytes(),
                    ciphertext.as_bytes(),
                )?;

                Ok(out.message)
            }
        }
    };
}

impl_structural_kpke!(
    StructuralKpke512,
    MlKemParameterSet::MlKem512,
    MlKem512PublicKey,
    StructuralKpke512SecretKey,
    MlKem512Ciphertext,
    800,
    768,
    768
);

impl_structural_kpke!(
    StructuralKpke768,
    MlKemParameterSet::MlKem768,
    MlKem768PublicKey,
    StructuralKpke768SecretKey,
    MlKem768Ciphertext,
    1184,
    1152,
    1088
);

impl_structural_kpke!(
    StructuralKpke1024,
    MlKemParameterSet::MlKem1024,
    MlKem1024PublicKey,
    StructuralKpke1024SecretKey,
    MlKem1024Ciphertext,
    1568,
    1536,
    1568
);

#[cfg(test)]
mod tests {
    use super::*;
    use subtle::ConstantTimeEq;

    #[test]
    fn structural_kpke_512_api_runs_end_to_end() {
        let seed = [1u8; 32];
        let (pk, sk) = StructuralKpke512::keygen_from_seed(&seed).unwrap();
        let message = Message::new([2u8; 32]);
        let randomness = EncryptionRandomness::new([3u8; 32]);
        let ct = StructuralKpke512::encrypt(&pk, &message, &randomness).unwrap();
        let recovered = StructuralKpke512::decrypt(&sk, &ct).unwrap();

        assert_eq!(pk.as_bytes().len(), 800);
        assert_eq!(sk.as_bytes().len(), 768);
        assert_eq!(ct.as_bytes().len(), 768);
        assert_eq!(recovered.as_bytes().len(), 32);
        assert_eq!(recovered.ct_eq(&recovered).unwrap_u8(), 1);
    }

    #[test]
    fn structural_kpke_768_api_runs_end_to_end() {
        let seed = [4u8; 32];
        let (pk, sk) = StructuralKpke768::keygen_from_seed(&seed).unwrap();
        let message = Message::new([5u8; 32]);
        let randomness = EncryptionRandomness::new([6u8; 32]);
        let ct = StructuralKpke768::encrypt(&pk, &message, &randomness).unwrap();
        let recovered = StructuralKpke768::decrypt(&sk, &ct).unwrap();

        assert_eq!(pk.as_bytes().len(), 1184);
        assert_eq!(sk.as_bytes().len(), 1152);
        assert_eq!(ct.as_bytes().len(), 1088);
        assert_eq!(recovered.as_bytes().len(), 32);
    }

    #[test]
    fn structural_kpke_1024_api_runs_end_to_end() {
        let seed = [7u8; 32];
        let (pk, sk) = StructuralKpke1024::keygen_from_seed(&seed).unwrap();
        let message = Message::new([8u8; 32]);
        let randomness = EncryptionRandomness::new([9u8; 32]);
        let ct = StructuralKpke1024::encrypt(&pk, &message, &randomness).unwrap();
        let recovered = StructuralKpke1024::decrypt(&sk, &ct).unwrap();

        assert_eq!(pk.as_bytes().len(), 1568);
        assert_eq!(sk.as_bytes().len(), 1536);
        assert_eq!(ct.as_bytes().len(), 1568);
        assert_eq!(recovered.as_bytes().len(), 32);
    }

    #[test]
    fn structural_keygen_is_deterministic() {
        let seed = [11u8; 32];
        let (pk1, sk1) = StructuralKpke768::keygen_from_seed(&seed).unwrap();
        let (pk2, sk2) = StructuralKpke768::keygen_from_seed(&seed).unwrap();

        assert_eq!(pk1.as_bytes(), pk2.as_bytes());
        assert_eq!(sk1.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn structural_encryption_is_deterministic() {
        let seed = [12u8; 32];
        let (pk, _) = StructuralKpke512::keygen_from_seed(&seed).unwrap();
        let message = Message::new([13u8; 32]);
        let randomness = EncryptionRandomness::new([14u8; 32]);

        let ct1 = StructuralKpke512::encrypt(&pk, &message, &randomness).unwrap();
        let ct2 = StructuralKpke512::encrypt(&pk, &message, &randomness).unwrap();

        assert_eq!(ct1.as_bytes(), ct2.as_bytes());
    }
}
