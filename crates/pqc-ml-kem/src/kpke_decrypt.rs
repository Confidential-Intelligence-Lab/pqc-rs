//! Deterministic K-PKE decryption structure for ML-KEM.
//!
//! Stage 5B-8 wires ciphertext decoding, secret-key decoding, structural
//! polynomial-vector arithmetic, and message recovery. It remains structural
//! because ciphertext compression is lossy and the current arithmetic path is not
//! yet official-KAT-complete.

use pqc_core::{PqcError, PqcResult};

use crate::encoding::poly_to_message;
use crate::kpke::Message;
use crate::kpke_ntt_domain::NttPolyVec;
use crate::packing::{
    ciphertext_component_bytes, decode_ciphertext_components, decode_secret_key_component,
};
use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::MlKemParameterSet;

/// Structural K-PKE decryption output.
#[derive(Clone, Debug)]
pub struct KpkeDecryptOutput {
    /// Recovered message.
    pub message: Message,
}

/// Compute structural `w = v - s^T u`.
pub fn compute_message_poly(s_hat: &PolyVec, u: &PolyVec, v: &Poly) -> Poly {
    assert_eq!(s_hat.rank(), u.rank());

    let secret_hat = NttPolyVec::from_sampled_ntt_polyvec(s_hat);
    let u_hat = NttPolyVec::from_polyvec(u);
    let product = crate::kpke_ntt_domain::dot_to_poly(&secret_hat, &u_hat);
    v.sub(&product)
}

/// Deterministic structural K-PKE decryption.
pub fn decrypt_to_message(
    parameter_set: MlKemParameterSet,
    secret_key: &[u8],
    ciphertext: &[u8],
) -> PqcResult<KpkeDecryptOutput> {
    let expected_ct = ciphertext_component_bytes(parameter_set);
    if ciphertext.len() != expected_ct {
        return Err(PqcError::InvalidLength {
            expected: expected_ct,
            actual: ciphertext.len(),
        });
    }

    let s_hat = decode_secret_key_component(parameter_set, secret_key)?;
    let (u, v) = decode_ciphertext_components(parameter_set, ciphertext)?;
    let message_poly = compute_message_poly(&s_hat, &u, &v);
    let message = poly_to_message(&message_poly);

    Ok(KpkeDecryptOutput { message })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kpke::EncryptionRandomness;
    use crate::kpke_encrypt;
    use crate::kpke_keygen;

    #[test]
    fn compute_message_poly_has_expected_shape() {
        let zero_vec = PolyVec::zero(2);
        let v = Poly::zero();
        let out = compute_message_poly(&zero_vec, &zero_vec, &v);
        assert_eq!(out, Poly::zero());
    }

    #[test]
    fn decrypt_512_has_message_shape() {
        let seed = [1u8; 32];
        let keypair =
            kpke_keygen::keygen_from_seed::<800, 768>(MlKemParameterSet::MlKem512, &seed).unwrap();

        let message = Message::new([7u8; 32]);
        let randomness = EncryptionRandomness::new([8u8; 32]);

        let ciphertext = kpke_encrypt::encrypt_from_randomness::<768>(
            MlKemParameterSet::MlKem512,
            &keypair.public_key,
            &message,
            &randomness,
        )
        .unwrap();

        let decrypted = decrypt_to_message(
            MlKemParameterSet::MlKem512,
            &keypair.secret_key,
            &ciphertext.ciphertext,
        )
        .unwrap();

        assert_eq!(decrypted.message.as_bytes().len(), 32);
    }

    #[test]
    fn decrypt_768_has_message_shape() {
        let seed = [2u8; 32];
        let keypair =
            kpke_keygen::keygen_from_seed::<1184, 1152>(MlKemParameterSet::MlKem768, &seed)
                .unwrap();

        let message = Message::new([9u8; 32]);
        let randomness = EncryptionRandomness::new([10u8; 32]);

        let ciphertext = kpke_encrypt::encrypt_from_randomness::<1088>(
            MlKemParameterSet::MlKem768,
            &keypair.public_key,
            &message,
            &randomness,
        )
        .unwrap();

        let decrypted = decrypt_to_message(
            MlKemParameterSet::MlKem768,
            &keypair.secret_key,
            &ciphertext.ciphertext,
        )
        .unwrap();

        assert_eq!(decrypted.message.as_bytes().len(), 32);
    }

    #[test]
    fn wrong_ciphertext_length_is_rejected() {
        let seed = [1u8; 32];
        let keypair =
            kpke_keygen::keygen_from_seed::<800, 768>(MlKemParameterSet::MlKem512, &seed).unwrap();

        assert!(decrypt_to_message(
            MlKemParameterSet::MlKem512,
            &keypair.secret_key,
            &[0u8; 767]
        )
        .is_err());
    }

    #[test]
    fn wrong_secret_key_length_is_rejected() {
        let ciphertext = [0u8; 768];
        assert!(decrypt_to_message(MlKemParameterSet::MlKem512, &[0u8; 767], &ciphertext).is_err());
    }
}
