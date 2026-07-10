//! Deterministic K-PKE encryption structure for ML-KEM.
//!
//! Stage 5B-7 wires public-key decoding, encryption-noise sampling, structural
//! polynomial-vector arithmetic, and ciphertext packing. This remains a
//! structural implementation until the verified FIPS-domain arithmetic path is
//! complete.

use pqc_core::{PqcError, PqcResult};

use crate::encoding::message_to_poly;
use crate::kpke::{EncryptionRandomness, Message};
use crate::kpke_arithmetic;
use crate::matrix::expand_matrix;
use crate::packing::{
    ciphertext_component_bytes, decode_public_key_component, encode_ciphertext_components,
};
use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::sampling::cbd_eta2;
use crate::symmetric;
use crate::MlKemParameterSet;

/// Structural K-PKE encryption output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KpkeEncryptOutput<const CT_BYTES: usize> {
    /// Encoded ciphertext component.
    pub ciphertext: [u8; CT_BYTES],
}

/// Sample an `eta2` noise polynomial.
pub fn sample_eta2_poly(sigma: &[u8; 32], nonce: u8) -> Poly {
    let mut buf = [0u8; 128];
    symmetric::prf(sigma, nonce, &mut buf);
    cbd_eta2(&buf)
}

/// Sample an `eta2` noise polynomial vector.
pub fn sample_eta2_vector(
    parameter_set: MlKemParameterSet,
    sigma: &[u8; 32],
    nonce_start: u8,
) -> PolyVec {
    let rank = parameter_set.k();
    let mut polys = [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()];

    let mut i = 0;
    while i < rank {
        polys[i] = sample_eta2_poly(sigma, nonce_start.wrapping_add(i as u8));
        i += 1;
    }

    PolyVec::from_slice(&polys[..rank])
}

/// Compute structural `u = A^T r + e1`.
pub fn compute_u_vector(
    parameter_set: MlKemParameterSet,
    rho: &[u8; 32],
    r: &PolyVec,
    e1: &PolyVec,
) -> PolyVec {
    let rank = parameter_set.k();
    assert_eq!(r.rank(), rank);
    assert_eq!(e1.rank(), rank);

    let transposed_matrix = expand_matrix(rank, rho, true);
    kpke_arithmetic::matrix_vector_mul_add(&transposed_matrix, r, e1)
}

/// Compute structural `v = t^T r + e2 + m`.
pub fn compute_v_poly(t_hat: &PolyVec, r: &PolyVec, e2: &Poly, message: &Message) -> Poly {
    assert_eq!(t_hat.rank(), r.rank());

    let mut acc = kpke_arithmetic::dot(t_hat, r);
    acc = acc.add(e2);
    acc.add(&message_to_poly(message))
}

/// Deterministic structural K-PKE encryption.
pub fn encrypt_from_randomness<const CT_BYTES: usize>(
    parameter_set: MlKemParameterSet,
    public_key: &[u8],
    message: &Message,
    randomness: &EncryptionRandomness,
) -> PqcResult<KpkeEncryptOutput<CT_BYTES>> {
    let expected = ciphertext_component_bytes(parameter_set);
    if CT_BYTES != expected {
        return Err(PqcError::InvalidLength {
            expected,
            actual: CT_BYTES,
        });
    }

    let (t_hat, rho) = decode_public_key_component(parameter_set, public_key)?;

    let mut sigma = [0u8; 32];
    sigma.copy_from_slice(randomness.as_bytes());

    let r = sample_eta2_vector(parameter_set, &sigma, 0);
    let e1 = sample_eta2_vector(parameter_set, &sigma, parameter_set.k() as u8);
    let e2 = sample_eta2_poly(&sigma, (2 * parameter_set.k()) as u8);

    let u = compute_u_vector(parameter_set, &rho, &r, &e1);
    let v = compute_v_poly(&t_hat, &r, &e2, message);

    let ciphertext = encode_ciphertext_components::<CT_BYTES>(parameter_set, &u, &v)?;

    Ok(KpkeEncryptOutput { ciphertext })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kpke_keygen;

    #[test]
    fn eta2_vector_has_expected_rank() {
        let sigma = [4u8; 32];
        let v = sample_eta2_vector(MlKemParameterSet::MlKem1024, &sigma, 0);
        assert_eq!(v.rank(), 4);
    }

    #[test]
    fn encrypt_512_is_deterministic_and_has_correct_shape() {
        let seed = [1u8; 32];
        let keypair =
            kpke_keygen::keygen_from_seed::<800, 768>(MlKemParameterSet::MlKem512, &seed).unwrap();

        let message = Message::new([7u8; 32]);
        let randomness = EncryptionRandomness::new([8u8; 32]);

        let a = encrypt_from_randomness::<768>(
            MlKemParameterSet::MlKem512,
            &keypair.public_key,
            &message,
            &randomness,
        )
        .unwrap();
        let b = encrypt_from_randomness::<768>(
            MlKemParameterSet::MlKem512,
            &keypair.public_key,
            &message,
            &randomness,
        )
        .unwrap();

        assert_eq!(a, b);
        assert_eq!(a.ciphertext.len(), 768);
    }

    #[test]
    fn encrypt_768_is_deterministic_and_has_correct_shape() {
        let seed = [2u8; 32];
        let keypair =
            kpke_keygen::keygen_from_seed::<1184, 1152>(MlKemParameterSet::MlKem768, &seed)
                .unwrap();

        let message = Message::new([9u8; 32]);
        let randomness = EncryptionRandomness::new([10u8; 32]);

        let out = encrypt_from_randomness::<1088>(
            MlKemParameterSet::MlKem768,
            &keypair.public_key,
            &message,
            &randomness,
        )
        .unwrap();

        assert_eq!(out.ciphertext.len(), 1088);
    }

    #[test]
    fn encrypt_1024_is_deterministic_and_has_correct_shape() {
        let seed = [3u8; 32];
        let keypair =
            kpke_keygen::keygen_from_seed::<1568, 1536>(MlKemParameterSet::MlKem1024, &seed)
                .unwrap();

        let message = Message::new([11u8; 32]);
        let randomness = EncryptionRandomness::new([12u8; 32]);

        let out = encrypt_from_randomness::<1568>(
            MlKemParameterSet::MlKem1024,
            &keypair.public_key,
            &message,
            &randomness,
        )
        .unwrap();

        assert_eq!(out.ciphertext.len(), 1568);
    }

    #[test]
    fn wrong_ciphertext_length_is_rejected() {
        let seed = [1u8; 32];
        let keypair =
            kpke_keygen::keygen_from_seed::<800, 768>(MlKemParameterSet::MlKem512, &seed).unwrap();

        let message = Message::new([0u8; 32]);
        let randomness = EncryptionRandomness::new([0u8; 32]);

        assert!(encrypt_from_randomness::<767>(
            MlKemParameterSet::MlKem512,
            &keypair.public_key,
            &message,
            &randomness,
        )
        .is_err());
    }

    #[test]
    fn malformed_public_key_is_rejected() {
        let message = Message::new([0u8; 32]);
        let randomness = EncryptionRandomness::new([0u8; 32]);

        assert!(encrypt_from_randomness::<768>(
            MlKemParameterSet::MlKem512,
            &[0u8; 799],
            &message,
            &randomness,
        )
        .is_err());
    }
}
