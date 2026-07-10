//! Deterministic intermediate-value capture for K-PKE validation.
//!
//! These records are internal golden fixtures. They are not official FIPS 203
//! vectors and must not be used to claim conformance.

use crate::kpke::{EncryptionRandomness, Message};
use crate::kpke_encrypt;
use crate::kpke_keygen;
use crate::matrix::expand_matrix;
use crate::packing::decode_public_key_component;
use crate::poly::Poly;
use crate::MlKemParameterSet;
use pqc_core::PqcResult;

/// Compact digest-based summary of one polynomial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolynomialDigest {
    /// SHA3-256 digest of the 12-bit polynomial encoding.
    pub digest: [u8; 32],
}

impl PolynomialDigest {
    /// Build a digest from a polynomial.
    pub fn from_poly(poly: &Poly) -> Self {
        Self {
            digest: crate::symmetric::h(&poly.encode_12()),
        }
    }
}

/// Internal intermediate-value fixture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntermediateFixture {
    /// Fixture identifier.
    pub id: &'static str,
    /// Parameter set.
    pub parameter_set: MlKemParameterSet,
    /// Input key-generation seed.
    pub keygen_seed: [u8; 32],
    /// Expanded public matrix seed.
    pub rho: [u8; 32],
    /// Expanded noise seed.
    pub sigma: [u8; 32],
    /// Input message bytes.
    pub message: [u8; 32],
    /// Encryption randomness bytes.
    pub encryption_randomness: [u8; 32],
    /// Digest of the first expanded matrix entry.
    pub matrix_00_digest: PolynomialDigest,
    /// Digest of the first secret polynomial.
    pub secret_0_digest: PolynomialDigest,
    /// Digest of the first error polynomial.
    pub error_0_digest: PolynomialDigest,
    /// Public-key bytes.
    pub public_key: Vec<u8>,
    /// CPA secret-key component bytes.
    pub secret_key: Vec<u8>,
    /// Ciphertext bytes.
    pub ciphertext: Vec<u8>,
}

/// Build an internal fixture for ML-KEM-512.
pub fn build_ml_kem_512_fixture() -> PqcResult<IntermediateFixture> {
    build_fixture::<800, 768, 768>(
        "stage6-4-acvp-keygen-ml-kem-512",
        MlKemParameterSet::MlKem512,
        [0x11u8; 32],
        [0x22u8; 32],
        [0x33u8; 32],
    )
}

/// Build an internal fixture for ML-KEM-768.
pub fn build_ml_kem_768_fixture() -> PqcResult<IntermediateFixture> {
    build_fixture::<1184, 1152, 1088>(
        "stage6-4-acvp-keygen-ml-kem-768",
        MlKemParameterSet::MlKem768,
        [0x44u8; 32],
        [0x55u8; 32],
        [0x66u8; 32],
    )
}

/// Build an internal fixture for ML-KEM-1024.
pub fn build_ml_kem_1024_fixture() -> PqcResult<IntermediateFixture> {
    build_fixture::<1568, 1536, 1568>(
        "stage6-4-acvp-keygen-ml-kem-1024",
        MlKemParameterSet::MlKem1024,
        [0x77u8; 32],
        [0x88u8; 32],
        [0x99u8; 32],
    )
}

fn build_fixture<const PK: usize, const SK: usize, const CT: usize>(
    id: &'static str,
    parameter_set: MlKemParameterSet,
    keygen_seed: [u8; 32],
    message_bytes: [u8; 32],
    encryption_randomness_bytes: [u8; 32],
) -> PqcResult<IntermediateFixture> {
    let seed_material =
        kpke_keygen::expand_keygen_seed_for_parameter_set(parameter_set, &keygen_seed);
    let matrix = expand_matrix(parameter_set.k(), &seed_material.rho, false);
    let secret = kpke_keygen::sample_noise_vector(parameter_set, &seed_material.sigma, 0);
    let error = kpke_keygen::sample_noise_vector(
        parameter_set,
        &seed_material.sigma,
        parameter_set.k() as u8,
    );

    let keypair = kpke_keygen::keygen_from_seed::<PK, SK>(parameter_set, &keygen_seed)?;

    let message = Message::new(message_bytes);
    let randomness = EncryptionRandomness::new(encryption_randomness_bytes);

    let ciphertext = kpke_encrypt::encrypt_from_randomness::<CT>(
        parameter_set,
        &keypair.public_key,
        &message,
        &randomness,
    )?;

    let (_, decoded_rho) = decode_public_key_component(parameter_set, &keypair.public_key)?;

    debug_assert_eq!(decoded_rho, seed_material.rho);

    Ok(IntermediateFixture {
        id,
        parameter_set,
        keygen_seed,
        rho: seed_material.rho,
        sigma: seed_material.sigma,
        message: message_bytes,
        encryption_randomness: encryption_randomness_bytes,
        matrix_00_digest: PolynomialDigest::from_poly(matrix.get(0, 0)),
        secret_0_digest: PolynomialDigest::from_poly(&secret.as_slice()[0]),
        error_0_digest: PolynomialDigest::from_poly(&error.as_slice()[0]),
        public_key: keypair.public_key.to_vec(),
        secret_key: keypair.secret_key.to_vec(),
        ciphertext: ciphertext.ciphertext.to_vec(),
    })
}

/// Return the expected public-key length for a fixture.
pub const fn expected_public_key_length(parameter_set: MlKemParameterSet) -> usize {
    parameter_set.public_key_bytes()
}

/// Return the expected CPA secret-key component length.
pub const fn expected_cpa_secret_key_length(parameter_set: MlKemParameterSet) -> usize {
    parameter_set.k() * 384
}

/// Return the expected ciphertext length.
pub const fn expected_ciphertext_length(parameter_set: MlKemParameterSet) -> usize {
    parameter_set.ciphertext_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_fixture_shape(fixture: &IntermediateFixture) {
        assert_eq!(
            fixture.public_key.len(),
            expected_public_key_length(fixture.parameter_set),
        );
        assert_eq!(
            fixture.secret_key.len(),
            expected_cpa_secret_key_length(fixture.parameter_set),
        );
        assert_eq!(
            fixture.ciphertext.len(),
            expected_ciphertext_length(fixture.parameter_set),
        );
    }

    #[test]
    fn fixture_512_is_deterministic_and_well_formed() {
        let first = build_ml_kem_512_fixture().unwrap();
        let second = build_ml_kem_512_fixture().unwrap();

        assert_eq!(first, second);
        assert_fixture_shape(&first);
        assert_eq!(first.id, "stage6-4-acvp-keygen-ml-kem-512");
    }

    #[test]
    fn fixture_768_is_deterministic_and_well_formed() {
        let first = build_ml_kem_768_fixture().unwrap();
        let second = build_ml_kem_768_fixture().unwrap();

        assert_eq!(first, second);
        assert_fixture_shape(&first);
        assert_eq!(first.id, "stage6-4-acvp-keygen-ml-kem-768");
    }

    #[test]
    fn fixture_1024_is_deterministic_and_well_formed() {
        let first = build_ml_kem_1024_fixture().unwrap();
        let second = build_ml_kem_1024_fixture().unwrap();

        assert_eq!(first, second);
        assert_fixture_shape(&first);
        assert_eq!(first.id, "stage6-4-acvp-keygen-ml-kem-1024");
    }

    #[test]
    fn fixture_public_keys_end_with_their_rho_seed() {
        for fixture in [
            build_ml_kem_512_fixture().unwrap(),
            build_ml_kem_768_fixture().unwrap(),
            build_ml_kem_1024_fixture().unwrap(),
        ] {
            let rho_offset = fixture.public_key.len() - 32;
            assert_eq!(&fixture.public_key[rho_offset..], fixture.rho);
        }
    }

    #[test]
    fn parameter_sets_produce_distinct_fixture_digests() {
        let a = build_ml_kem_512_fixture().unwrap();
        let b = build_ml_kem_768_fixture().unwrap();
        let c = build_ml_kem_1024_fixture().unwrap();

        assert_ne!(a.matrix_00_digest, b.matrix_00_digest);
        assert_ne!(b.matrix_00_digest, c.matrix_00_digest);
        assert_ne!(a.secret_0_digest, c.secret_0_digest);
    }
}
