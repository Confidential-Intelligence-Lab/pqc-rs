//! Deterministic K-PKE key-generation structure for ML-KEM.
//!
//! Stage 5B-6 introduces a deterministic K-PKE key-generation path that wires
//! seed expansion, matrix expansion, noise-vector generation, polynomial-vector
//! arithmetic, and packing helpers. This is still a structural implementation;
//! Stage 5B-7 should replace remaining schoolbook/facade arithmetic with the
//! verified FIPS-domain path.

use pqc_core::{PqcError, PqcResult};

use crate::kpke_arithmetic;
use crate::matrix::expand_matrix;
use crate::packing::{
    encode_public_key_component, encode_secret_key_component, public_key_component_bytes,
    secret_key_component_bytes,
};
use crate::poly::Poly;
use crate::polyvec::PolyVec;
use crate::sampling::{cbd_eta2, cbd_eta3};
use crate::symmetric;
use crate::MlKemParameterSet;

/// Expanded K-PKE key-generation seed material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KpkeSeedMaterial {
    /// Public matrix seed.
    pub rho: [u8; 32],
    /// Noise seed.
    pub sigma: [u8; 32],
}

/// Structural K-PKE key-generation output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KpkeKeygenOutput<const PK_BYTES: usize, const SK_BYTES: usize> {
    /// Encoded public key component.
    pub public_key: [u8; PK_BYTES],
    /// Encoded CPA secret-key component.
    pub secret_key: [u8; SK_BYTES],
    /// Public matrix seed.
    pub rho: [u8; 32],
}

/// Expand 32-byte entropy into `rho` and `sigma`.
pub fn expand_keygen_seed(seed: &[u8; 32]) -> KpkeSeedMaterial {
    let expanded = symmetric::g(seed);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];

    rho.copy_from_slice(&expanded[..32]);
    sigma.copy_from_slice(&expanded[32..]);

    KpkeSeedMaterial { rho, sigma }
}

/// Generate a secret/noise polynomial for a parameter set and nonce.
pub fn sample_noise_poly(parameter_set: MlKemParameterSet, sigma: &[u8; 32], nonce: u8) -> Poly {
    match parameter_set.eta1() {
        2 => {
            let mut buf = [0u8; 128];
            symmetric::prf(sigma, nonce, &mut buf);
            cbd_eta2(&buf)
        }
        3 => {
            let mut buf = [0u8; 192];
            symmetric::prf(sigma, nonce, &mut buf);
            cbd_eta3(&buf)
        }
        _ => unreachable!("unsupported eta1"),
    }
}

/// Generate a polynomial vector of noise samples.
pub fn sample_noise_vector(
    parameter_set: MlKemParameterSet,
    sigma: &[u8; 32],
    nonce_start: u8,
) -> PolyVec {
    let rank = parameter_set.k();
    let mut polys = [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()];

    let mut i = 0;
    while i < rank {
        polys[i] = sample_noise_poly(parameter_set, sigma, nonce_start.wrapping_add(i as u8));
        i += 1;
    }

    PolyVec::from_slice(&polys[..rank])
}

/// Compute a structural public vector `t = A * s + e`.
pub fn compute_public_vector(
    matrix_rank: usize,
    a: &crate::matrix::PolyMatrix,
    s: &PolyVec,
    e: &PolyVec,
) -> PolyVec {
    assert_eq!(matrix_rank, a.rank());
    assert_eq!(matrix_rank, s.rank());
    assert_eq!(matrix_rank, e.rank());

    kpke_arithmetic::matrix_vector_mul_add(a, s, e)
}

/// Deterministic structural K-PKE key generation.
pub fn keygen_from_seed<const PK_BYTES: usize, const SK_BYTES: usize>(
    parameter_set: MlKemParameterSet,
    seed: &[u8; 32],
) -> PqcResult<KpkeKeygenOutput<PK_BYTES, SK_BYTES>> {
    let expected_pk = public_key_component_bytes(parameter_set);
    if PK_BYTES != expected_pk {
        return Err(PqcError::InvalidLength {
            expected: expected_pk,
            actual: PK_BYTES,
        });
    }

    let expected_sk = secret_key_component_bytes(parameter_set);
    if SK_BYTES != expected_sk {
        return Err(PqcError::InvalidLength {
            expected: expected_sk,
            actual: SK_BYTES,
        });
    }

    let seed_material = expand_keygen_seed(seed);
    let matrix = expand_matrix(parameter_set.k(), &seed_material.rho, false);
    let s = sample_noise_vector(parameter_set, &seed_material.sigma, 0);
    let e = sample_noise_vector(parameter_set, &seed_material.sigma, parameter_set.k() as u8);
    let t = compute_public_vector(parameter_set.k(), &matrix, &s, &e);

    let public_key =
        encode_public_key_component::<PK_BYTES>(parameter_set, &t, &seed_material.rho)?;
    let secret_key = encode_secret_key_component::<SK_BYTES>(parameter_set, &s)?;

    Ok(KpkeKeygenOutput {
        public_key,
        secret_key,
        rho: seed_material.rho,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_expansion_is_deterministic() {
        let seed = [5u8; 32];
        assert_eq!(expand_keygen_seed(&seed), expand_keygen_seed(&seed));
    }

    #[test]
    fn noise_vector_has_expected_rank() {
        let seed = [9u8; 32];
        let expanded = expand_keygen_seed(&seed);
        let s = sample_noise_vector(MlKemParameterSet::MlKem768, &expanded.sigma, 0);
        assert_eq!(s.rank(), 3);
    }

    #[test]
    fn keygen_512_shapes_are_correct_and_deterministic() {
        let seed = [1u8; 32];

        let a = keygen_from_seed::<800, 768>(MlKemParameterSet::MlKem512, &seed).unwrap();
        let b = keygen_from_seed::<800, 768>(MlKemParameterSet::MlKem512, &seed).unwrap();

        assert_eq!(a, b);
        assert_eq!(a.public_key.len(), 800);
        assert_eq!(a.secret_key.len(), 768);
    }

    #[test]
    fn keygen_768_shapes_are_correct_and_deterministic() {
        let seed = [2u8; 32];

        let a = keygen_from_seed::<1184, 1152>(MlKemParameterSet::MlKem768, &seed).unwrap();
        let b = keygen_from_seed::<1184, 1152>(MlKemParameterSet::MlKem768, &seed).unwrap();

        assert_eq!(a, b);
        assert_eq!(a.public_key.len(), 1184);
        assert_eq!(a.secret_key.len(), 1152);
    }

    #[test]
    fn keygen_1024_shapes_are_correct_and_deterministic() {
        let seed = [3u8; 32];

        let a = keygen_from_seed::<1568, 1536>(MlKemParameterSet::MlKem1024, &seed).unwrap();
        let b = keygen_from_seed::<1568, 1536>(MlKemParameterSet::MlKem1024, &seed).unwrap();

        assert_eq!(a, b);
        assert_eq!(a.public_key.len(), 1568);
        assert_eq!(a.secret_key.len(), 1536);
    }

    #[test]
    fn wrong_keygen_lengths_are_rejected() {
        let seed = [0u8; 32];
        assert!(keygen_from_seed::<799, 768>(MlKemParameterSet::MlKem512, &seed).is_err());
        assert!(keygen_from_seed::<800, 767>(MlKemParameterSet::MlKem512, &seed).is_err());
    }
}
