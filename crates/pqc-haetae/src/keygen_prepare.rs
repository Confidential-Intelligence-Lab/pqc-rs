//! Experimental deterministic HAETAE key-generation preparation.
//!
//! This module does not generate, serialize, or validate key pairs.

use crate::keygen_seed::expand_keygen_seed;
use crate::params::{ParameterSet, SEED_BYTES};
use crate::polymat::expand_mat_a;
use crate::polyvec::{PolyVecK, PolyVecM};
use zeroize::Zeroize;

/// First key-generation sampling attempt and its public parameters.
///
/// Secret polynomial vectors and derived seeds must be handled as
/// sensitive material. Secret seeds and polynomial vectors are
/// explicitly zeroized when this structure is dropped.
pub struct KeygenPreparation<const K: usize, const M: usize> {
    pub rhoprime: [u8; SEED_BYTES],
    pub sigma: [u8; 64],
    pub key: [u8; SEED_BYTES],
    pub matrix: [PolyVecM<M>; K],
    pub public_vector: Option<PolyVecK<K>>,
    pub s1: PolyVecM<M>,
    pub s2: PolyVecK<K>,
}

// HAETAE_10K_7D_3D_1_PREPARATION
// HAETAE_10K_7D_3D_3B_PREPARATION
impl<const K: usize, const M: usize> KeygenPreparation<K, M> {
    fn zeroize_secret_material(&mut self) {
        self.sigma.zeroize();
        self.key.zeroize();
        self.s1.zeroize();
        self.s2.zeroize();
    }
}

impl<const K: usize, const M: usize> Drop for KeygenPreparation<K, M> {
    fn drop(&mut self) {
        self.zeroize_secret_material();
    }
}

/// Prepare the first sampling attempt using the authenticated reference order.
///
/// The initial sampling nonce is zero. No singular-value rejection or
/// mode-specific public-key arithmetic is performed here.
#[must_use]
pub fn prepare_first_attempt<const K: usize, const M: usize>(
    seed: &[u8; SEED_BYTES],
    mode: ParameterSet,
) -> KeygenPreparation<K, M> {
    let params = mode.parameters();
    assert_eq!(K, params.k, "HAETAE keygen K dimension mismatch");
    assert_eq!(M, params.l - 1, "HAETAE keygen M dimension mismatch");

    let derived = expand_keygen_seed(seed);
    let matrix = expand_mat_a::<K, M>(&derived.rhoprime, mode);

    let public_vector = match mode {
        ParameterSet::Haetae2 | ParameterSet::Haetae3 => {
            Some(PolyVecK::<K>::expand_vec_a(&derived.rhoprime, mode))
        }
        ParameterSet::Haetae5 => None,
    };

    let (s1, s2) = PolyVecM::<M>::expand_s_with_k::<K>(&derived.sigma, 0, mode);

    KeygenPreparation {
        rhoprime: derived.rhoprime,
        sigma: derived.sigma,
        key: derived.key,
        matrix,
        public_vector,
        s1,
        s2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check<const K: usize, const M: usize>(mode: ParameterSet) {
        let seed = std::array::from_fn(|i| (i * 13 + 7) as u8);
        let result = prepare_first_attempt::<K, M>(&seed, mode);
        let derived = expand_keygen_seed(&seed);

        assert_eq!(result.rhoprime, derived.rhoprime);
        assert_eq!(result.sigma, derived.sigma);
        assert_eq!(result.key, derived.key);

        assert_eq!(result.matrix, expand_mat_a::<K, M>(&derived.rhoprime, mode));

        assert_eq!(
            result.public_vector,
            match mode {
                ParameterSet::Haetae2 | ParameterSet::Haetae3 => {
                    Some(PolyVecK::<K>::expand_vec_a(&derived.rhoprime, mode))
                }
                ParameterSet::Haetae5 => None,
            }
        );

        let (expected_s1, expected_s2) =
            PolyVecM::<M>::expand_s_with_k::<K>(&derived.sigma, 0, mode);

        assert_eq!(result.s1, expected_s1);
        assert_eq!(result.s2, expected_s2);
    }

    #[test]
    fn first_attempt_all_modes() {
        check::<2, 3>(ParameterSet::Haetae2);
        check::<3, 5>(ParameterSet::Haetae3);
        check::<4, 6>(ParameterSet::Haetae5);
    }

    #[test]
    fn rejects_dimension_mismatch() {
        let seed = [0_u8; SEED_BYTES];

        assert!(std::panic::catch_unwind(|| {
            prepare_first_attempt::<3, 3>(&seed, ParameterSet::Haetae2)
        })
        .is_err());
    }
}

// HAETAE_10K_7D_3D_3B_PREPARATION_TEST
#[cfg(test)]
mod lifecycle_zeroization_tests {
    use super::*;

    #[test]
    fn preparation_clears_secrets_and_preserves_public_state() {
        for (mode, k, m) in [
            (ParameterSet::Haetae2, 2, 3),
            (ParameterSet::Haetae3, 3, 5),
            (ParameterSet::Haetae5, 4, 6),
        ] {
            match (k, m) {
                (2, 3) => check::<2, 3>(mode),
                (3, 5) => check::<3, 5>(mode),
                (4, 6) => check::<4, 6>(mode),
                _ => unreachable!(),
            }
        }
    }

    fn check<const K: usize, const M: usize>(mode: ParameterSet) {
        let seed = [0x5a_u8; SEED_BYTES];
        let mut state = prepare_first_attempt::<K, M>(&seed, mode);

        let public_seed = state.rhoprime;
        let public_matrix = state.matrix.clone();
        let public_vector = state.public_vector.clone();

        assert!(state.sigma.iter().any(|&x| x != 0));
        assert!(state.key.iter().any(|&x| x != 0));

        state.zeroize_secret_material();
        state.zeroize_secret_material();

        assert!(state.sigma.iter().all(|&x| x == 0));
        assert!(state.key.iter().all(|&x| x == 0));
        assert!(state
            .s1
            .as_slice()
            .iter()
            .all(|p| p.coeffs.iter().all(|&x| x == 0)));
        assert!(state
            .s2
            .as_slice()
            .iter()
            .all(|p| p.coeffs.iter().all(|&x| x == 0)));

        assert_eq!(state.rhoprime, public_seed);
        assert_eq!(state.matrix, public_matrix);
        assert_eq!(state.public_vector, public_vector);
    }
}
