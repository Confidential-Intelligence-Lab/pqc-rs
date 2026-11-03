//! Experimental deterministic HAETAE key-generation preparation.
//!
//! This module does not generate, serialize, or validate key pairs.

use crate::keygen_seed::expand_keygen_seed;
use crate::params::{ParameterSet, SEED_BYTES};
use crate::polymat::expand_mat_a;
use crate::polyvec::{PolyVecK, PolyVecM};

/// First key-generation sampling attempt and its public parameters.
///
/// Secret polynomial vectors and derived seeds must be handled as
/// sensitive material. This structure is experimental and does not
/// provide automatic memory zeroization.
pub struct KeygenPreparation<const K: usize, const M: usize> {
    pub rhoprime: [u8; SEED_BYTES],
    pub sigma: [u8; 64],
    pub key: [u8; SEED_BYTES],
    pub matrix: [PolyVecM<M>; K],
    pub public_vector: Option<PolyVecK<K>>,
    pub s1: PolyVecM<M>,
    pub s2: PolyVecK<K>,
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
