// SPDX-License-Identifier: MIT
//! Experimental HAETAE key-generation rejection loop.
//!
//! This module constructs accepted mathematical key-generation state.
//! It does not implement key serialization, signing, verification,
//! cryptographic key erasure, or production-ready key generation.

use crate::keygen_arithmetic::{rounded_first_attempt, unrounded_first_attempt};
use crate::keygen_prepare::prepare_first_attempt;
use crate::keygen_rejection::{
    next_sampling_counter, validate_sampling_batch, NonceCounterExhausted,
};
use crate::params::{ParameterSet, SEED_BYTES};
use crate::polyvec::{PolyVecK, PolyVecM};
use zeroize::Zeroize;

/// Failure to obtain an accepted state within the permitted search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeygenLoopError {
    /// The caller supplied zero permitted attempts.
    ZeroAttempts,
    /// The configured attempt limit was reached without acceptance.
    AttemptLimitReached,
    /// Advancing the sampling nonce would overflow its 16-bit representation.
    NonceExhausted,
}

/// Internal checked sampling-nonce cursor.
///
/// The cursor identifies the first nonce in a complete sampling batch.
/// Rejection advances it only when the next batch is representable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SamplingCursor {
    nonce: u16,
}

impl SamplingCursor {
    fn new(mode: ParameterSet) -> Result<Self, NonceCounterExhausted> {
        validate_sampling_batch(0, mode)?;
        Ok(Self { nonce: 0 })
    }

    fn current(self) -> u16 {
        self.nonce
    }

    fn advance_after_rejection(&mut self, mode: ParameterSet) -> Result<(), NonceCounterExhausted> {
        let next = next_sampling_counter(self.nonce, mode)?;
        validate_sampling_batch(next, mode)?;
        self.nonce = next;
        Ok(())
    }
}

/// Accepted HAETAE mathematical key-generation state.
///
/// All seed-derived values and secret polynomial vectors are sensitive.
/// Secret material is cleared when this state is dropped.
pub struct AcceptedKeygenState<const K: usize, const M: usize> {
    pub rhoprime: [u8; SEED_BYTES],
    pub key: [u8; SEED_BYTES],
    pub public_b: PolyVecK<K>,
    pub s1: PolyVecM<M>,
    pub s2: PolyVecK<K>,
    pub squared_singular_value: i64,
    pub attempts: usize,
    pub sampling_nonce: u16,
}

// HAETAE_10K_7D_3D_1_ACCEPTED_STATE
// HAETAE_10K_7D_3D_3B_ACCEPTED
impl<const K: usize, const M: usize> AcceptedKeygenState<K, M> {
    fn zeroize_secret_material(&mut self) {
        self.key.zeroize();
        self.s1.zeroize();
        self.s2.zeroize();
    }
}

impl<const K: usize, const M: usize> Drop for AcceptedKeygenState<K, M> {
    fn drop(&mut self) {
        self.zeroize_secret_material();
    }
}

impl From<NonceCounterExhausted> for KeygenLoopError {
    fn from(_: NonceCounterExhausted) -> Self {
        Self::NonceExhausted
    }
}

/// Generate an accepted HAETAE key-generation state.
///
/// Matrix expansion and seed derivation occur once. Subsequent attempts
/// resample secret vectors at consecutive reference-compatible nonces.
///
/// HAETAE-2/3 apply public-key rounding and update s2 before rejection.
/// HAETAE-5 rejects before computing its public-key vector.
///
/// The caller must supply a finite, nonzero attempt limit.
pub fn generate_accepted_state<const K: usize, const M: usize>(
    seed: &[u8; SEED_BYTES],
    mode: ParameterSet,
    max_attempts: usize,
) -> Result<AcceptedKeygenState<K, M>, KeygenLoopError> {
    if max_attempts == 0 {
        return Err(KeygenLoopError::ZeroAttempts);
    }

    let mut prepared = prepare_first_attempt::<K, M>(seed, mode);
    let mut cursor = SamplingCursor::new(mode)?;

    for attempt in 0..max_attempts {
        let nonce = cursor.current();

        if attempt != 0 {
            let (s1, s2) = PolyVecM::<M>::expand_s_with_k::<K>(&prepared.sigma, nonce, mode);
            prepared.s1.zeroize();
            prepared.s2.zeroize();
            prepared.s1 = s1;
            prepared.s2 = s2;
        }

        let (public_b, accepted_s2, squared) = match mode {
            ParameterSet::Haetae2 | ParameterSet::Haetae3 => {
                let mut result = rounded_first_attempt(&prepared, mode);

                if result.rejected {
                    if attempt + 1 == max_attempts {
                        return Err(KeygenLoopError::AttemptLimitReached);
                    }

                    cursor.advance_after_rejection(mode)?;
                    continue;
                }

                (
                    std::mem::take(&mut result.public_b),
                    std::mem::take(&mut result.updated_s2),
                    result.squared_singular_value,
                )
            }
            ParameterSet::Haetae5 => {
                let result = unrounded_first_attempt(&prepared, mode);

                if result.rejected {
                    if attempt + 1 == max_attempts {
                        return Err(KeygenLoopError::AttemptLimitReached);
                    }

                    cursor.advance_after_rejection(mode)?;
                    continue;
                }

                (
                    result.public_b.expect("accepted HAETAE-5 must produce B"),
                    std::mem::take(&mut prepared.s2),
                    result.squared_singular_value,
                )
            }
        };

        return Ok(AcceptedKeygenState {
            rhoprime: prepared.rhoprime,
            key: prepared.key,
            public_b,
            s1: std::mem::take(&mut prepared.s1),
            s2: accepted_s2,
            squared_singular_value: squared,
            attempts: attempt + 1,
            sampling_nonce: nonce,
        });
    }

    Err(KeygenLoopError::AttemptLimitReached)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampling_cursor_initial_state() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let cursor = SamplingCursor::new(mode).unwrap();
            assert_eq!(cursor.current(), 0);
        }
    }

    #[test]
    fn sampling_cursor_advances_by_batch_width() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let width = crate::keygen_rejection::nonces_per_attempt(mode);
            let mut cursor = SamplingCursor::new(mode).unwrap();

            for attempt in 0..100_u16 {
                assert_eq!(cursor.current(), attempt * width);
                cursor.advance_after_rejection(mode).unwrap();
            }
        }
    }

    #[test]
    fn sampling_cursor_accepts_final_batch_and_rejects_next() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let width = crate::keygen_rejection::nonces_per_attempt(mode);
            let capacity = (u32::from(u16::MAX) + 1) / u32::from(width);
            let final_start = ((capacity - 1) * u32::from(width)) as u16;

            let mut cursor = SamplingCursor::new(mode).unwrap();

            for _ in 1..capacity {
                cursor.advance_after_rejection(mode).unwrap();
            }

            assert_eq!(cursor.current(), final_start);
            assert_eq!(validate_sampling_batch(cursor.current(), mode), Ok(()));

            assert_eq!(
                cursor.advance_after_rejection(mode),
                Err(NonceCounterExhausted)
            );

            assert_eq!(cursor.current(), final_start);
        }
    }

    #[test]
    fn sampling_cursor_rejection_is_transactional() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let width = crate::keygen_rejection::nonces_per_attempt(mode);
            let capacity = 65_536_u32 / u32::from(width);
            let final_start = ((capacity - 1) * u32::from(width)) as u16;

            let mut cursor = SamplingCursor { nonce: final_start };
            let before = cursor;

            assert_eq!(
                cursor.advance_after_rejection(mode),
                Err(NonceCounterExhausted)
            );

            assert_eq!(cursor, before);
        }
    }

    #[test]
    fn rejects_zero_attempt_limit() {
        let seed = [0_u8; SEED_BYTES];

        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let result = match mode {
                ParameterSet::Haetae2 => {
                    generate_accepted_state::<2, 3>(&seed, mode, 0).map(|_| ())
                }
                ParameterSet::Haetae3 => {
                    generate_accepted_state::<3, 5>(&seed, mode, 0).map(|_| ())
                }
                ParameterSet::Haetae5 => {
                    generate_accepted_state::<4, 6>(&seed, mode, 0).map(|_| ())
                }
            };

            assert_eq!(result, Err(KeygenLoopError::ZeroAttempts));
        }
    }

    #[test]
    fn haetae5_authenticated_acceptance_positions() {
        let expected = [
            (0_u8, 11_usize, 100_u16, 776_036_i64),
            (255_u8, 21, 200, 709_352),
        ];

        for (byte, attempts, nonce, squared) in expected {
            let seed = [byte; SEED_BYTES];

            let result = generate_accepted_state::<4, 6>(&seed, ParameterSet::Haetae5, 100)
                .expect("reference HAETAE-5 case must accept");

            assert_eq!(result.attempts, attempts);
            assert_eq!(result.sampling_nonce, nonce);
            assert_eq!(result.squared_singular_value, squared);
        }
    }

    #[test]
    fn haetae5_attempt_limit_is_enforced() {
        let seed = [0_u8; SEED_BYTES];

        assert!(matches!(
            generate_accepted_state::<4, 6>(&seed, ParameterSet::Haetae5, 1),
            Err(KeygenLoopError::AttemptLimitReached)
        ));
    }

    #[test]
    fn rejects_invalid_dimensions() {
        let seed = [0_u8; SEED_BYTES];

        assert!(std::panic::catch_unwind(|| {
            let _ = generate_accepted_state::<3, 3>(&seed, ParameterSet::Haetae2, 1);
        })
        .is_err());
    }
}

// HAETAE_10K_7D_3D_3B_ACCEPTED_TEST
#[cfg(test)]
mod lifecycle_zeroization_tests {
    use super::*;

    #[test]
    fn accepted_state_clears_secrets_and_preserves_public_state() {
        let seed = [0x5a_u8; SEED_BYTES];

        check::<2, 3>(&seed, ParameterSet::Haetae2);
        check::<3, 5>(&seed, ParameterSet::Haetae3);
        check::<4, 6>(&seed, ParameterSet::Haetae5);
    }

    fn check<const K: usize, const M: usize>(seed: &[u8; SEED_BYTES], mode: ParameterSet) {
        let mut state = generate_accepted_state::<K, M>(seed, mode, 1000)
            .expect("keygen must accept within test limit");

        let public_seed = state.rhoprime;
        let public_b = state.public_b.clone();
        let attempts = state.attempts;
        let nonce = state.sampling_nonce;

        assert!(state.key.iter().any(|&x| x != 0));

        state.zeroize_secret_material();
        state.zeroize_secret_material();

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
        assert_eq!(state.public_b, public_b);
        assert_eq!(state.attempts, attempts);
        assert_eq!(state.sampling_nonce, nonce);
    }
}
