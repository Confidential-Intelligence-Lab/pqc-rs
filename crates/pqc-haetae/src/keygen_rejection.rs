// SPDX-License-Identifier: MIT

//! HAETAE 1.2.0 key-generation rejection and nonce accounting.
//!
//! Integer rejection limits were established against the authenticated
//! reference's floating-point predicate for all three parameter sets.

use crate::params::ParameterSet;

/// Largest accepted integer squared singular value.
#[must_use]
pub const fn acceptance_limit(mode: ParameterSet) -> i64 {
    match mode {
        ParameterSet::Haetae2 => 611_098,
        ParameterSet::Haetae3 => 852_505,
        ParameterSet::Haetae5 => 778_065,
    }
}

/// Whether the authenticated key-generation bound rejects this value.
#[must_use]
pub const fn rejects_squared_singular_value(squared_value: i64, mode: ParameterSet) -> bool {
    squared_value > acceptance_limit(mode)
}

/// Number of polynomial sampling nonces consumed per attempt.
#[must_use]
pub const fn nonces_per_attempt(mode: ParameterSet) -> u16 {
    match mode {
        ParameterSet::Haetae2 => 5,
        ParameterSet::Haetae3 => 8,
        ParameterSet::Haetae5 => 10,
    }
}

/// An additional sampling attempt cannot be represented without wrapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonceCounterExhausted;

/// Advance the starting nonce after sampling M + K polynomials.
///
/// Unlike the reference C uint16_t assignment, overflow is reported
/// explicitly rather than silently wrapping to zero.
pub fn next_sampling_counter(
    current: u16,
    mode: ParameterSet,
) -> Result<u16, NonceCounterExhausted> {
    current
        .checked_add(nonces_per_attempt(mode))
        .ok_or(NonceCounterExhausted)
}

/// Check that every nonce consumed by a sampling batch fits in u16.
///
/// A batch beginning at `start` consumes `M + K` consecutive nonces,
/// including `start`. The last consumed nonce must be representable.
pub fn validate_sampling_batch(
    start: u16,
    mode: ParameterSet,
) -> Result<(), NonceCounterExhausted> {
    let last_offset = nonces_per_attempt(mode) - 1;
    start
        .checked_add(last_offset)
        .map(|_| ())
        .ok_or(NonceCounterExhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_sampling_batch_boundaries() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let width = nonces_per_attempt(mode);
            let largest_valid = u16::MAX - (width - 1);

            assert_eq!(validate_sampling_batch(0, mode), Ok(()));
            assert_eq!(validate_sampling_batch(largest_valid, mode), Ok(()));

            assert_eq!(
                validate_sampling_batch(largest_valid + 1, mode),
                Err(NonceCounterExhausted)
            );
        }
    }

    #[test]
    fn authenticated_rejection_boundaries() {
        for (mode, limit) in [
            (ParameterSet::Haetae2, 611_098),
            (ParameterSet::Haetae3, 852_505),
            (ParameterSet::Haetae5, 778_065),
        ] {
            assert_eq!(acceptance_limit(mode), limit);

            for offset in -2..=2 {
                let value = limit + offset;
                assert_eq!(rejects_squared_singular_value(value, mode), offset > 0);
            }
        }
    }

    #[test]
    fn negative_and_extreme_estimator_values() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            assert!(!rejects_squared_singular_value(i64::MIN, mode));
            assert!(!rejects_squared_singular_value(0, mode));
            assert!(rejects_squared_singular_value(i64::MAX, mode));
        }
    }

    #[test]
    fn reference_nonce_increments() {
        for (mode, increment) in [
            (ParameterSet::Haetae2, 5),
            (ParameterSet::Haetae3, 8),
            (ParameterSet::Haetae5, 10),
        ] {
            assert_eq!(nonces_per_attempt(mode), increment);
            assert_eq!(next_sampling_counter(0, mode), Ok(increment));
            assert_eq!(next_sampling_counter(increment, mode), Ok(2 * increment));
        }
    }

    #[test]
    fn nonce_exhaustion_is_explicit() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let increment = nonces_per_attempt(mode);

            assert_eq!(
                next_sampling_counter(u16::MAX - increment, mode),
                Ok(u16::MAX)
            );
            assert_eq!(
                next_sampling_counter(u16::MAX - increment + 1, mode),
                Err(NonceCounterExhausted)
            );
        }
    }
}
