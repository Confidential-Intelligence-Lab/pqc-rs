// SPDX-License-Identifier: MIT

//! Experimental HAETAE key-generation arithmetic.
//!
//! This module does not implement rejection resampling, key serialization,
//! or production-ready secret handling.

use crate::keygen_prepare::KeygenPreparation;
use crate::keygen_rejection::rejects_squared_singular_value;
use crate::params::ParameterSet;
use crate::polymat::pointwise_montgomery;
use crate::polyvec::PolyVecK;
use crate::singular_value::squared_singular_value;

/// Arithmetic result for one HAETAE-2/3 key-generation attempt.
///
/// `public_b` is the decomposed high component that the authenticated
/// reference subsequently passes to public-key serialization.
///
/// `updated_s2` is the secret vector after subtracting the low component.
pub struct RoundedKeygenAttempt<const K: usize> {
    pub public_b: PolyVecK<K>,
    pub updated_s2: PolyVecK<K>,
    pub squared_singular_value: i64,
    pub rejected: bool,
}

/// Execute the authenticated HAETAE-2/3 arithmetic for one sampled attempt.
///
/// The input preparation state is not modified. Rejection resampling and
/// nonce progression are handled separately.
#[must_use]
pub fn rounded_first_attempt<const K: usize, const M: usize>(
    prepared: &KeygenPreparation<K, M>,
    mode: ParameterSet,
) -> RoundedKeygenAttempt<K> {
    assert!(
        matches!(mode, ParameterSet::Haetae2 | ParameterSet::Haetae3),
        "rounded keygen arithmetic is defined only for HAETAE-2/3"
    );

    let params = mode.parameters();
    assert_eq!(K, params.k, "rounded keygen K dimension mismatch");
    assert_eq!(M, params.l - 1, "rounded keygen M dimension mismatch");

    let public_a = prepared
        .public_vector
        .as_ref()
        .expect("HAETAE-2/3 requires the expanded public vector");

    let mut s1hat = prepared.s1.clone();
    s1hat.ntt();

    let mut b = pointwise_montgomery(&prepared.matrix, &s1hat, mode);
    b.invntt_tomont();

    b = b.add(&prepared.s2);
    b = b.add(public_a);
    b.freeze();

    let low = b.decompose_vk();
    let updated_s2 = prepared.s2.sub(&low);

    let squared = squared_singular_value(&prepared.s1, &updated_s2, mode);
    let rejected = rejects_squared_singular_value(squared, mode);

    RoundedKeygenAttempt {
        public_b: b,
        updated_s2,
        squared_singular_value: squared,
        rejected,
    }
}

/// Arithmetic result for one HAETAE-5 key-generation attempt.
///
/// Rejected attempts have no public-key arithmetic output.
/// The sampled secret vectors remain available in the preparation state.
pub struct UnroundedKeygenAttempt<const K: usize> {
    pub public_b: Option<PolyVecK<K>>,
    pub squared_singular_value: i64,
    pub rejected: bool,
}

/// Execute the authenticated HAETAE-5 first-attempt arithmetic.
///
/// HAETAE-5 evaluates the singular-value rejection condition before
/// performing the NTT-domain public-key calculation.
///
/// Rejection resampling and key serialization are not implemented here.
#[must_use]
pub fn unrounded_first_attempt<const K: usize, const M: usize>(
    prepared: &KeygenPreparation<K, M>,
    mode: ParameterSet,
) -> UnroundedKeygenAttempt<K> {
    assert!(
        matches!(mode, ParameterSet::Haetae5),
        "unrounded keygen arithmetic is defined only for HAETAE-5"
    );

    let params = mode.parameters();
    assert_eq!(K, params.k, "unrounded keygen K dimension mismatch");
    assert_eq!(M, params.l - 1, "unrounded keygen M dimension mismatch");

    assert!(
        prepared.public_vector.is_none(),
        "HAETAE-5 must not have a separate public vector"
    );

    let squared = squared_singular_value(&prepared.s1, &prepared.s2, mode);
    let rejected = rejects_squared_singular_value(squared, mode);

    if rejected {
        return UnroundedKeygenAttempt {
            public_b: None,
            squared_singular_value: squared,
            rejected,
        };
    }

    let mut s1hat = prepared.s1.clone();
    let mut s2hat = prepared.s2.clone();

    s1hat.ntt();
    s2hat.ntt();

    let mut b = pointwise_montgomery(&prepared.matrix, &s1hat, mode);
    b.frommont();
    b = b.add(&s2hat);
    b.double_negate();
    b.caddq();

    UnroundedKeygenAttempt {
        public_b: Some(b),
        squared_singular_value: squared,
        rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen_prepare::prepare_first_attempt;

    #[test]
    fn deterministic_rounded_arithmetic() {
        let seed = std::array::from_fn(|i| (i * 17 + 3) as u8);

        let prepared2 = prepare_first_attempt::<2, 3>(&seed, ParameterSet::Haetae2);

        let a2 = rounded_first_attempt(&prepared2, ParameterSet::Haetae2);
        let b2 = rounded_first_attempt(&prepared2, ParameterSet::Haetae2);

        assert_eq!(a2.public_b, b2.public_b);
        assert_eq!(a2.updated_s2, b2.updated_s2);
        assert_eq!(a2.squared_singular_value, b2.squared_singular_value);
        assert_eq!(a2.rejected, b2.rejected);

        let prepared3 = prepare_first_attempt::<3, 5>(&seed, ParameterSet::Haetae3);

        let a3 = rounded_first_attempt(&prepared3, ParameterSet::Haetae3);
        let b3 = rounded_first_attempt(&prepared3, ParameterSet::Haetae3);

        assert_eq!(a3.public_b, b3.public_b);
        assert_eq!(a3.updated_s2, b3.updated_s2);
        assert_eq!(a3.squared_singular_value, b3.squared_singular_value);
        assert_eq!(a3.rejected, b3.rejected);
    }

    #[test]
    #[should_panic(expected = "rounded keygen arithmetic is defined only")]
    fn rejects_haetae5() {
        let seed = [0_u8; 32];
        let prepared = prepare_first_attempt::<4, 6>(&seed, ParameterSet::Haetae5);

        let _ = rounded_first_attempt(&prepared, ParameterSet::Haetae5);
    }
}
