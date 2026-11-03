//! HAETAE 1.2.0 Montgomery arithmetic.
//!
//! Implements the signed 32-bit Montgomery reduction convention
//! used by the authenticated C reference.

use crate::params::Q;

/// Montgomery radix modulo q.
pub const MONT: i32 = 14_321;

/// Montgomery radix squared modulo q.
pub const MONT_SQUARED: i32 = 4_214;

/// q inverse modulo 2^32.
pub const QINV: i32 = 940_508_161;

/// Computes a * 2^(-32) modulo q.
///
/// The input must satisfy:
/// -2^31 * q <= a <= 2^31 * q.
///
/// The output is congruent to a * R^(-1) modulo q.
#[inline]
pub fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    let r = (a - i64::from(t) * i64::from(Q)) >> 32;

    r as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::reduce;

    #[test]
    fn constants_match_reference() {
        assert_eq!((1_i64 << 32) % i64::from(Q), i64::from(MONT));
        assert_eq!(((1_i128 << 64) % i128::from(Q)) as i32, MONT_SQUARED);
        assert_eq!((i64::from(Q) * i64::from(QINV)) % (1_i64 << 32), 1);
    }

    #[test]
    fn montgomery_round_trip() {
        for a in 0..Q {
            let encoded = montgomery_reduce(i64::from(a) * i64::from(MONT_SQUARED));

            let decoded = montgomery_reduce(i64::from(encoded));

            assert_eq!(reduce(i64::from(decoded)), a);
        }
    }

    #[test]
    fn montgomery_product_matches_field_product() {
        for a in [0, 1, 2, 42, Q / 2, Q - 1] {
            for b in [0, 1, 3, 57, Q / 2, Q - 1] {
                let a_mont = montgomery_reduce(i64::from(a) * i64::from(MONT_SQUARED));
                let b_mont = montgomery_reduce(i64::from(b) * i64::from(MONT_SQUARED));

                let product_mont = montgomery_reduce(i64::from(a_mont) * i64::from(b_mont));

                let product = montgomery_reduce(i64::from(product_mont));

                assert_eq!(
                    reduce(i64::from(product)),
                    reduce(i64::from(a) * i64::from(b))
                );
            }
        }
    }

    #[test]
    fn reduction_output_range() {
        let bound = (1_i64 << 31) * i64::from(Q);

        for a in [-bound, -bound + 1, -1, 0, 1, bound - 1, bound] {
            let r = montgomery_reduce(a);
            // The reference's inclusive input bound permits an
            // output of +Q at its positive endpoint.
            assert!((-Q..=Q).contains(&r));
        }
    }
}
