//! Modular reduction primitives.

use crate::constants::{Q, Q_INV};

/// Montgomery reduction of a 64-bit product.
///
/// Returns a representative congruent to `a * 2^-32 mod Q`.
#[inline]
pub fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(Q_INV);
    let u = (a - i64::from(t) * i64::from(Q)) >> 32;
    u as i32
}

/// Reduce a coefficient to a centered representative.
#[inline]
pub fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

/// Conditionally add `Q` to a negative representative.
#[inline]
pub fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

/// Return the canonical representative in `[0, Q)`.
#[inline]
pub fn freeze(a: i32) -> i32 {
    caddq(reduce32(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_is_canonical() {
        for value in [-2 * Q, -Q - 1, -Q, -1, 0, 1, Q - 1, Q, Q + 1, 2 * Q] {
            let reduced = freeze(value);
            assert!((0..Q).contains(&reduced));
            assert_eq!((reduced - value).rem_euclid(Q), 0);
        }
    }

    #[test]
    fn montgomery_reduce_preserves_residue() {
        let values = [
            0_i64,
            1,
            i64::from(Q),
            i64::from(Q) * i64::from(Q),
            123_456_789,
            -123_456_789,
        ];

        for value in values {
            let reduced = montgomery_reduce(value);
            let lhs =
                (i64::from(reduced) * ((1_i64 << 32) % i64::from(Q))).rem_euclid(i64::from(Q));
            let rhs = value.rem_euclid(i64::from(Q));
            assert_eq!(lhs, rhs);
        }
    }
}
