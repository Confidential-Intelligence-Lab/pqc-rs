//! Reference modular arithmetic for HAETAE.
//!
//! Correctness-first implementation. No constant-time guarantees are
//! claimed for division-based reduction.

use crate::params::Q;

/// Canonical reduction into [0, q).
#[inline]
pub fn reduce(x: i64) -> i32 {
    x.rem_euclid(i64::from(Q)) as i32
}

/// Addition modulo q.
#[inline]
pub fn add(a: i32, b: i32) -> i32 {
    reduce(i64::from(a) + i64::from(b))
}

/// Subtraction modulo q.
#[inline]
pub fn sub(a: i32, b: i32) -> i32 {
    reduce(i64::from(a) - i64::from(b))
}

/// Multiplication modulo q.
#[inline]
pub fn mul(a: i32, b: i32) -> i32 {
    reduce(i64::from(a) * i64::from(b))
}

/// Exponentiation modulo q, for public inputs only.
pub fn pow(mut base: i32, mut exponent: u64) -> i32 {
    let mut result = 1;
    base = reduce(i64::from(base));

    while exponent != 0 {
        if exponent & 1 != 0 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exponent >>= 1;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction_boundaries() {
        for x in [
            i64::MIN,
            -2 * i64::from(Q),
            -i64::from(Q),
            -1,
            0,
            1,
            i64::from(Q) - 1,
            i64::from(Q),
            2 * i64::from(Q),
            i64::MAX,
        ] {
            let r = reduce(x);
            assert!((0..Q).contains(&r));
            assert_eq!(i64::from(r), x.rem_euclid(i64::from(Q)));
        }
    }

    #[test]
    fn field_identities() {
        for a in 0..Q {
            assert_eq!(add(a, 0), a);
            assert_eq!(sub(a, a), 0);
            assert_eq!(mul(a, 1), a);
            assert_eq!(mul(a, 0), 0);
            assert_eq!(add(a, Q - a), 0);
        }
    }

    #[test]
    fn deterministic_arithmetic_crosscheck() {
        let mut state = 0x1234_5678_9abc_def0_u64;

        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let a = (state % Q as u64) as i32;

            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let b = (state % Q as u64) as i32;

            assert_eq!(
                add(a, b),
                ((i64::from(a) + i64::from(b)) % i64::from(Q)) as i32
            );
            assert_eq!(
                sub(a, b),
                (i64::from(a) - i64::from(b)).rem_euclid(i64::from(Q)) as i32
            );
            assert_eq!(
                mul(a, b),
                ((i64::from(a) * i64::from(b)) % i64::from(Q)) as i32
            );
        }
    }

    #[test]
    fn exponentiation_properties() {
        for a in [1, 2, 3, 7, 42, Q - 1] {
            assert_eq!(pow(a, 0), 1);
            assert_eq!(pow(a, 1), a);
            assert_eq!(pow(a, (Q - 1) as u64), 1);
        }
    }
}
