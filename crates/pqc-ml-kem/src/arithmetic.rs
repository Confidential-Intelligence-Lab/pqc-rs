//! Finite-field arithmetic for ML-KEM.
//!
//! Stage 5B-1 adds Montgomery-domain and Barrett-reduction helpers that will
//! be used by the real FIPS 203 NTT implementation.

/// ML-KEM polynomial degree.
pub const N: usize = 256;

/// ML-KEM modulus.
pub const Q: i16 = 3329;

/// Montgomery radix `R = 2^16`.
pub const MONTGOMERY_R: i32 = 1 << 16;

/// `R mod Q`.
pub const MONTGOMERY_R_MOD_Q: i16 = 2285;

/// `R^-1 mod Q`.
pub const MONTGOMERY_R_INV_MOD_Q: i16 = 169;

/// `-Q^-1 mod 2^16`, used by Montgomery reduction.
pub const MONTGOMERY_QINV: i32 = 3327;

/// Barrett reduction multiplier for q = 3329.
pub const BARRETT_V: i32 = 20159;

/// Reduce an integer modulo `Q` into `[0, Q)`.
pub fn reduce(x: i32) -> i16 {
    let mut r = x % i32::from(Q);
    if r < 0 {
        r += i32::from(Q);
    }
    r as i16
}

/// Barrett reduce an integer modulo `Q` into `[0, Q)`.
///
/// This is written as a canonical reduction for now, preserving a stable API
/// and test oracle before the Stage 5B NTT replaces hot paths with bounded
/// Barrett reductions.
pub fn barrett_reduce(x: i32) -> i16 {
    reduce(x)
}

/// Montgomery reduce `x` by computing `x * R^-1 mod Q`.
///
/// This implementation returns a canonical representative in `[0, Q)`.
pub fn montgomery_reduce(x: i32) -> i16 {
    reduce(x * i32::from(MONTGOMERY_R_INV_MOD_Q))
}

/// Convert a canonical coefficient to Montgomery domain.
pub fn to_montgomery(x: i16) -> i16 {
    reduce(i32::from(x) * MONTGOMERY_R)
}

/// Convert a Montgomery-domain coefficient back to standard representation.
pub fn from_montgomery(x: i16) -> i16 {
    montgomery_reduce(i32::from(x))
}

/// Montgomery-domain multiplication returning a canonical standard coefficient.
pub fn montgomery_mul(a: i16, b: i16) -> i16 {
    montgomery_reduce(i32::from(a) * i32::from(b))
}

/// Add two field elements modulo `Q`.
pub fn add(a: i16, b: i16) -> i16 {
    reduce(i32::from(a) + i32::from(b))
}

/// Subtract two field elements modulo `Q`.
pub fn sub(a: i16, b: i16) -> i16 {
    reduce(i32::from(a) - i32::from(b))
}

/// Multiply two field elements modulo `Q`.
pub fn mul(a: i16, b: i16) -> i16 {
    reduce(i32::from(a) * i32::from(b))
}

/// Compress a coefficient to `d` bits.
pub fn compress_coefficient(x: i16, d: u32) -> u16 {
    debug_assert!(d <= 12);
    let q = u32::from(Q as u16);
    let x = u32::from(reduce(i32::from(x)) as u16);
    let scale = 1u32 << d;
    ((((x * scale) + (q / 2)) / q) & (scale - 1)) as u16
}

/// Decompress a `d`-bit coefficient.
pub fn decompress_coefficient(y: u16, d: u32) -> i16 {
    debug_assert!(d <= 12);
    let q = u32::from(Q as u16);
    let scale = 1u32 << d;
    let y = u32::from(y) & (scale - 1);
    (((y * q) + (scale / 2)) / scale) as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reduction_outputs_canonical_representatives() {
        assert_eq!(reduce(0), 0);
        assert_eq!(reduce(3329), 0);
        assert_eq!(reduce(-1), 3328);
        assert_eq!(reduce(3330), 1);
    }

    #[test]
    fn field_operations_are_modular() {
        assert_eq!(add(3328, 2), 1);
        assert_eq!(sub(1, 2), 3328);
        assert_eq!(mul(3328, 3328), 1);
    }

    #[test]
    fn barrett_reduce_matches_canonical_reduce() {
        for x in [-100_000, -3329, -1, 0, 1, 3328, 3329, 100_000] {
            assert_eq!(barrett_reduce(x), reduce(x));
        }
    }

    #[test]
    fn montgomery_constants_are_consistent() {
        assert_eq!(reduce(MONTGOMERY_R), MONTGOMERY_R_MOD_Q);
        assert_eq!(
            reduce(i32::from(MONTGOMERY_R_MOD_Q) * i32::from(MONTGOMERY_R_INV_MOD_Q)),
            1
        );
        assert_eq!((i32::from(Q) * MONTGOMERY_QINV + 1) & 0xffff, 0);
    }

    #[test]
    fn montgomery_round_trip_returns_original_value() {
        for x in [0, 1, 2, 17, 1024, 2048, 3328] {
            assert_eq!(from_montgomery(to_montgomery(x)), reduce(i32::from(x)));
        }
    }

    #[test]
    fn montgomery_reduce_matches_multiply_by_r_inverse() {
        for x in [0, 1, 17, 3328, 3329, 65536, 1_234_567] {
            assert_eq!(
                montgomery_reduce(x),
                reduce(x * i32::from(MONTGOMERY_R_INV_MOD_Q))
            );
        }
    }

    #[test]
    fn montgomery_domain_multiplication_matches_standard_product() {
        for a in [0, 1, 2, 17, 1024, 3328] {
            for b in [0, 1, 3, 19, 2048, 3328] {
                let a_m = to_montgomery(a);
                let b_m = to_montgomery(b);
                let product_m = montgomery_mul(a_m, b_m);
                assert_eq!(from_montgomery(product_m), mul(a, b));
            }
        }
    }

    fn circular_distance_mod_q(a: i16, b: i16) -> i32 {
        let q = i32::from(Q);
        let diff = (i32::from(reduce(i32::from(a))) - i32::from(reduce(i32::from(b)))).abs();
        core::cmp::min(diff, q - diff)
    }

    #[test]
    fn coefficient_compression_round_trip_is_bounded_mod_q() {
        for x in [0, 1, 17, 100, 1024, 2048, 3328] {
            let c = compress_coefficient(x, 10);
            let d = decompress_coefficient(c, 10);
            assert!(
                circular_distance_mod_q(x, d) <= 3,
                "x={x}, compressed={c}, decompressed={d}"
            );
        }
    }
}
