//! FIPS NTT zeta schedule assets for ML-KEM.
//!
//! Stage 5B-2 introduces the constant-table module and bit-reversal helpers used
//! by the real NTT implementation. The full butterfly implementation lands in a
//! later increment after this schedule is validated in isolation.

use crate::arithmetic::{mul, reduce, Q};

/// Primitive root used by ML-KEM's NTT schedule generation.
pub const ZETA_GENERATOR: i16 = 17;

/// Number of zeta values in the compact ML-KEM schedule.
pub const ZETAS_LEN: usize = 128;

/// Compact zeta schedule used by Kyber/ML-KEM implementations.
///
/// These values are kept in canonical `[0, q)` representation. Stage 5B-3 will
/// consume this table in the real forward and inverse NTT.
pub const ZETAS: [i16; ZETAS_LEN] = [
    2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962, 2127, 1855, 1468, 573,
    2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017, 732, 608, 1787, 411, 3124, 1758, 1223, 652,
    2777, 1015, 2036, 1491, 3047, 1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239,
    3058, 830, 107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226, 430, 555,
    843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574, 1653, 3083, 778, 1159, 3182,
    2552, 1483, 2727, 1119, 1739, 644, 2457, 349, 418, 329, 3173, 3254, 817, 1097, 603, 610, 1322,
    2044, 1864, 384, 2114, 3193, 1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819,
    2475, 2459, 478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628,
];

/// Reverse the lowest `width` bits of `value`.
pub const fn bit_reverse(mut value: usize, width: u32) -> usize {
    let mut out = 0usize;
    let mut i = 0;
    while i < width {
        out = (out << 1) | (value & 1);
        value >>= 1;
        i += 1;
    }
    out
}

/// Compute `base^exp mod q`.
pub fn pow_mod_q(base: i16, exp: usize) -> i16 {
    let mut result = 1i16;
    let mut b = reduce(i32::from(base));
    let mut e = exp;

    while e > 0 {
        if e & 1 == 1 {
            result = mul(result, b);
        }
        b = mul(b, b);
        e >>= 1;
    }

    result
}

/// Generate a zeta from the primitive generator and bit-reversed exponent.
pub fn generated_zeta(index: usize) -> i16 {
    debug_assert!(index < ZETAS_LEN);
    let exponent = bit_reverse(index, 7);
    pow_mod_q(ZETA_GENERATOR, exponent)
}

/// Return a scheduled zeta by index.
pub fn zeta(index: usize) -> i16 {
    ZETAS[index]
}

/// Return `true` if every table value is canonical modulo q.
pub fn all_zetas_are_canonical() -> bool {
    ZETAS.iter().all(|z| *z >= 0 && *z < Q)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_reverse_examples_are_correct() {
        assert_eq!(bit_reverse(0b0000001, 7), 0b1000000);
        assert_eq!(bit_reverse(0b0000011, 7), 0b1100000);
        assert_eq!(bit_reverse(0b1010101, 7), 0b1010101);
    }

    #[test]
    fn zeta_table_has_expected_length_and_boundaries() {
        assert_eq!(ZETAS.len(), ZETAS_LEN);
        assert_eq!(ZETAS[0], 2285);
        assert_eq!(ZETAS[127], 1628);
    }

    #[test]
    fn zeta_values_are_canonical() {
        assert!(all_zetas_are_canonical());
    }

    #[test]
    fn generator_has_expected_order_shape() {
        assert_eq!(pow_mod_q(ZETA_GENERATOR, 256), 1);
        assert_eq!(pow_mod_q(ZETA_GENERATOR, 128), Q - 1);
    }

    #[test]
    fn generated_zeta_path_is_deterministic() {
        assert_eq!(generated_zeta(0), 1);
        assert_eq!(generated_zeta(1), pow_mod_q(ZETA_GENERATOR, 64));
        assert_eq!(generated_zeta(2), pow_mod_q(ZETA_GENERATOR, 32));
    }
}
