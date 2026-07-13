//! ML-DSA rounding and decomposition primitives.

use crate::constants::Q;

/// Number of low bits retained by `Power2Round`.
pub const D: u32 = 13;

/// Supported `gamma2` values for ML-DSA decomposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Gamma2 {
    /// `(Q - 1) / 88`, used by ML-DSA-44.
    QMinusOneOver88,
    /// `(Q - 1) / 32`, used by ML-DSA-65 and ML-DSA-87.
    QMinusOneOver32,
}

impl Gamma2 {
    /// Return the integer value of `gamma2`.
    pub const fn value(self) -> i32 {
        match self {
            Self::QMinusOneOver88 => (Q - 1) / 88,
            Self::QMinusOneOver32 => (Q - 1) / 32,
        }
    }

    /// Return `alpha = 2 * gamma2`.
    pub const fn alpha(self) -> i32 {
        2 * self.value()
    }

    /// Return the number of possible high-bit values.
    pub const fn high_modulus(self) -> i32 {
        match self {
            Self::QMinusOneOver88 => 44,
            Self::QMinusOneOver32 => 16,
        }
    }
}

/// Split `r` into high and low parts with radix `2^D`.
///
/// Returns `(r1, r0)` such that
///
/// `r = r1 * 2^D + r0`
///
/// and `r0` lies in the centered interval required by FIPS 204.
#[inline]
pub fn power2round(r: i32) -> (i32, i32) {
    let r1 = (r + (1 << (D - 1)) - 1) >> D;
    let r0 = r - (r1 << D);
    (r1, r0)
}

/// Decompose `r mod Q` into high and low parts for the selected `gamma2`.
///
/// Returns `(r1, r0)` such that
///
/// `r = r1 * (2 * gamma2) + r0 mod Q`.
#[inline]
pub fn decompose(r: i32, gamma2: Gamma2) -> (i32, i32) {
    let canonical = r.rem_euclid(Q);
    let mut r1 = (canonical + 127) >> 7;

    match gamma2 {
        Gamma2::QMinusOneOver32 => {
            r1 = (r1 * 1_025 + (1 << 21)) >> 22;
            r1 &= 15;
        }
        Gamma2::QMinusOneOver88 => {
            r1 = (r1 * 11_275 + (1 << 23)) >> 24;
            r1 ^= ((43 - r1) >> 31) & r1;
        }
    }

    let mut r0 = canonical - r1 * gamma2.alpha();
    r0 -= (((Q - 1) / 2 - r0) >> 31) & Q;

    (r1, r0)
}

/// Return the high bits of `r` for the selected `gamma2`.
#[inline]
pub fn high_bits(r: i32, gamma2: Gamma2) -> i32 {
    decompose(r, gamma2).0
}

/// Return the low bits of `r` for the selected `gamma2`.
#[inline]
pub fn low_bits(r: i32, gamma2: Gamma2) -> i32 {
    decompose(r, gamma2).1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power2round_known_boundaries() {
        let cases = [
            (0, (0, 0)),
            (1, (0, 1)),
            ((1 << (D - 1)) - 1, (0, (1 << (D - 1)) - 1)),
            (1 << (D - 1), (0, 1 << (D - 1))),
            ((1 << D) - 1, (1, -1)),
            (1 << D, (1, 0)),
        ];

        for (input, expected) in cases {
            assert_eq!(power2round(input), expected);
        }
    }

    #[test]
    fn gamma2_values_match_parameter_sets() {
        assert_eq!(Gamma2::QMinusOneOver88.value(), 95_232);
        assert_eq!(Gamma2::QMinusOneOver32.value(), 261_888);
        assert_eq!(Gamma2::QMinusOneOver88.high_modulus(), 44);
        assert_eq!(Gamma2::QMinusOneOver32.high_modulus(), 16);
    }
}
