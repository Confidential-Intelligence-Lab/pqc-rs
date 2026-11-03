//! HAETAE 1.2.0 scalar decomposition and CRT operations.
//!
//! These functions reproduce the authenticated C reference semantics.
//! Inputs to CRT reconstruction must be canonical modulo Q.

use crate::params::{ParameterSet, Q};

/// Signed radix-256 decomposition.
///
/// Returns (high, low), with low in [-128, 127].
pub fn decompose_z1(r: i32) -> (i32, i32) {
    let low = ((r & 255) + 128).rem_euclid(256) - 128;
    let high = (r.wrapping_add(128)) >> 8;
    (high, low)
}

/// HAETAE hint high bits, including reference wraparound.
pub fn decompose_hint(r: i32, mode: ParameterSet) -> i32 {
    let (alpha, shift) = match mode {
        ParameterSet::Haetae2 | ParameterSet::Haetae3 => (512, 9),
        ParameterSet::Haetae5 => (256, 8),
    };

    let mut high = r.wrapping_add(alpha / 2) >> shift;
    let modulus = (2 * Q - 2) / alpha;

    let edgecase = (modulus.wrapping_sub(high.wrapping_add(1))) >> 31;
    high = high.wrapping_sub(modulus & edgecase);
    high
}

/// HAETAE verification-key decomposition.
///
/// Returns (high, low), where low is either -1, 0, or 1.
pub fn decompose_vk(a: i32) -> (i32, i32) {
    let mut low = a & 1;
    low -= ((a >> 1) & low) << 1;
    ((a - low) >> 1, low)
}

/// CRT reconstruction from canonical modulo-Q residue and parity.
///
/// The caller must supply xq in [0, Q) and parity in {0, 1}.
pub fn fromcrt(xq: i32, parity: i32) -> i32 {
    debug_assert!((0..Q).contains(&xq));
    debug_assert!(parity == 0 || parity == 1);
    xq + (Q & -((xq ^ parity) & 1))
}

/// CRT reconstruction assuming even parity.
pub fn fromcrt0(xq: i32) -> i32 {
    fromcrt(xq, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn z1_boundaries() {
        for r in [-1025, -256, -129, -128, -1, 0, 1, 127, 128, 255, 256, 1025] {
            let (high, low) = decompose_z1(r);
            assert!((-128..128).contains(&low));
            assert_eq!(high * 256 + low, r);
        }
    }

    #[test]
    fn hint_mode_boundaries() {
        for mode in [
            ParameterSet::Haetae2,
            ParameterSet::Haetae3,
            ParameterSet::Haetae5,
        ] {
            let alpha = match mode {
                ParameterSet::Haetae5 => 256,
                _ => 512,
            };
            assert_eq!(decompose_hint(0, mode), 0);
            assert_eq!(decompose_hint(alpha / 2 - 1, mode), 0);
            assert_eq!(decompose_hint(alpha / 2, mode), 1);
        }
    }

    #[test]
    fn vk_recomposition() {
        for a in 0..Q {
            let (high, low) = decompose_vk(a);
            assert!((-1..=1).contains(&low));
            assert_eq!(high * 2 + low, a);
        }
    }

    #[test]
    fn crt_reconstruction() {
        for xq in 0..Q {
            for parity in 0..=1 {
                let value = fromcrt(xq, parity);
                assert!((0..2 * Q).contains(&value));
                assert_eq!(value % Q, xq);
                assert_eq!(value & 1, parity);
            }
            assert_eq!(fromcrt0(xq) & 1, 0);
        }
    }
}
