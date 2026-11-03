//! HAETAE 1.2.0 fixed-point squared singular-value estimator.
//!
//! Mirrors reference polyvecmk_sk_singular_value.
//! This module is not yet authenticated by differential testing.
//! Signed wrapping is explicit; C overflow equivalence is not assumed.

use crate::fixed_fft::{fft, init_and_bitrev, squared_abs, FFT_N};
use crate::params::ParameterSet;
use crate::poly::Poly;
use crate::polyvec::{PolyVecK, PolyVecM};

#[inline]
fn minmax(x: &mut i32, y: &mut i32) {
    let a = *x;
    let b = *y;
    let ab = b ^ a;
    let mut c = b.wrapping_sub(a);
    c ^= ab & (c ^ b);
    c >>= 31;
    c &= ab;
    *x = a ^ c;
    *y = b ^ c;
}

fn accumulate(sum: &mut [i32; FFT_N], polynomial: &Poly) {
    let mut input = init_and_bitrev(polynomial);
    fft(&mut input);

    for (sum_value, coefficient) in sum.iter_mut().zip(input.iter()) {
        *sum_value = sum_value.wrapping_add(squared_abs(*coefficient));
    }
}

fn select_and_round(mut sum: [i32; FFT_N], tau: usize) -> i64 {
    assert!(tau > 0 && tau <= FFT_N);

    let count = FFT_N / tau + 1;
    let mut bestm = vec![0_i32; count];
    bestm.copy_from_slice(&sum[..count]);

    for value in sum.iter_mut().skip(count) {
        for selected in &mut bestm {
            minmax(value, selected);
        }
    }

    let mut minimum = bestm[0];

    for &value in bestm.iter().skip(1) {
        let mut temporary = value;
        minmax(&mut minimum, &mut temporary);
    }

    let mut result = 0_i32;

    for value in bestm {
        let mut factor = minimum.wrapping_sub(value) >> 31;

        factor = (factor & tau as i32) ^ ((!factor) & (FFT_N % tau) as i32);

        let rounded = value.wrapping_add(0x10200) >> 10;
        let weighted = rounded.wrapping_mul(factor);

        result = result.wrapping_add(weighted);
    }

    i64::from(result.wrapping_add(1 << 5) >> 6)
}

/// Computes the reference squared singular-value estimate.
///
/// The caller must supply the correct key-generation-stage secret
/// vectors. In particular, HAETAE-2/3 use the adjusted s2 vector.
pub fn squared_singular_value<const M: usize, const K: usize>(
    s1: &PolyVecM<M>,
    s2: &PolyVecK<K>,
    mode: ParameterSet,
) -> i64 {
    let parameters = mode.parameters();

    assert_eq!(M, parameters.l - 1, "M dimension mismatch");
    assert_eq!(K, parameters.k, "K dimension mismatch");

    let tau = match mode {
        ParameterSet::Haetae2 => 58,
        ParameterSet::Haetae3 => 80,
        ParameterSet::Haetae5 => 128,
    };

    let mut sum = [0_i32; FFT_N];

    for polynomial in s1.as_slice() {
        accumulate(&mut sum, polynomial);
    }

    for polynomial in s2.as_slice() {
        accumulate(&mut sum, polynomial);
    }

    select_and_round(sum, tau)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::polyvec::PolyVec;

    #[test]
    fn minmax_orders_values() {
        for (a, b) in [(0, 0), (1, 2), (2, 1), (-2, 3), (3, -2), (-10, -20)] {
            let mut x = a;
            let mut y = b;
            minmax(&mut x, &mut y);
            assert_eq!((x, y), (a.min(b), a.max(b)));
        }
    }

    #[test]
    fn zero_spectrum_rounding_all_modes() {
        for (tau, expected) in [(58, 120), (80, 64), (128, 0)] {
            assert_eq!(select_and_round([0; FFT_N], tau), expected);
        }
    }

    #[test]
    fn zero_vectors_all_modes() {
        let m2 = PolyVecM::<3>(PolyVec::default());
        let k2 = PolyVecK::<2>(PolyVec::default());
        assert_eq!(squared_singular_value(&m2, &k2, ParameterSet::Haetae2), 120);

        let m3 = PolyVecM::<5>(PolyVec::default());
        let k3 = PolyVecK::<3>(PolyVec::default());
        assert_eq!(squared_singular_value(&m3, &k3, ParameterSet::Haetae3), 64);

        let m5 = PolyVecM::<6>(PolyVec::default());
        let k5 = PolyVecK::<4>(PolyVec::default());
        assert_eq!(squared_singular_value(&m5, &k5, ParameterSet::Haetae5), 0);
    }

    #[test]
    fn deterministic_nonzero_vectors() {
        let mut m = PolyVecM::<3>(PolyVec::default());
        let mut k = PolyVecK::<2>(PolyVec::default());

        m.0.vec[0].coeffs[0] = 1;
        k.0.vec[0].coeffs[1] = -1;

        let first = squared_singular_value(&m, &k, ParameterSet::Haetae2);
        let second = squared_singular_value(&m, &k, ParameterSet::Haetae2);

        assert_eq!(first, second);
        assert!(first >= 256);
    }
}
