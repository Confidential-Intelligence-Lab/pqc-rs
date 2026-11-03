//! HAETAE 1.2.0 polynomial operations.
//!
//! Experimental implementation following the authenticated C reference.
//! Arithmetic operations preserve unreduced coefficients.

use crate::decompose::{decompose_z1, fromcrt, fromcrt0};
use crate::montgomery::montgomery_reduce;
use crate::ntt;
use crate::params::N;

/// Polynomial with signed coefficients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0; N] }
    }
}

// H1.1-B.4: reference reciprocal reductions
const Q_REF: i64 = 64_513;
const DQ_REF: i64 = 129_026;
const QREC: i64 = 66_575;
const DQREC: i64 = 33_287;

#[inline]
fn freeze_coefficient(a: i32) -> i32 {
    let mut t = (i64::from(a) * QREC) >> 32;
    t = i64::from(a) - t * Q_REF;
    t += (t >> 63) & DQ_REF;
    t -= !((t - Q_REF) >> 63) & Q_REF;
    t as i32
}

#[inline]
fn freeze2q_coefficient(a: i32) -> i32 {
    let mut t = (i64::from(a) * DQREC) >> 32;
    t = i64::from(a) - t * DQ_REF;
    t += (t >> 63) & (2 * DQ_REF);
    t -= !((t - DQ_REF) >> 63) & DQ_REF;
    t as i32
}

#[inline]
fn reduce2q_coefficient(a: i32) -> i32 {
    let mut t = (i64::from(a) * DQREC) >> 32;
    t = i64::from(a) - t * DQ_REF;
    t += (t >> 63) & (2 * DQ_REF);
    t -= !((t - DQ_REF) >> 63) & DQ_REF;
    t -= !((t - Q_REF) >> 63) & DQ_REF;
    t as i32
}

impl Poly {
    /// Construct a polynomial from its coefficients.
    pub const fn new(coeffs: [i32; N]) -> Self {
        Self { coeffs }
    }

    /// Coefficient-wise addition without modular reduction.
    ///
    /// Inputs must have sums representable as `i32`.
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0_i32; N];

        for (i, coefficient) in result.iter_mut().enumerate() {
            *coefficient = self.coeffs[i]
                .checked_add(other.coeffs[i])
                .expect("HAETAE polynomial addition overflow");
        }

        Self::new(result)
    }

    /// Coefficient-wise subtraction without modular reduction.
    ///
    /// Inputs must have differences representable as `i32`.
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [0_i32; N];

        for (i, coefficient) in result.iter_mut().enumerate() {
            *coefficient = self.coeffs[i]
                .checked_sub(other.coeffs[i])
                .expect("HAETAE polynomial subtraction overflow");
        }

        Self::new(result)
    }

    /// Pointwise multiplication with Montgomery reduction.
    ///
    /// Inputs are expected to be in the NTT domain.
    pub fn pointwise_montgomery(&self, other: &Self) -> Self {
        let mut result = [0_i32; N];

        for (i, coefficient) in result.iter_mut().enumerate() {
            *coefficient =
                montgomery_reduce(i64::from(self.coeffs[i]) * i64::from(other.coeffs[i]));
        }

        Self::new(result)
    }

    /// Forward in-place NTT.
    pub fn ntt(&mut self) {
        ntt::forward(&mut self.coeffs);
    }

    /// Inverse in-place NTT with Montgomery scaling.
    pub fn invntt_tomont(&mut self) {
        ntt::inverse_to_mont(&mut self.coeffs);
    }

    /// Canonical coefficient reduction modulo q.
    pub fn freeze(&mut self) {
        for coefficient in &mut self.coeffs {
            *coefficient = freeze_coefficient(*coefficient);
        }
    }

    /// Canonical coefficient reduction modulo 2q.
    pub fn freeze2q(&mut self) {
        for coefficient in &mut self.coeffs {
            *coefficient = freeze2q_coefficient(*coefficient);
        }
    }

    /// Centered coefficient reduction modulo 2q.
    pub fn reduce2q(&mut self) {
        for coefficient in &mut self.coeffs {
            *coefficient = reduce2q_coefficient(*coefficient);
        }
    }

    /// High coefficients of signed radix-256 decomposition.
    pub fn highbits(&self) -> Self {
        let mut result = [0_i32; N];
        for (i, value) in result.iter_mut().enumerate() {
            *value = decompose_z1(self.coeffs[i]).0;
        }
        Self::new(result)
    }

    /// Low coefficients of signed radix-256 decomposition.
    pub fn lowbits(&self) -> Self {
        let mut result = [0_i32; N];
        for (i, value) in result.iter_mut().enumerate() {
            *value = decompose_z1(self.coeffs[i]).1;
        }
        Self::new(result)
    }

    /// Recompose high and low coefficients without modular reduction.
    ///
    /// Inputs must produce results representable as i32.
    pub fn compose(high: &Self, low: &Self) -> Self {
        let mut result = [0_i32; N];
        for (i, value) in result.iter_mut().enumerate() {
            *value = high.coeffs[i]
                .checked_mul(256)
                .and_then(|x| x.checked_add(low.coeffs[i]))
                .expect("HAETAE polynomial composition overflow");
        }
        Self::new(result)
    }

    /// Extract the least significant bit of each coefficient.
    pub fn lsb(&self) -> Self {
        let mut result = [0_i32; N];
        for (i, value) in result.iter_mut().enumerate() {
            *value = self.coeffs[i] & 1;
        }
        Self::new(result)
    }

    /// Reconstruct coefficients modulo 2q from modulo-q residues and parity.
    ///
    /// Self must contain canonical residues in [0, q).
    pub fn fromcrt(&self, parity: &Self) -> Self {
        let mut result = [0_i32; N];
        for (i, value) in result.iter_mut().enumerate() {
            *value = fromcrt(self.coeffs[i], parity.coeffs[i] & 1);
        }
        Self::new(result)
    }

    /// Reconstruct coefficients modulo 2q assuming even parity.
    ///
    /// Self must contain canonical residues in [0, q).
    pub fn fromcrt0(&self) -> Self {
        let mut result = [0_i32; N];
        for (i, value) in result.iter_mut().enumerate() {
            *value = fromcrt0(self.coeffs[i]);
        }
        Self::new(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::reduce;
    use crate::montgomery::MONT;
    use crate::params::Q;

    #[test]
    fn decomposition_recomposition() {
        let mut coefficients = [0_i32; N];
        for (i, value) in coefficients.iter_mut().enumerate() {
            *value = (i as i32 - 128) * 257;
        }

        let poly = Poly::new(coefficients);
        let high = poly.highbits();
        let low = poly.lowbits();

        assert_eq!(Poly::compose(&high, &low), poly);
        assert!(low.coeffs.iter().all(|&x| (-128..128).contains(&x)));
    }

    #[test]
    fn polynomial_lsb() {
        let mut coefficients = [0_i32; N];
        for (i, value) in coefficients.iter_mut().enumerate() {
            *value = i as i32 - 128;
        }

        let poly = Poly::new(coefficients);
        let parity = poly.lsb();

        for (actual, coefficient) in parity.coeffs.iter().zip(coefficients.iter()) {
            assert_eq!(*actual, *coefficient & 1);
        }
    }

    #[test]
    fn polynomial_crt() {
        use crate::params::Q;

        let mut coefficients = [0_i32; N];
        let mut bits = [0_i32; N];

        for (i, coefficient) in coefficients.iter_mut().enumerate() {
            *coefficient = (i as i32 * 257).rem_euclid(Q);
            bits[i] = (i as i32) & 1;
        }

        let residues = Poly::new(coefficients);
        let parity = Poly::new(bits);

        let reconstructed = residues.fromcrt(&parity);
        let reconstructed_zero = residues.fromcrt0();

        for (i, coefficient) in coefficients.iter().enumerate() {
            assert_eq!(reconstructed.coeffs[i] % Q, *coefficient);
            assert_eq!(reconstructed.coeffs[i] & 1, bits[i]);
            assert_eq!(reconstructed_zero.coeffs[i] & 1, 0);
        }
    }

    #[test]
    fn zero_and_construction() {
        let zero = Poly::default();
        assert!(zero.coeffs.iter().all(|&x| x == 0));

        let input = [7_i32; N];
        assert_eq!(Poly::new(input).coeffs, input);
    }

    #[test]
    fn addition_and_subtraction_are_unreduced() {
        let a = Poly::new([Q - 1; N]);
        let b = Poly::new([Q - 1; N]);

        let sum = a.add(&b);
        assert!(sum.coeffs.iter().all(|&x| x == 2 * (Q - 1)));

        let difference = sum.sub(&a);
        assert_eq!(difference, b);
    }

    #[test]
    fn pointwise_montgomery_matches_scalar() {
        let a = Poly::new([1234; N]);
        let b = Poly::new([-5678; N]);

        let result = a.pointwise_montgomery(&b);
        let expected = montgomery_reduce(1234_i64 * -5678_i64);

        assert!(result.coeffs.iter().all(|&x| x == expected));
    }

    #[test]
    fn polynomial_ntt_round_trip() {
        let mut coefficients = [0_i32; N];

        for (i, coefficient) in coefficients.iter_mut().enumerate() {
            *coefficient = (i as i32 * 173).rem_euclid(Q);
        }

        let original = coefficients;
        let mut polynomial = Poly::new(coefficients);

        polynomial.ntt();
        polynomial.invntt_tomont();

        for (actual, expected) in polynomial.coeffs.iter().zip(original.iter()) {
            assert_eq!(
                reduce(i64::from(*actual)),
                reduce(i64::from(*expected) * i64::from(MONT)),
            );
        }
    }

    #[test]
    #[should_panic(expected = "HAETAE polynomial addition overflow")]
    fn addition_rejects_overflow() {
        let a = Poly::new([i32::MAX; N]);
        let b = Poly::new([1; N]);
        let _ = a.add(&b);
    }

    #[test]
    fn reference_reduction_boundaries() {
        const Q: i32 = 64_513;
        const DQ: i32 = 129_026;

        let values = [-DQ - 1, -DQ, -Q, -1, 0, 1, Q - 1, Q, DQ - 1, DQ, DQ + 1];

        for value in values {
            let mut a = Poly::new([value; N]);
            let mut b = a.clone();
            let mut c = a.clone();

            a.freeze();
            b.freeze2q();
            c.reduce2q();

            let expected_q = value.rem_euclid(Q);
            let expected_dq = value.rem_euclid(DQ);
            let expected_centered = if expected_dq >= Q {
                expected_dq - DQ
            } else {
                expected_dq
            };

            assert_eq!(a.coeffs[0], expected_q);
            assert_eq!(b.coeffs[0], expected_dq);
            assert_eq!(c.coeffs[0], expected_centered);

            assert!(a.coeffs.iter().all(|&x| x == expected_q));
            assert!(b.coeffs.iter().all(|&x| x == expected_dq));
            assert!(c.coeffs.iter().all(|&x| x == expected_centered));
        }
    }
}
