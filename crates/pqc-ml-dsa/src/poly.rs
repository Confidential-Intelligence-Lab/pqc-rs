//! ML-DSA polynomial representation and arithmetic.

use crate::constants::{N, Q};
use crate::ntt;
use crate::reduce::{freeze, montgomery_reduce, reduce32};

/// Polynomial in `R_q = Z_q[X] / (X^256 + 1)`.
#[derive(Clone, Eq, PartialEq)]
pub struct Poly {
    coeffs: [i32; N],
}

impl Poly {
    /// Construct the zero polynomial.
    pub const fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Construct a polynomial from coefficients.
    pub const fn from_coeffs(coeffs: [i32; N]) -> Self {
        Self { coeffs }
    }

    /// Borrow all coefficients.
    pub const fn coeffs(&self) -> &[i32; N] {
        &self.coeffs
    }

    /// Mutably borrow all coefficients.
    pub fn coeffs_mut(&mut self) -> &mut [i32; N] {
        &mut self.coeffs
    }

    /// Reduce every coefficient.
    pub fn reduce(&mut self) {
        for coefficient in &mut self.coeffs {
            *coefficient = reduce32(*coefficient);
        }
    }

    /// Canonicalize every coefficient into `[0, Q)`.
    pub fn freeze(&mut self) {
        for coefficient in &mut self.coeffs {
            *coefficient = freeze(*coefficient);
        }
    }

    /// Add another polynomial coefficient-wise.
    pub fn add_assign(&mut self, rhs: &Self) {
        for (left, right) in self.coeffs.iter_mut().zip(rhs.coeffs) {
            *left = left.wrapping_add(right);
        }
    }

    /// Subtract another polynomial coefficient-wise.
    pub fn sub_assign(&mut self, rhs: &Self) {
        for (left, right) in self.coeffs.iter_mut().zip(rhs.coeffs) {
            *left = left.wrapping_sub(right);
        }
    }

    /// Apply the forward NTT in place.
    pub fn ntt(&mut self) {
        ntt::forward(&mut self.coeffs);
    }

    /// Apply the inverse NTT and Montgomery scaling in place.
    pub fn inv_ntt_to_mont(&mut self) {
        ntt::inverse_to_mont(&mut self.coeffs);
    }

    /// Pointwise Montgomery multiplication in the NTT domain.
    pub fn pointwise_montgomery(&self, rhs: &Self) -> Self {
        let mut output = [0_i32; N];

        for ((out, left), right) in output.iter_mut().zip(self.coeffs).zip(rhs.coeffs) {
            *out = montgomery_reduce(i64::from(left) * i64::from(right));
        }

        Self::from_coeffs(output)
    }

    /// Return true when every coefficient is canonical.
    pub fn is_canonical(&self) -> bool {
        self.coeffs.iter().all(|value| (0..Q).contains(value))
    }
}

impl Default for Poly {
    fn default() -> Self {
        Self::zero()
    }
}
