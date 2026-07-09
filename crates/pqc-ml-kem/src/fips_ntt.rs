//! FIPS 203 NTT implementation boundary.
//!
//! Stage 5A introduces a dedicated FIPS NTT facade separate from the Stage 4
//! identity-domain boundary. The transform functions remain identity mappings
//! until Stage 5B replaces them with the exact FIPS 203 zeta schedule and
//! butterfly ordering.

use crate::arithmetic::{mul, reduce, N};
use crate::poly::Poly;

/// Number of coefficients in an ML-KEM polynomial.
pub const FIPS_NTT_DEGREE: usize = N;

/// FIPS NTT-domain polynomial facade.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FipsNttPoly {
    coeffs: [i16; N],
}

impl FipsNttPoly {
    /// Construct from coefficients.
    pub fn from_coefficients(coeffs: [i16; N]) -> Self {
        let mut out = [0i16; N];
        let mut i = 0;
        while i < N {
            out[i] = reduce(i32::from(coeffs[i]));
            i += 1;
        }
        Self { coeffs: out }
    }

    /// Borrow coefficients.
    pub fn coefficients(&self) -> &[i16; N] {
        &self.coeffs
    }

    /// Multiply through the Stage 5A facade.
    pub fn mul_facade(&self, rhs: &Self) -> Self {
        let lhs = Poly::from_coefficients(self.coeffs);
        let rhs = Poly::from_coefficients(rhs.coeffs);
        Self::from_poly(&lhs.mul_schoolbook(&rhs))
    }

    fn from_poly(poly: &Poly) -> Self {
        Self::from_coefficients(*poly.coefficients())
    }
}

/// Placeholder FIPS 203 forward NTT facade.
///
/// This is intentionally an identity mapping in Stage 5A. It establishes the
/// module boundary used by K-PKE while avoiding a false claim of compliance.
pub fn ntt(poly: &Poly) -> FipsNttPoly {
    FipsNttPoly::from_coefficients(*poly.coefficients())
}

/// Placeholder FIPS 203 inverse NTT facade.
pub fn intt(poly: &FipsNttPoly) -> Poly {
    Poly::from_coefficients(poly.coeffs)
}

/// Placeholder base multiplication for degree-one NTT factors.
///
/// Stage 5B should replace this with the exact FIPS 203 `basemul` operation.
pub fn basemul(a0: i16, a1: i16, b0: i16, b1: i16, zeta: i16) -> (i16, i16) {
    let c0 = reduce(i32::from(mul(a1, b1)) * i32::from(zeta) + i32::from(mul(a0, b0)));
    let c1 = reduce(i32::from(mul(a0, b1)) + i32::from(mul(a1, b0)));
    (c0, c1)
}

/// Multiply two polynomials through the Stage 5A FIPS NTT facade.
pub fn multiply(lhs: &Poly, rhs: &Poly) -> Poly {
    intt(&ntt(lhs).mul_facade(&ntt(rhs)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fips_ntt_facade_round_trips() {
        let mut coeffs = [0i16; N];
        let mut i = 0;
        while i < N {
            coeffs[i] = ((17 * i + 5) % 3329) as i16;
            i += 1;
        }

        let p = Poly::from_coefficients(coeffs);
        assert_eq!(intt(&ntt(&p)), p);
    }

    #[test]
    fn fips_ntt_facade_multiplication_matches_schoolbook() {
        let mut a = [0i16; N];
        let mut b = [0i16; N];

        let mut i = 0;
        while i < 8 {
            a[i] = (i as i16) + 3;
            b[i] = (2 * i as i16) + 1;
            i += 1;
        }

        let pa = Poly::from_coefficients(a);
        let pb = Poly::from_coefficients(b);
        assert_eq!(multiply(&pa, &pb), pa.mul_schoolbook(&pb));
    }

    #[test]
    fn basemul_shape_is_stable() {
        let (c0, c1) = basemul(1, 2, 3, 4, 17);
        assert_eq!(c0, reduce(3 + 2 * 4 * 17));
        assert_eq!(c1, reduce(4 + 2 * 3));
    }
}
