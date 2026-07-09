//! Baseline NTT-domain boundary for ML-KEM.
//!
//! Stage 4 intentionally exposes the NTT-domain API boundary without claiming a
//! production FIPS 203 NTT implementation. The current transform is an identity
//! boundary used to keep the K-PKE module structure testable while the real zeta
//! schedule, butterfly ordering, and inverse transform are introduced in Stage 5.

use crate::arithmetic::{mul, reduce, N, Q};
use crate::poly::Poly;

/// Placeholder root marker retained for the Stage 5 FIPS 203 NTT handoff.
pub const BASELINE_ROOT_256: i16 = 17;

/// Polynomial represented at the Stage 4 NTT boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NttPoly {
    coeffs: [i16; N],
}

impl NttPoly {
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

    /// Borrow NTT-boundary coefficients.
    pub fn coefficients(&self) -> &[i16; N] {
        &self.coeffs
    }

    /// Boundary-domain coefficient-wise addition.
    pub fn add(&self, rhs: &Self) -> Self {
        let lhs = Poly::from_coefficients(self.coeffs);
        let rhs = Poly::from_coefficients(rhs.coeffs);
        Self::from_poly(&lhs.add(&rhs))
    }

    /// Boundary-domain multiplication.
    ///
    /// In Stage 4 this is intentionally not pointwise FIPS NTT multiplication.
    /// It converts back to the coefficient-domain baseline and uses schoolbook
    /// negacyclic multiplication. Stage 5 should replace this with true NTT
    /// pointwise multiplication.
    pub fn mul_boundary(&self, rhs: &Self) -> Self {
        let lhs = Poly::from_coefficients(self.coeffs);
        let rhs = Poly::from_coefficients(rhs.coeffs);
        Self::from_poly(&lhs.mul_schoolbook(&rhs))
    }

    fn from_poly(poly: &Poly) -> Self {
        Self::from_coefficients(*poly.coefficients())
    }
}

/// Compute `base^exp mod Q`.
///
/// This helper remains useful for Stage 5 NTT work and modular arithmetic tests.
pub fn pow_mod(base: i16, exp: usize) -> i16 {
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

/// Multiplicative inverse modulo `Q`.
pub fn inv_mod(x: i16) -> i16 {
    pow_mod(x, (Q as usize) - 2)
}

/// Stage 4 NTT boundary transform.
///
/// This is an identity transform by design. It validates module boundaries,
/// data ownership, type shapes, and round-trip behavior before Stage 5 replaces
/// it with the FIPS 203 NTT.
pub fn ntt_baseline(poly: &Poly) -> NttPoly {
    NttPoly::from_coefficients(*poly.coefficients())
}

/// Stage 4 inverse NTT boundary transform.
pub fn intt_baseline(ntt: &NttPoly) -> Poly {
    Poly::from_coefficients(ntt.coeffs)
}

/// Multiply through the Stage 4 NTT boundary.
pub fn mul_ntt_baseline(lhs: &Poly, rhs: &Poly) -> Poly {
    let lhs_ntt = ntt_baseline(lhs);
    let rhs_ntt = ntt_baseline(rhs);
    intt_baseline(&lhs_ntt.mul_boundary(&rhs_ntt))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modular_inverse_works() {
        for x in [1, 2, 3, 17, 3328] {
            assert_eq!(mul(x, inv_mod(x)), 1);
        }
    }

    #[test]
    fn stage4_ntt_boundary_round_trip_zero_and_one() {
        let zero = Poly::zero();
        assert_eq!(intt_baseline(&ntt_baseline(&zero)), zero);

        let mut one = [0i16; N];
        one[0] = 1;
        let one = Poly::from_coefficients(one);
        assert_eq!(intt_baseline(&ntt_baseline(&one)), one);
    }

    #[test]
    fn stage4_ntt_boundary_round_trip_structured_poly() {
        let mut coeffs = [0i16; N];
        let mut i = 0;
        while i < N {
            coeffs[i] = ((i * i + 3 * i + 7) % 3329) as i16;
            i += 1;
        }

        let p = Poly::from_coefficients(coeffs);
        assert_eq!(intt_baseline(&ntt_baseline(&p)), p);
    }

    #[test]
    fn stage4_boundary_multiplication_matches_schoolbook() {
        let mut a = [0i16; N];
        let mut b = [0i16; N];

        let mut i = 0;
        while i < 16 {
            a[i] = (i as i16) + 1;
            b[i] = (3 * i as i16) + 2;
            i += 1;
        }

        let pa = Poly::from_coefficients(a);
        let pb = Poly::from_coefficients(b);
        assert_eq!(mul_ntt_baseline(&pa, &pb), pa.mul_schoolbook(&pb));
    }
}
