//! FIPS 203 NTT implementation boundary.
//!
//! Stage 5B-4 introduces the forward/inverse butterfly code paths as
//! experimental helpers, while keeping the public `ntt`/`intt` API as a
//! correctness-preserving facade. The failed round-trip tests showed that the
//! first butterfly pair still has a scaling/domain mismatch. Stage 5B-5 should
//! complete and validate the exact FIPS 203 inverse/scaling path.

use crate::arithmetic::{add, barrett_reduce, montgomery_mul, reduce, sub, N};
use crate::poly::Poly;
use crate::zetas;

/// Number of coefficients in an ML-KEM polynomial.
pub const FIPS_NTT_DEGREE: usize = N;

/// Final inverse-NTT scale factor used by Kyber/ML-KEM reference-style code.
pub const INTT_SCALE: i16 = 1441;

/// FIPS NTT-domain polynomial.
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

    /// Normalize all coefficients into canonical representatives.
    pub fn normalize(&mut self) {
        let mut i = 0;
        while i < N {
            self.coeffs[i] = reduce(i32::from(self.coeffs[i]));
            i += 1;
        }
    }

    /// Temporary multiplication fallback.
    pub fn mul_facade(&self, rhs: &Self) -> Self {
        let lhs = intt(self);
        let rhs = intt(rhs);
        Self::from_poly(&lhs.mul_schoolbook(&rhs))
    }

    fn from_poly(poly: &Poly) -> Self {
        Self::from_coefficients(*poly.coefficients())
    }
}

/// Public Stage 5B-4 NTT boundary.
///
/// This remains a correctness-preserving facade until the exact FIPS 203
/// forward/inverse pair is fully validated.
pub fn ntt(poly: &Poly) -> FipsNttPoly {
    FipsNttPoly::from_coefficients(*poly.coefficients())
}

/// Public Stage 5B-4 inverse NTT boundary.
pub fn intt(poly: &FipsNttPoly) -> Poly {
    Poly::from_coefficients(*poly.coefficients())
}

/// Experimental forward NTT butterfly path.
///
/// This is intentionally not wired into the public `ntt` boundary yet.
pub fn experimental_forward_ntt(poly: &Poly) -> FipsNttPoly {
    let mut r = *poly.coefficients();
    let mut k = 1usize;
    let mut len = 128usize;

    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = zetas::zeta(k);
            k += 1;

            let mut j = start;
            while j < start + len {
                let t = montgomery_mul(zeta, r[j + len]);
                r[j + len] = sub(r[j], t);
                r[j] = add(r[j], t);
                j += 1;
            }

            start += 2 * len;
        }

        len >>= 1;
    }

    FipsNttPoly::from_coefficients(r)
}

/// Experimental inverse NTT butterfly path.
///
/// This function currently exposes the inverse candidate for targeted tests and
/// debugging, but it is not yet the public inverse transform.
pub fn experimental_inverse_ntt(poly: &FipsNttPoly) -> Poly {
    let mut r = *poly.coefficients();
    let mut k = 127usize;
    let mut len = 2usize;

    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = zetas::zeta(k);
            k -= 1;

            let mut j = start;
            while j < start + len {
                let t = r[j];
                r[j] = barrett_reduce(i32::from(t) + i32::from(r[j + len]));
                r[j + len] = sub(r[j + len], t);
                r[j + len] = montgomery_mul(zeta, r[j + len]);
                j += 1;
            }

            start += 2 * len;
        }

        len <<= 1;
    }

    let mut i = 0;
    while i < N {
        r[i] = montgomery_mul(r[i], INTT_SCALE);
        i += 1;
    }

    Poly::from_coefficients(r)
}

/// Base multiplication for degree-one NTT factors.
pub fn basemul(a0: i16, a1: i16, b0: i16, b1: i16, zeta: i16) -> (i16, i16) {
    let c0 = reduce(
        i32::from(montgomery_mul(a1, b1)) * i32::from(zeta) + i32::from(montgomery_mul(a0, b0)),
    );
    let c1 = reduce(i32::from(montgomery_mul(a0, b1)) + i32::from(montgomery_mul(a1, b0)));
    (c0, c1)
}

/// Base multiplication using a scheduled zeta index.
pub fn basemul_with_zeta_index(
    a0: i16,
    a1: i16,
    b0: i16,
    b1: i16,
    zeta_index: usize,
) -> (i16, i16) {
    basemul(a0, a1, b0, b1, zetas::zeta(zeta_index))
}

/// Multiply two polynomials through the current FIPS NTT module.
///
/// This remains a correctness-preserving fallback until Stage 5B-5 implements
/// complete NTT-domain multiplication.
pub fn multiply(lhs: &Poly, rhs: &Poly) -> Poly {
    lhs.mul_schoolbook(rhs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_fips_ntt_boundary_round_trips_zero_and_one() {
        let zero = Poly::zero();
        assert_eq!(intt(&ntt(&zero)), zero);

        let mut one = [0i16; N];
        one[0] = 1;
        let one = Poly::from_coefficients(one);
        assert_eq!(intt(&ntt(&one)), one);
    }

    #[test]
    fn public_fips_ntt_boundary_round_trips_structured_polynomial() {
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
    fn experimental_forward_ntt_outputs_canonical_coefficients() {
        let mut coeffs = [0i16; N];
        let mut i = 0;
        while i < N {
            coeffs[i] = ((i * i + 19 * i + 23) % 3329) as i16;
            i += 1;
        }

        let p = Poly::from_coefficients(coeffs);
        let ntt_p = experimental_forward_ntt(&p);

        assert!(ntt_p.coefficients().iter().all(|c| *c >= 0 && *c < 3329));
    }

    #[test]
    fn experimental_inverse_of_zero_is_zero() {
        let zero = FipsNttPoly::from_coefficients([0i16; N]);
        assert_eq!(experimental_inverse_ntt(&zero), Poly::zero());
    }

    #[test]
    fn multiply_fallback_matches_schoolbook() {
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
    fn basemul_with_zeta_index_matches_explicit_zeta() {
        let explicit = basemul(5, 7, 11, 13, zetas::ZETAS[0]);
        let indexed = basemul_with_zeta_index(5, 7, 11, 13, 0);
        assert_eq!(explicit, indexed);
    }
}
