//! Reference-compatible ML-KEM NTT arithmetic.
//!
//! The forward transform maps standard-order coefficients to bit-reversed
//! NTT order. `invntt_tomont` maps bit-reversed NTT coefficients back to
//! standard order while multiplying by the Montgomery factor. The convenience
//! `intt` function removes that factor to provide an ordinary round trip.

use crate::arithmetic::{add, from_montgomery, montgomery_mul, reduce, sub, N};
use crate::poly::Poly;
use crate::zetas::ZETAS;

/// Inverse-transform scale `mont^2 / 128`.
pub const INTT_SCALE: i16 = 1441;

/// Polynomial in ML-KEM NTT representation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FipsNttPoly {
    coeffs: [i16; N],
}

impl FipsNttPoly {
    /// Construct from NTT coefficients.
    pub fn from_coefficients(coeffs: [i16; N]) -> Self {
        let mut out = [0i16; N];
        let mut i = 0;
        while i < N {
            out[i] = reduce(i32::from(coeffs[i]));
            i += 1;
        }
        Self { coeffs: out }
    }

    /// Borrow the NTT coefficients.
    pub fn coefficients(&self) -> &[i16; N] {
        &self.coeffs
    }
}

/// Compute the reference-compatible forward NTT.
pub fn ntt(poly: &Poly) -> FipsNttPoly {
    let mut r = *poly.coefficients();
    let mut k = 1usize;
    let mut len = 128usize;

    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
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

/// Compute the reference-compatible inverse NTT and multiply by `R`.
pub fn invntt_tomont(poly: &FipsNttPoly) -> Poly {
    let mut r = *poly.coefficients();
    let mut k = 127usize;
    let mut len = 2usize;

    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;

            let mut j = start;
            while j < start + len {
                let t = r[j];
                r[j] = add(t, r[j + len]);
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

/// Compute an ordinary inverse transform by removing the Montgomery factor.
pub fn intt(poly: &FipsNttPoly) -> Poly {
    let mont = invntt_tomont(poly);
    let mut out = [0i16; N];

    let mut i = 0;
    while i < N {
        out[i] = from_montgomery(mont.coefficients()[i]);
        i += 1;
    }

    Poly::from_coefficients(out)
}

/// Multiply two degree-one factors in `Z_q[X] / (X^2 - zeta)`.
pub fn basemul(a0: i16, a1: i16, b0: i16, b1: i16, zeta: i16) -> (i16, i16) {
    let mut c0 = montgomery_mul(a1, b1);
    c0 = montgomery_mul(c0, zeta);
    c0 = add(c0, montgomery_mul(a0, b0));

    let c1 = add(montgomery_mul(a0, b1), montgomery_mul(a1, b0));

    (c0, c1)
}

/// Multiply two complete polynomials in NTT representation.
pub fn basemul_polynomials(lhs: &FipsNttPoly, rhs: &FipsNttPoly) -> FipsNttPoly {
    let a = lhs.coefficients();
    let b = rhs.coefficients();
    let mut r = [0i16; N];

    let mut i = 0usize;
    while i < N / 4 {
        let zeta = ZETAS[64 + i];

        let (r0, r1) = basemul(a[4 * i], a[4 * i + 1], b[4 * i], b[4 * i + 1], zeta);
        r[4 * i] = r0;
        r[4 * i + 1] = r1;

        let (r2, r3) = basemul(
            a[4 * i + 2],
            a[4 * i + 3],
            b[4 * i + 2],
            b[4 * i + 3],
            -zeta,
        );
        r[4 * i + 2] = r2;
        r[4 * i + 3] = r3;

        i += 1;
    }

    FipsNttPoly::from_coefficients(r)
}

/// Multiply two coefficient-domain polynomials through the ML-KEM NTT path.
pub fn multiply(lhs: &Poly, rhs: &Poly) -> Poly {
    let lhs_ntt = ntt(lhs);
    let rhs_ntt = ntt(rhs);
    let product_ntt = basemul_polynomials(&lhs_ntt, &rhs_ntt);
    invntt_tomont(&product_ntt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::to_montgomery;

    fn structured_poly(multiplier: usize, offset: usize) -> Poly {
        let mut coeffs = [0i16; N];
        let mut i = 0;
        while i < N {
            coeffs[i] = ((multiplier * i + offset) % 3329) as i16;
            i += 1;
        }
        Poly::from_coefficients(coeffs)
    }

    #[test]
    fn forward_and_convenience_inverse_round_trip() {
        let p = structured_poly(17, 5);
        assert_eq!(intt(&ntt(&p)), p);
    }

    #[test]
    fn reference_inverse_returns_montgomery_scaled_input() {
        let p = structured_poly(11, 7);
        let recovered = invntt_tomont(&ntt(&p));

        for (actual, original) in recovered.coefficients().iter().zip(p.coefficients().iter()) {
            assert_eq!(*actual, to_montgomery(*original));
        }
    }

    #[test]
    fn ntt_multiplication_matches_schoolbook_sparse() {
        let mut a = [0i16; N];
        let mut b = [0i16; N];

        let mut i = 0;
        while i < 16 {
            a[i] = (i as i16) + 1;
            b[i] = (2 * i as i16) + 1;
            i += 1;
        }

        let lhs = Poly::from_coefficients(a);
        let rhs = Poly::from_coefficients(b);

        assert_eq!(multiply(&lhs, &rhs), lhs.mul_schoolbook(&rhs));
    }

    #[test]
    fn ntt_multiplication_matches_schoolbook_dense() {
        let lhs = structured_poly(17, 5);
        let rhs = structured_poly(29, 3);

        assert_eq!(multiply(&lhs, &rhs), lhs.mul_schoolbook(&rhs));
    }

    #[test]
    fn base_multiplication_uses_positive_and_negative_zetas() {
        let lhs = ntt(&structured_poly(3, 1));
        let rhs = ntt(&structured_poly(5, 2));
        let product = basemul_polynomials(&lhs, &rhs);

        assert_eq!(product.coefficients().len(), N);
        assert!(product
            .coefficients()
            .iter()
            .all(|coefficient| *coefficient >= 0 && *coefficient < 3329));
    }
}
