//! ML-DSA hint generation and application.

use crate::constants::N;
use crate::poly::Poly;
use crate::rounding::{decompose, high_bits, Gamma2};

/// Return a hint bit indicating whether adding `z` changes the high bits of `r`.
///
/// This is the scalar form of `MakeHint`.
#[inline]
pub fn make_hint(z: i32, r: i32, gamma2: Gamma2) -> u8 {
    let base = high_bits(r, gamma2);
    let adjusted = high_bits(r.wrapping_add(z), gamma2);
    u8::from(base != adjusted)
}

/// Apply one hint bit to the high bits of `r`.
///
/// This is the scalar form of `UseHint`.
#[inline]
pub fn use_hint(r: i32, hint: u8, gamma2: Gamma2) -> i32 {
    let (r1, r0) = decompose(r, gamma2);

    if hint == 0 {
        return r1;
    }

    let modulus = gamma2.high_modulus();

    if r0 > 0 {
        if r1 == modulus - 1 {
            0
        } else {
            r1 + 1
        }
    } else if r1 == 0 {
        modulus - 1
    } else {
        r1 - 1
    }
}

/// Generate a polynomial of hint bits.
///
/// Returns the hint polynomial and its Hamming weight.
pub fn make_hint_poly(z: &Poly, r: &Poly, gamma2: Gamma2) -> (Poly, usize) {
    let mut coefficients = [0_i32; N];
    let mut weight = 0_usize;

    for ((output, z_coefficient), r_coefficient) in
        coefficients.iter_mut().zip(z.coeffs()).zip(r.coeffs())
    {
        let hint = make_hint(*z_coefficient, *r_coefficient, gamma2);
        *output = i32::from(hint);
        weight += usize::from(hint);
    }

    (Poly::from_coeffs(coefficients), weight)
}

/// Apply a polynomial of hint bits to `r`.
pub fn use_hint_poly(r: &Poly, hints: &Poly, gamma2: Gamma2) -> Poly {
    let mut coefficients = [0_i32; N];

    for ((output, r_coefficient), hint_coefficient) in
        coefficients.iter_mut().zip(r.coeffs()).zip(hints.coeffs())
    {
        let hint = u8::from(*hint_coefficient != 0);
        *output = use_hint(*r_coefficient, hint, gamma2);
    }

    Poly::from_coeffs(coefficients)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_hint_preserves_high_bits() {
        for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
            for value in [0, 1, gamma2.value(), gamma2.alpha(), 8_380_416] {
                assert_eq!(use_hint(value, 0, gamma2), high_bits(value, gamma2));
            }
        }
    }

    #[test]
    fn hint_output_is_binary() {
        for gamma2 in [Gamma2::QMinusOneOver88, Gamma2::QMinusOneOver32] {
            for z in [-gamma2.value(), -1, 0, 1, gamma2.value()] {
                for r in [0, 1, gamma2.value(), gamma2.alpha(), 8_380_416] {
                    assert!(make_hint(z, r, gamma2) <= 1);
                }
            }
        }
    }
}
