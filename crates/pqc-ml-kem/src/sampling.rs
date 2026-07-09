//! Sampling helpers for ML-KEM.

use crate::arithmetic::N;
use crate::poly::Poly;

/// Sample a polynomial from a centered binomial distribution with `eta = 2`.
pub fn cbd_eta2(input: &[u8; 128]) -> Poly {
    let mut coeffs = [0i16; N];

    let mut i = 0;
    while i < N {
        let byte = input[i / 2];
        let nibble = if i % 2 == 0 { byte & 0x0f } else { byte >> 4 };
        let a = (nibble & 1) + ((nibble >> 1) & 1);
        let b = ((nibble >> 2) & 1) + ((nibble >> 3) & 1);
        coeffs[i] = i16::from(a) - i16::from(b);
        i += 1;
    }

    Poly::from_coefficients(coeffs)
}

/// Sample a polynomial from a centered binomial distribution with `eta = 3`.
pub fn cbd_eta3(input: &[u8; 192]) -> Poly {
    let mut coeffs = [0i16; N];

    let mut i = 0;
    while i < N {
        let bit_pos = i * 6;
        let byte_pos = bit_pos / 8;
        let offset = bit_pos % 8;

        let mut window = u32::from(input[byte_pos]) >> offset;
        if byte_pos + 1 < input.len() {
            window |= u32::from(input[byte_pos + 1]) << (8 - offset);
        }
        if offset > 4 && byte_pos + 2 < input.len() {
            window |= u32::from(input[byte_pos + 2]) << (16 - offset);
        }

        let bits = window & 0x3f;
        let a = (bits & 1) + ((bits >> 1) & 1) + ((bits >> 2) & 1);
        let b = ((bits >> 3) & 1) + ((bits >> 4) & 1) + ((bits >> 5) & 1);
        coeffs[i] = a as i16 - b as i16;

        i += 1;
    }

    Poly::from_coefficients(coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbd_eta2_coefficients_are_in_expected_range() {
        let p = cbd_eta2(&[0xff; 128]);
        for c in p.coefficients() {
            assert!(*c <= 3328);
        }
    }

    #[test]
    fn cbd_eta3_all_zero_input_gives_zero_poly() {
        let p = cbd_eta3(&[0u8; 192]);
        assert!(p.coefficients().iter().all(|x| *x == 0));
    }
}
