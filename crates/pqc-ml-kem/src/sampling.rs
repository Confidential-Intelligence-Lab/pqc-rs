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
    let mut coefficients = [0i16; 256];
    let mut block = 0usize;

    while block < 64 {
        let offset = 3 * block;
        let word = u32::from(input[offset])
            | (u32::from(input[offset + 1]) << 8)
            | (u32::from(input[offset + 2]) << 16);

        let mut sums = word & 0x0024_9249;
        sums += (word >> 1) & 0x0024_9249;
        sums += (word >> 2) & 0x0024_9249;

        let mut lane = 0usize;
        while lane < 4 {
            let shift = 6 * lane;
            let a = ((sums >> shift) & 0x7) as i16;
            let b = ((sums >> (shift + 3)) & 0x7) as i16;
            coefficients[4 * block + lane] = a - b;
            lane += 1;
        }

        block += 1;
    }

    Poly::from_coefficients(coefficients)
}

#[cfg(test)]
mod stage6_5b2_tests {
    use super::*;

    #[test]
    fn cbd_eta3_all_zero_input_is_zero() {
        assert_eq!(cbd_eta3(&[0u8; 192]), Poly::zero());
    }

    #[test]
    fn cbd_eta3_known_bit_groups() {
        let mut input = [0u8; 192];

        input[0] = 0b0000_0111;
        let positive = cbd_eta3(&input);
        assert_eq!(positive.coefficients()[0], 3);

        input[0] = 0b0011_1000;
        let negative = cbd_eta3(&input);
        assert_eq!(negative.coefficients()[0], 3326);
    }

    #[test]
    fn cbd_eta3_coefficients_stay_in_range() {
        let input = [0xffu8; 192];
        let polynomial = cbd_eta3(&input);

        assert!(polynomial
            .coefficients()
            .iter()
            .all(|coefficient| (-3..=3).contains(coefficient)));
    }
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
