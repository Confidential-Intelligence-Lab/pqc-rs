//! Reference-oriented SMAUG-T polynomial arithmetic.
//!
//! This module provides a fixed-size negacyclic multiply-accumulate
//! operation over 16-bit wrapping coefficients.
//!
//! The implementation prioritizes functional clarity and differential
//! testability over performance. It is not independently certified
//! against side-channel leakage.

use crate::N;

/// Accumulate a negacyclic polynomial product into `acc`.
///
/// Computes:
///
/// `acc <- acc + a * b` in `(Z / 2^16 Z)[x] / (x^256 + 1)`.
///
/// All arithmetic uses explicit 16-bit wrapping semantics.
///
/// This function does not reduce coefficients modulo the SMAUG-T
/// parameter-specific modulus `q`.
pub fn poly_mul_acc_16(acc: &mut [u16; N], a: &[u16; N], b: &[u16; N]) {
    for (i, &a_coeff) in a.iter().enumerate() {
        for (j, &b_coeff) in b.iter().enumerate() {
            let product = a_coeff.wrapping_mul(b_coeff);
            let index = i + j;

            if index < N {
                acc[index] = acc[index].wrapping_add(product);
            } else {
                acc[index - N] = acc[index - N].wrapping_sub(product);
            }
        }
    }
}

// S4.2b.1: scaled vector and matrix arithmetic/// Arithmetic right shift of a 16-bit coefficient representation.
///
/// The bit pattern is interpreted as a signed two's-complement integer,
/// matching the observed reference behavior on the validated platform.
#[inline]
fn descale_coeff(value: u16, shift: u32) -> u16 {
    assert!(shift < 16);
    ((value as i16) >> shift) as u16
}

/// Multiply two polynomial vectors, rescale, and add to `acc`.
///
/// The first vector contains scaled 16-bit coefficient representations.
/// The second vector contains unscaled polynomial coefficients.
pub fn vec_vec_mult_add_scaled<const K: usize>(
    acc: &mut [u16; 256],
    a: &[[u16; 256]; K],
    b: &[[u16; 256]; K],
    shift: u32,
) {
    assert!(shift < 16);

    let mut product = [0u16; 256];

    for i in 0..K {
        let descaled = a[i].map(|value| descale_coeff(value, shift));
        poly_mul_acc_16(&mut product, &descaled, &b[i]);
    }

    for (dst, value) in acc.iter_mut().zip(product) {
        *dst = dst.wrapping_add(value.wrapping_shl(shift));
    }
}

/// Compute `out = transpose(matrix) * secret`, with rescaling.
///
/// The input matrix contains scaled coefficients. The result is overwritten,
/// matching the reference's `matrix_vec_mult_add` behavior.
pub fn matrix_vec_mult_add_scaled<const K: usize>(
    out: &mut [[u16; 256]; K],
    matrix: &[[[u16; 256]; K]; K],
    secret: &[[u16; 256]; K],
    shift: u32,
) {
    assert!(shift < 16);

    for (column, output) in out.iter_mut().enumerate() {
        let mut product = [0u16; 256];

        for row in 0..K {
            let descaled = matrix[row][column].map(|value| descale_coeff(value, shift));
            poly_mul_acc_16(&mut product, &descaled, &secret[row]);
        }

        *output = product.map(|value| value.wrapping_shl(shift));
    }
}

/// Compute `out -= matrix * secret`, with rescaling.
///
/// Unlike the addition operation, this uses the matrix without transposition
/// and preserves the initial accumulator.
pub fn matrix_vec_mult_sub_scaled<const K: usize>(
    out: &mut [[u16; 256]; K],
    matrix: &[[[u16; 256]; K]; K],
    secret: &[[u16; 256]; K],
    shift: u32,
) {
    assert!(shift < 16);

    for row in 0..K {
        let mut product = [0u16; 256];

        for (column, secret_poly) in secret.iter().enumerate() {
            let descaled = matrix[row][column].map(|value| descale_coeff(value, shift));
            poly_mul_acc_16(&mut product, &descaled, secret_poly);
        }

        for (dst, value) in out[row].iter_mut().zip(product) {
            *dst = dst.wrapping_sub(value.wrapping_shl(shift));
        }
    }
}

#[cfg(test)]
mod tests {

    // S4.2b.1b: scaled vector/matrix unit tests

    #[test]
    fn scaled_vector_preserves_nonzero_accumulator() {
        let mut acc = [0u16; 256];
        acc[0] = 17;
        acc[255] = 23;

        let mut a = [[0u16; 256]; 2];
        let mut b = [[0u16; 256]; 2];

        a[0][0] = 3 << 6;
        b[0][0] = 4;

        a[1][255] = 2 << 6;
        b[1][0] = 5;

        super::vec_vec_mult_add_scaled(&mut acc, &a, &b, 6);

        assert_eq!(acc[0], 17 + (12 << 6));
        assert_eq!(acc[255], 23 + (10 << 6));
        assert!(acc[1..255].iter().all(|&x| x == 0));
    }

    #[test]
    fn scaled_vector_positive_negative_products_cancel() {
        let mut acc = [0u16; 256];
        acc[0] = 0x3456;

        let mut a = [[0u16; 256]; 2];
        let mut b = [[0u16; 256]; 2];

        a[0][0] = 7 << 5;
        b[0][0] = 3;

        a[1][0] = ((-7i16) << 5) as u16;
        b[1][0] = 3;

        super::vec_vec_mult_add_scaled(&mut acc, &a, &b, 5);

        assert_eq!(acc[0], 0x3456);
        assert!(acc[1..].iter().all(|&x| x == 0));
    }

    #[test]
    fn scaled_matrix_add_uses_transpose() {
        let mut matrix = [[[0u16; 256]; 2]; 2];
        let mut secret = [[0u16; 256]; 2];
        let mut out = [[0u16; 256]; 2];

        matrix[0][1][0] = 3 << 6;
        matrix[1][0][0] = 7 << 6;

        secret[0][0] = 2;
        secret[1][0] = 5;

        super::matrix_vec_mult_add_scaled(&mut out, &matrix, &secret, 6);

        assert_eq!(out[0][0], 35 << 6);
        assert_eq!(out[1][0], 6 << 6);
        assert!(out.iter().all(|poly| { poly[1..].iter().all(|&x| x == 0) }));
    }

    #[test]
    fn scaled_matrix_sub_uses_original_orientation() {
        let mut matrix = [[[0u16; 256]; 2]; 2];
        let mut secret = [[0u16; 256]; 2];
        let mut out = [[0u16; 256]; 2];

        matrix[0][1][0] = 3 << 6;
        matrix[1][0][0] = 7 << 6;

        secret[0][0] = 2;
        secret[1][0] = 5;

        out[0][0] = 0x4000;
        out[1][0] = 0x5000;

        super::matrix_vec_mult_sub_scaled(&mut out, &matrix, &secret, 6);

        assert_eq!(out[0][0], 0x4000 - (15 << 6));
        assert_eq!(out[1][0], 0x5000 - (14 << 6));
    }

    #[test]
    fn scaled_vector_accumulation_wraps_modulo_16_bits() {
        let mut acc = [0u16; 256];
        acc[0] = 0xffc0;

        let mut a = [[0u16; 256]; 1];
        let mut b = [[0u16; 256]; 1];

        a[0][0] = 2 << 6;
        b[0][0] = 1;

        super::vec_vec_mult_add_scaled(&mut acc, &a, &b, 6);

        assert_eq!(acc[0], 0x0040);
    }

    #[test]
    fn scaled_arithmetic_supports_all_reference_shifts() {
        for shift in [5u32, 6, 7, 8] {
            let mut acc = [0u16; 256];
            let mut a = [[0u16; 256]; 1];
            let mut b = [[0u16; 256]; 1];

            a[0][0] = 3u16 << shift;
            b[0][0] = 4;

            super::vec_vec_mult_add_scaled(&mut acc, &a, &b, shift);

            assert_eq!(acc[0], 12u16 << shift);
            assert!(acc[1..].iter().all(|&x| x == 0));
        }
    }

    use super::*;

    fn zero() -> [u16; N] {
        [0u16; N]
    }

    #[test]
    fn zero_product_preserves_accumulator() {
        let a = zero();
        let b = [0xffff; N];
        let mut acc = [0x1234; N];

        poly_mul_acc_16(&mut acc, &a, &b);

        assert_eq!(acc, [0x1234; N]);
    }

    #[test]
    fn multiplicative_identity() {
        let mut a = zero();
        let mut one = zero();
        let mut acc = zero();

        for (i, coefficient) in a.iter_mut().enumerate() {
            *coefficient = (i as u16).wrapping_mul(257).wrapping_add(0x8001);
        }

        one[0] = 1;

        poly_mul_acc_16(&mut acc, &a, &one);

        assert_eq!(acc, a);
    }

    #[test]
    fn negacyclic_boundary_relation() {
        let mut a = zero();
        let mut b = zero();
        let mut acc = zero();

        a[N - 1] = 1;
        b[1] = 1;

        poly_mul_acc_16(&mut acc, &a, &b);

        assert_eq!(acc[0], 0xffff);
        assert!(acc[1..].iter().all(|&x| x == 0));
    }

    #[test]
    fn signed_representation_is_preserved_modulo_2_16() {
        let mut a = zero();
        let mut b = zero();
        let mut acc = zero();

        // 0xffff represents -1 in the signed C reference.
        a[0] = 0xffff;
        b[0] = 3;

        poly_mul_acc_16(&mut acc, &a, &b);

        assert_eq!(acc[0], 0xfffd);
    }

    #[test]
    fn existing_accumulator_is_updated() {
        let mut a = zero();
        let mut b = zero();
        let mut acc = [0x1234; N];

        a[0] = 7;
        b[0] = 9;

        poly_mul_acc_16(&mut acc, &a, &b);

        assert_eq!(acc[0], 0x1273);
        assert!(acc[1..].iter().all(|&x| x == 0x1234));
    }

    #[test]
    fn accumulation_wraps_at_16_bits() {
        let mut a = zero();
        let mut b = zero();
        let mut acc = zero();

        a[0] = 0xffff;
        b[0] = 2;
        acc[0] = 5;

        poly_mul_acc_16(&mut acc, &a, &b);

        assert_eq!(acc[0], 3);
    }

    #[test]
    fn multiplication_is_commutative() {
        let mut a = zero();
        let mut b = zero();

        for i in 0..N {
            a[i] = (i as u16).wrapping_mul(17).wrapping_add(1);
            b[i] = (i as u16).wrapping_mul(31).wrapping_add(3);
        }

        let mut ab = zero();
        let mut ba = zero();

        poly_mul_acc_16(&mut ab, &a, &b);
        poly_mul_acc_16(&mut ba, &b, &a);

        assert_eq!(ab, ba);
    }

    #[test]
    fn repeated_accumulation_is_additive() {
        let mut a = zero();
        let mut b = zero();

        for i in 0..N {
            a[i] = (i as u16).wrapping_mul(5);
            b[i] = (i as u16).wrapping_mul(11);
        }

        let mut once = zero();
        let mut twice = zero();

        poly_mul_acc_16(&mut once, &a, &b);

        poly_mul_acc_16(&mut twice, &a, &b);
        poly_mul_acc_16(&mut twice, &a, &b);

        for i in 0..N {
            assert_eq!(twice[i], once[i].wrapping_mul(2));
        }
    }
}
