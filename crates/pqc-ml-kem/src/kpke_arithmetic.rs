//! NTT-backed polynomial and module arithmetic for K-PKE.

use crate::fips_ntt;
use crate::matrix::PolyMatrix;
use crate::poly::Poly;
use crate::polyvec::PolyVec;

/// Multiply two polynomials through the ML-KEM NTT path.
pub fn multiply(lhs: &Poly, rhs: &Poly) -> Poly {
    fips_ntt::multiply(lhs, rhs)
}

/// Compute the inner product of equal-rank polynomial vectors.
pub fn dot(lhs: &PolyVec, rhs: &PolyVec) -> Poly {
    assert_eq!(lhs.rank(), rhs.rank());

    let mut accumulator = Poly::zero();
    let mut index = 0usize;
    while index < lhs.rank() {
        accumulator = accumulator.add(&multiply(&lhs.as_slice()[index], &rhs.as_slice()[index]));
        index += 1;
    }
    accumulator
}

/// Compute `matrix * vector`.
pub fn matrix_vector_mul(matrix: &PolyMatrix, vector: &PolyVec) -> PolyVec {
    assert_eq!(matrix.rank(), vector.rank());

    let rank = vector.rank();
    let mut output = [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()];

    let mut row = 0usize;
    while row < rank {
        let mut accumulator = Poly::zero();
        let mut column = 0usize;
        while column < rank {
            accumulator = accumulator.add(&multiply(
                matrix.get(row, column),
                &vector.as_slice()[column],
            ));
            column += 1;
        }
        output[row] = accumulator;
        row += 1;
    }

    PolyVec::from_slice(&output[..rank])
}

/// Compute `matrix * vector + error`.
pub fn matrix_vector_mul_add(matrix: &PolyMatrix, vector: &PolyVec, error: &PolyVec) -> PolyVec {
    assert_eq!(matrix.rank(), vector.rank());
    assert_eq!(vector.rank(), error.rank());
    matrix_vector_mul(matrix, vector).add(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arithmetic::N;
    use crate::matrix::PolyMatrix;

    fn polynomial(multiplier: usize, offset: usize) -> Poly {
        let mut coefficients = [0i16; N];
        let mut index = 0usize;
        while index < N {
            coefficients[index] = ((multiplier * index + offset) % 3329) as i16;
            index += 1;
        }
        Poly::from_coefficients(coefficients)
    }

    #[test]
    fn ntt_product_matches_schoolbook_product() {
        let lhs = polynomial(17, 5);
        let rhs = polynomial(29, 3);
        assert_eq!(multiply(&lhs, &rhs), lhs.mul_schoolbook(&rhs));
    }

    #[test]
    fn ntt_dot_product_matches_schoolbook_dot_product() {
        let lhs = PolyVec::from_slice(&[polynomial(3, 1), polynomial(5, 2), polynomial(7, 4)]);
        let rhs = PolyVec::from_slice(&[polynomial(11, 6), polynomial(13, 8), polynomial(17, 9)]);
        assert_eq!(dot(&lhs, &rhs), lhs.dot_schoolbook(&rhs));
    }

    #[test]
    fn ntt_matrix_vector_matches_schoolbook_reference() {
        let mut matrix = PolyMatrix::zero(2);
        matrix.set(0, 0, polynomial(3, 1));
        matrix.set(0, 1, polynomial(5, 2));
        matrix.set(1, 0, polynomial(7, 3));
        matrix.set(1, 1, polynomial(11, 4));

        let vector = PolyVec::from_slice(&[polynomial(13, 5), polynomial(17, 6)]);

        let actual = matrix_vector_mul(&matrix, &vector);
        let expected = PolyVec::from_slice(&[
            matrix
                .get(0, 0)
                .mul_schoolbook(&vector.as_slice()[0])
                .add(&matrix.get(0, 1).mul_schoolbook(&vector.as_slice()[1])),
            matrix
                .get(1, 0)
                .mul_schoolbook(&vector.as_slice()[0])
                .add(&matrix.get(1, 1).mul_schoolbook(&vector.as_slice()[1])),
        ]);

        assert_eq!(actual, expected);
    }
}
