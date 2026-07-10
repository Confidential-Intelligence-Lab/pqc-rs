//! Explicit NTT-domain intermediate representations for K-PKE.
//!
//! Stage 5B-13 introduces transformed polynomial vectors and matrices without
//! replacing the working coefficient-domain K-PKE path. Every operation is
//! validated against the coefficient-domain reference before later stages
//! adopt these types in key generation and encryption.

use crate::arithmetic::N;
use crate::fips_ntt::{self, FipsNttPoly};
use crate::matrix::PolyMatrix;
use crate::poly::Poly;
use crate::polyvec::{PolyVec, MAX_K};

/// Polynomial vector represented in the ML-KEM NTT domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NttPolyVec {
    rank: usize,
    polys: [FipsNttPoly; MAX_K],
}

impl NttPolyVec {
    /// Construct a zero NTT-domain polynomial vector.
    pub fn zero(rank: usize) -> Self {
        assert!((1..=MAX_K).contains(&rank));
        Self {
            rank,
            polys: core::array::from_fn(|_| FipsNttPoly::from_coefficients([0i16; N])),
        }
    }

    /// Transform a coefficient-domain vector into NTT representation.
    pub fn from_polyvec(polyvec: &PolyVec) -> Self {
        let mut out = Self::zero(polyvec.rank());
        let mut index = 0usize;

        while index < polyvec.rank() {
            out.polys[index] = fips_ntt::ntt(&polyvec.as_slice()[index]);
            index += 1;
        }

        out
    }

    /// Return the active rank.
    pub fn rank(&self) -> usize {
        self.rank
    }

    /// Borrow the active NTT polynomial slice.
    pub fn as_slice(&self) -> &[FipsNttPoly] {
        &self.polys[..self.rank]
    }

    /// Convert back to coefficient-domain polynomials.
    pub fn to_polyvec(&self) -> PolyVec {
        let mut polys = [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()];
        let mut index = 0usize;

        while index < self.rank {
            polys[index] = fips_ntt::intt(&self.polys[index]);
            index += 1;
        }

        PolyVec::from_slice(&polys[..self.rank])
    }
}

/// Square matrix represented in the ML-KEM NTT domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NttPolyMatrix {
    rank: usize,
    entries: [[FipsNttPoly; MAX_K]; MAX_K],
}

impl NttPolyMatrix {
    /// Transform a coefficient-domain matrix into NTT representation.
    pub fn from_matrix(matrix: &PolyMatrix) -> Self {
        let rank = matrix.rank();
        let mut entries = core::array::from_fn(|_| {
            core::array::from_fn(|_| FipsNttPoly::from_coefficients([0i16; N]))
        });

        let mut row = 0usize;
        while row < rank {
            let mut column = 0usize;
            while column < rank {
                entries[row][column] = fips_ntt::ntt(matrix.get(row, column));
                column += 1;
            }
            row += 1;
        }

        Self { rank, entries }
    }

    /// Return the matrix rank.
    pub fn rank(&self) -> usize {
        self.rank
    }

    /// Borrow one NTT-domain entry.
    pub fn get(&self, row: usize, column: usize) -> &FipsNttPoly {
        assert!(row < self.rank);
        assert!(column < self.rank);
        &self.entries[row][column]
    }
}

/// Compute an NTT-domain vector inner product and return coefficient-domain
/// output.
pub fn dot_to_poly(lhs: &NttPolyVec, rhs: &NttPolyVec) -> Poly {
    assert_eq!(lhs.rank(), rhs.rank());

    let mut accumulator = [0i16; N];
    let mut index = 0usize;

    while index < lhs.rank() {
        let product = fips_ntt::basemul_polynomials(&lhs.as_slice()[index], &rhs.as_slice()[index]);

        let mut coefficient = 0usize;
        while coefficient < N {
            accumulator[coefficient] = crate::arithmetic::add(
                accumulator[coefficient],
                product.coefficients()[coefficient],
            );
            coefficient += 1;
        }

        index += 1;
    }

    fips_ntt::invntt_tomont(&FipsNttPoly::from_coefficients(accumulator))
}

/// Add a coefficient-domain error vector after NTT-domain matrix-vector
/// multiplication.
pub fn matrix_vector_mul_add_to_polyvec(
    matrix: &NttPolyMatrix,
    vector: &NttPolyVec,
    error: &PolyVec,
) -> PolyVec {
    assert_eq!(matrix.rank(), vector.rank());
    assert_eq!(vector.rank(), error.rank());

    matrix_vector_mul_to_polyvec(matrix, vector).add(error)
}

/// Compute `matrix * vector` in the NTT domain and return coefficient-domain
/// output.
pub fn matrix_vector_mul_to_polyvec(matrix: &NttPolyMatrix, vector: &NttPolyVec) -> PolyVec {
    assert_eq!(matrix.rank(), vector.rank());

    let rank = vector.rank();
    let mut output = [Poly::zero(), Poly::zero(), Poly::zero(), Poly::zero()];

    let mut row = 0usize;
    while row < rank {
        let mut accumulator = Poly::zero();
        let mut column = 0usize;

        while column < rank {
            let product =
                fips_ntt::basemul_polynomials(matrix.get(row, column), &vector.as_slice()[column]);
            accumulator = accumulator.add(&fips_ntt::invntt_tomont(&product));
            column += 1;
        }

        output[row] = accumulator;
        row += 1;
    }

    PolyVec::from_slice(&output[..rank])
}

#[cfg(test)]
mod tests {
    use super::*;
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
    fn ntt_polyvec_round_trip_preserves_values() {
        let vector = PolyVec::from_slice(&[polynomial(3, 1), polynomial(5, 2), polynomial(7, 4)]);

        let transformed = NttPolyVec::from_polyvec(&vector);

        assert_eq!(transformed.rank(), 3);
        assert_eq!(transformed.to_polyvec(), vector);
    }

    #[test]
    fn ntt_dot_matches_coefficient_domain_reference() {
        let lhs = PolyVec::from_slice(&[polynomial(3, 1), polynomial(5, 2)]);
        let rhs = PolyVec::from_slice(&[polynomial(7, 3), polynomial(11, 4)]);

        let lhs_ntt = NttPolyVec::from_polyvec(&lhs);
        let rhs_ntt = NttPolyVec::from_polyvec(&rhs);

        assert_eq!(dot_to_poly(&lhs_ntt, &rhs_ntt), lhs.dot_schoolbook(&rhs));
    }

    #[test]
    fn ntt_matrix_vector_matches_coefficient_domain_reference() {
        let mut matrix = PolyMatrix::zero(2);
        matrix.set(0, 0, polynomial(3, 1));
        matrix.set(0, 1, polynomial(5, 2));
        matrix.set(1, 0, polynomial(7, 3));
        matrix.set(1, 1, polynomial(11, 4));

        let vector = PolyVec::from_slice(&[polynomial(13, 5), polynomial(17, 6)]);

        let matrix_ntt = NttPolyMatrix::from_matrix(&matrix);
        let vector_ntt = NttPolyVec::from_polyvec(&vector);
        let actual = matrix_vector_mul_to_polyvec(&matrix_ntt, &vector_ntt);

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

    #[test]
    fn ntt_matrix_reports_rank() {
        let matrix = PolyMatrix::zero(4);
        let transformed = NttPolyMatrix::from_matrix(&matrix);
        assert_eq!(transformed.rank(), 4);
    }
}
