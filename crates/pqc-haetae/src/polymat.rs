//! HAETAE matrix expansion and NTT-domain matrix-vector products.
//!
//! Experimental implementation; not yet validated for production use.

use crate::params::ParameterSet;
use crate::polyvec::{PolyVecK, PolyVecM};
use crate::sampling::uniform;

/// Expand the public K-by-M matrix from the matrix seed.
///
/// Matches the reference nonce schedule `(row << 8) + column`.
pub fn expand_mat_a<const K: usize, const M: usize>(
    seed: &[u8; 32],
    mode: ParameterSet,
) -> [PolyVecM<M>; K] {
    let params = mode.parameters();

    assert_eq!(K, params.k, "HAETAE matrix row dimension mismatch");
    assert_eq!(M, params.l - 1, "HAETAE matrix column dimension mismatch");
    assert!(M <= 256, "HAETAE matrix nonce columns exceed one byte");

    std::array::from_fn(|row| {
        PolyVecM::new(std::array::from_fn(|column| {
            let nonce = (row << 8) + column;
            uniform(seed, u16::try_from(nonce).expect("matrix nonce range"))
        }))
    })
}

/// Multiply an NTT-domain K-by-M matrix by an NTT-domain M-vector.
///
/// The caller is responsible for transforming the input vector into
/// the NTT domain. Matrix expansion already produces the representation
/// expected by the authenticated reference.
pub fn pointwise_montgomery<const K: usize, const M: usize>(
    matrix: &[PolyVecM<M>; K],
    vector: &PolyVecM<M>,
    mode: ParameterSet,
) -> PolyVecK<K> {
    let params = mode.parameters();

    assert_eq!(K, params.k, "HAETAE matrix row dimension mismatch");
    assert_eq!(M, params.l - 1, "HAETAE matrix column dimension mismatch");

    PolyVecK::new(std::array::from_fn(|row| {
        matrix[row].pointwise_acc_montgomery(vector)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::N;
    use crate::poly::Poly;

    fn check<const K: usize, const M: usize>(mode: ParameterSet) {
        let seed = std::array::from_fn(|i| i as u8);
        let matrix = expand_mat_a::<K, M>(&seed, mode);

        for (row, matrix_row) in matrix.iter().enumerate() {
            for column in 0..M {
                let nonce = ((row << 8) + column) as u16;
                assert_eq!(matrix_row.0.vec[column], uniform(&seed, nonce));
            }
        }

        let zero = PolyVecM::<M>::default();
        let output = pointwise_montgomery(&matrix, &zero, mode);

        for polynomial in output.as_slice() {
            assert_eq!(polynomial, &Poly::new([0; N]));
        }

        let vector = PolyVecM::<M>::new(std::array::from_fn(|_| Poly::new([1; N])));

        let result = pointwise_montgomery(&matrix, &vector, mode);

        for (row, matrix_row) in matrix.iter().enumerate() {
            assert_eq!(
                result.0.vec[row],
                matrix_row.pointwise_acc_montgomery(&vector)
            );
        }
    }

    #[test]
    fn matrix_operations_all_modes() {
        check::<2, 3>(ParameterSet::Haetae2);
        check::<3, 5>(ParameterSet::Haetae3);
        check::<4, 6>(ParameterSet::Haetae5);
    }

    #[test]
    #[should_panic(expected = "HAETAE matrix row dimension mismatch")]
    fn rejects_wrong_row_dimension() {
        let seed = [0_u8; 32];
        let _ = expand_mat_a::<3, 3>(&seed, ParameterSet::Haetae2);
    }

    #[test]
    #[should_panic(expected = "HAETAE matrix column dimension mismatch")]
    fn rejects_wrong_column_dimension() {
        let seed = [0_u8; 32];
        let _ = expand_mat_a::<2, 5>(&seed, ParameterSet::Haetae2);
    }
}
