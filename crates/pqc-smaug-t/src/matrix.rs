// SPDX-License-Identifier: MIT
//! Deterministic public-matrix expansion for SMAUG-T.

use crate::encoding::unpack_unsigned;
use crate::{Parameters, Polynomial, N};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

/// Expand a 32-byte public seed into a k-by-k matrix of canonical
/// polynomials modulo q.
///
/// Each entry uses SHAKE128(seed || row || column), where row and
/// column are single-byte indices.
pub fn expand_matrix(seed: &[u8; 32], parameters: &Parameters) -> Vec<Vec<Polynomial>> {
    let k = parameters.k;
    let q = parameters.q;
    let width = q.trailing_zeros() as u8;
    let bytes_per_polynomial = N * usize::from(width) / 8;

    let mut matrix = Vec::with_capacity(k);

    for row in 0..k {
        let mut entries = Vec::with_capacity(k);

        for column in 0..k {
            let mut xof = Shake128::default();
            xof.update(seed);
            xof.update(&[row as u8, column as u8]);

            let mut reader = xof.finalize_xof();
            let mut bytes = vec![0u8; bytes_per_polynomial];
            reader.read(&mut bytes);

            let coefficients = unpack_unsigned(&bytes, width)
                .expect("SHAKE128 output has the required packed length");

            entries.push(Polynomial { coefficients });
        }

        matrix.push(entries);
    }

    matrix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_dimensions() {
        for parameters in [
            crate::TIMER,
            crate::SMAUG_T128,
            crate::SMAUG_T192,
            crate::SMAUG_T256,
        ] {
            let matrix = expand_matrix(&[0u8; 32], &parameters);
            let k = parameters.k;

            assert_eq!(matrix.len(), k);
            assert!(matrix.iter().all(|row| row.len() == k));
            assert!(matrix
                .iter()
                .flatten()
                .all(|p| { p.coefficients.iter().all(|&c| c < parameters.q) }));
        }
    }

    #[test]
    fn deterministic_for_same_seed() {
        let seed = [0x42u8; 32];

        let first = expand_matrix(&seed, &crate::SMAUG_T256);
        let second = expand_matrix(&seed, &crate::SMAUG_T256);

        for (row_a, row_b) in first.iter().zip(&second) {
            for (a, b) in row_a.iter().zip(row_b) {
                assert_eq!(a.coefficients, b.coefficients);
            }
        }
    }

    #[test]
    fn distinct_matrix_coordinates() {
        let matrix = expand_matrix(&[0xA5u8; 32], &crate::SMAUG_T192);

        assert_ne!(matrix[0][0].coefficients, matrix[0][1].coefficients);
        assert_ne!(matrix[0][0].coefficients, matrix[1][0].coefficients);
    }
}
