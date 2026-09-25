//! Matrix expansion and rejection sampling helpers for ML-KEM.
//!
//! Public-matrix entries follow FIPS 203 SampleNTT semantics: SHAKE128 output
//! is consumed incrementally until exactly 256 coefficients in `[0, q)` have
//! been accepted by rejection sampling.

use crate::arithmetic::{N, Q};
use crate::poly::Poly;
use crate::polyvec::MAX_K;

use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

/// Matrix of polynomials with rank at most 4.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolyMatrix {
    rank: usize,
    entries: [[Poly; MAX_K]; MAX_K],
}

impl PolyMatrix {
    /// Construct a zero matrix.
    pub fn zero(rank: usize) -> Self {
        assert!((1..=MAX_K).contains(&rank));
        Self {
            rank,
            entries: core::array::from_fn(|_| core::array::from_fn(|_| Poly::zero())),
        }
    }

    /// Return rank.
    pub fn rank(&self) -> usize {
        self.rank
    }

    /// Borrow an entry.
    pub fn get(&self, row: usize, col: usize) -> &Poly {
        assert!(row < self.rank);
        assert!(col < self.rank);
        &self.entries[row][col]
    }

    /// Set an entry.
    pub fn set(&mut self, row: usize, col: usize, value: Poly) {
        assert!(row < self.rank);
        assert!(col < self.rank);
        self.entries[row][col] = value;
    }
}

const SHAKE128_RATE_BYTES: usize = 168;

/// Expand the public matrix from `rho`.
///
/// Each matrix entry is generated with FIPS 203 SampleNTT semantics:
/// SHAKE128 output is consumed incrementally until exactly `N` coefficients
/// in `[0, Q)` have been accepted.
pub fn expand_matrix(rank: usize, rho: &[u8; 32], transposed: bool) -> PolyMatrix {
    let mut matrix = PolyMatrix::zero(rank);

    let mut row = 0;
    while row < rank {
        let mut col = 0;
        while col < rank {
            let x = if transposed { row as u8 } else { col as u8 };
            let y = if transposed { col as u8 } else { row as u8 };

            let poly = sample_uniform(rho, x, y);

            matrix.set(row, col, poly);
            col += 1;
        }
        row += 1;
    }

    matrix
}

/// Generate one SampleNTT polynomial from `rho || x || y`.
fn sample_uniform(rho: &[u8; 32], x: u8, y: u8) -> Poly {
    let mut hasher = Shake128::default();
    hasher.update(rho);
    hasher.update(&[x, y]);

    let mut reader = hasher.finalize_xof();

    let mut coeffs = [0i16; N];
    let mut coeff_index = 0usize;

    while coeff_index < N {
        let mut block = [0u8; SHAKE128_RATE_BYTES];
        reader.read(&mut block);

        coeff_index = rejection_sample_into(&block, &mut coeffs, coeff_index);
    }

    Poly::from_coefficients(coeffs)
}

/// Rejection-sample candidates from `input` into `coeffs`.
///
/// Returns the next output coefficient index. Input is interpreted as pairs
/// of 12-bit little-endian candidates from each three-byte group.
fn rejection_sample_into(input: &[u8], coeffs: &mut [i16; N], mut coeff_index: usize) -> usize {
    let mut pos = 0usize;

    while coeff_index < N && pos + 3 <= input.len() {
        let d1 = u16::from(input[pos]) | ((u16::from(input[pos + 1]) & 0x0f) << 8);

        let d2 = (u16::from(input[pos + 1]) >> 4) | (u16::from(input[pos + 2]) << 4);

        pos += 3;

        if d1 < Q as u16 {
            coeffs[coeff_index] = d1 as i16;
            coeff_index += 1;
        }

        if coeff_index < N && d2 < Q as u16 {
            coeffs[coeff_index] = d2 as i16;
            coeff_index += 1;
        }
    }

    coeff_index
}

/// Rejection sample a polynomial from a finite XOF byte slice.
///
/// This helper remains available for tests and callers that already provide
/// XOF output bytes. The input must contain enough accepted candidates to fill
/// the polynomial.
pub fn sample_uniform_from_xof(input: &[u8]) -> Poly {
    let mut coeffs = [0i16; N];

    let coeff_index = rejection_sample_into(input, &mut coeffs, 0);

    assert_eq!(
        coeff_index, N,
        "insufficient XOF input for ML-KEM SampleNTT"
    );

    Poly::from_coefficients(coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_expansion_is_deterministic() {
        let rho = [42u8; 32];

        let a = expand_matrix(3, &rho, false);
        let b = expand_matrix(3, &rho, false);

        assert_eq!(a, b);
        assert_eq!(a.rank(), 3);
    }

    #[test]
    fn transposed_matrix_uses_different_domain() {
        let rho = [7u8; 32];

        let a = expand_matrix(2, &rho, false);
        let at = expand_matrix(2, &rho, true);

        assert_eq!(a.get(0, 1), at.get(1, 0));
    }

    #[test]
    fn sampled_coefficients_are_canonical() {
        let mut input = [0u8; 672];
        let mut i = 0;
        while i < input.len() {
            input[i] = (i % 251) as u8;
            i += 1;
        }

        let p = sample_uniform_from_xof(&input);
        assert!(p.coefficients().iter().all(|c| *c >= 0 && *c < Q));
    }
}
