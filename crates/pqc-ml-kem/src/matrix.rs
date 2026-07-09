//! Matrix expansion and rejection sampling helpers for ML-KEM.
//!
//! Stage 5A provides deterministic matrix expansion structure for K-PKE. It is
//! suitable for API and harness validation, but Stage 5B should verify it against
//! official FIPS 203 KATs.

use crate::arithmetic::{reduce, N, Q};
use crate::poly::Poly;
use crate::polyvec::MAX_K;
use crate::symmetric;

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

/// Expand the public matrix from `rho`.
pub fn expand_matrix(rank: usize, rho: &[u8; 32], transposed: bool) -> PolyMatrix {
    let mut matrix = PolyMatrix::zero(rank);

    let mut row = 0;
    while row < rank {
        let mut col = 0;
        while col < rank {
            let x = if transposed { row as u8 } else { col as u8 };
            let y = if transposed { col as u8 } else { row as u8 };

            let mut stream = [0u8; 672];
            symmetric::xof(rho, x, y, &mut stream);
            let poly = sample_uniform_from_xof(&stream);

            matrix.set(row, col, poly);
            col += 1;
        }
        row += 1;
    }

    matrix
}

/// Rejection sample a polynomial with coefficients in `[0, Q)`.
pub fn sample_uniform_from_xof(input: &[u8]) -> Poly {
    let mut coeffs = [0i16; N];
    let mut coeff_index = 0usize;
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

    // Stage 5A fallback: in practice the XOF stream length is chosen to make this
    // overwhelmingly unlikely. The fallback keeps the API total and deterministic
    // for scaffolding tests. Stage 5B should stream until full.
    while coeff_index < N {
        coeffs[coeff_index] = reduce(coeff_index as i32);
        coeff_index += 1;
    }

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
