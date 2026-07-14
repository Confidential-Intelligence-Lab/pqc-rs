//! ML-DSA public-matrix expansion.
//!
//! `ExpandA` deterministically expands `rho` into a `k` by `l` matrix of
//! polynomials in the NTT domain.

use crate::constants::{N, Q};
use crate::params::MlDsaParameterSet;
use crate::poly::Poly;
use crate::xof::{ExpandAReader, RHO_BYTES};

const SHAKE128_BLOCK_BYTES: usize = 168;

/// Matrix of ML-DSA polynomials stored in row-major order.
#[derive(Clone, Eq, PartialEq)]
pub struct PolyMatrix {
    rows: usize,
    columns: usize,
    entries: Vec<Poly>,
}

impl PolyMatrix {
    /// Construct a matrix from row-major polynomial entries.
    pub fn new(rows: usize, columns: usize, entries: Vec<Poly>) -> Result<Self, ExpandAError> {
        if entries.len() != rows.saturating_mul(columns) {
            return Err(ExpandAError::InvalidDimensions);
        }

        Ok(Self {
            rows,
            columns,
            entries,
        })
    }

    /// Return the number of rows.
    pub const fn rows(&self) -> usize {
        self.rows
    }

    /// Return the number of columns.
    pub const fn columns(&self) -> usize {
        self.columns
    }

    /// Borrow the polynomial at `(row, column)`.
    pub fn get(&self, row: usize, column: usize) -> Option<&Poly> {
        if row >= self.rows || column >= self.columns {
            return None;
        }

        self.entries.get(row * self.columns + column)
    }

    /// Borrow all matrix entries in row-major order.
    pub fn entries(&self) -> &[Poly] {
        &self.entries
    }
}

/// Error returned by matrix expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpandAError {
    /// Matrix dimensions do not match the number of entries.
    InvalidDimensions,
    /// A matrix index cannot be represented by the ML-DSA domain separator.
    IndexOverflow,
}

/// Expand `rho` into the public matrix for the selected parameter set.
pub fn expand_a(
    rho: &[u8; RHO_BYTES],
    parameter_set: MlDsaParameterSet,
) -> Result<PolyMatrix, ExpandAError> {
    let parameters = parameter_set.parameters();
    let mut entries = Vec::with_capacity(parameters.k * parameters.l);

    for row in 0..parameters.k {
        for column in 0..parameters.l {
            let row = u8::try_from(row).map_err(|_| ExpandAError::IndexOverflow)?;
            let column = u8::try_from(column).map_err(|_| ExpandAError::IndexOverflow)?;
            entries.push(rej_ntt_poly(rho, row, column));
        }
    }

    PolyMatrix::new(parameters.k, parameters.l, entries)
}

/// Expand one matrix entry using `RejNTTPoly`.
pub fn rej_ntt_poly(rho: &[u8; RHO_BYTES], row: u8, column: u8) -> Poly {
    let mut reader = ExpandAReader::new(rho, row, column);
    let mut coefficients = [0_i32; N];
    let mut accepted = 0_usize;
    let mut buffer = [0_u8; SHAKE128_BLOCK_BYTES];

    while accepted < N {
        reader.read(&mut buffer);

        for chunk in buffer.chunks_exact(3) {
            let candidate =
                u32::from(chunk[0]) | (u32::from(chunk[1]) << 8) | (u32::from(chunk[2]) << 16);
            let candidate = candidate & 0x7f_ffff;

            if candidate < Q as u32 {
                coefficients[accepted] = candidate as i32;
                accepted += 1;

                if accepted == N {
                    break;
                }
            }
        }
    }

    Poly::from_coeffs(coefficients)
}
