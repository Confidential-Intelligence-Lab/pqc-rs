//! Polynomial representation and byte encoding helpers for ML-KEM.

use crate::arithmetic::{add, compress_coefficient, decompress_coefficient, mul, reduce, sub, N};

/// Polynomial in `Z_q[x] / (x^256 + 1)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Poly {
    coeffs: [i16; N],
}

impl Poly {
    /// Construct the zero polynomial.
    pub const fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

    /// Construct a polynomial from canonical or non-canonical coefficients.
    pub fn from_coefficients(coeffs: [i16; N]) -> Self {
        let mut out = [0i16; N];
        let mut i = 0;
        while i < N {
            out[i] = reduce(i32::from(coeffs[i]));
            i += 1;
        }
        Self { coeffs: out }
    }

    /// Borrow the coefficients.
    pub fn coefficients(&self) -> &[i16; N] {
        &self.coeffs
    }

    /// Add two polynomials coefficient-wise.
    pub fn add(&self, rhs: &Self) -> Self {
        let mut out = [0i16; N];
        let mut i = 0;
        while i < N {
            out[i] = add(self.coeffs[i], rhs.coeffs[i]);
            i += 1;
        }
        Self { coeffs: out }
    }

    /// Subtract two polynomials coefficient-wise.
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut out = [0i16; N];
        let mut i = 0;
        while i < N {
            out[i] = sub(self.coeffs[i], rhs.coeffs[i]);
            i += 1;
        }
        Self { coeffs: out }
    }

    /// Schoolbook negacyclic multiplication.
    ///
    /// This is a correctness-oriented portable baseline. Stage 4 should replace
    /// high-throughput paths with NTT-based multiplication.
    pub fn mul_schoolbook(&self, rhs: &Self) -> Self {
        let mut acc = [0i32; N];

        let mut i = 0;
        while i < N {
            let mut j = 0;
            while j < N {
                let product = i32::from(mul(self.coeffs[i], rhs.coeffs[j]));
                let idx = i + j;
                if idx < N {
                    acc[idx] += product;
                } else {
                    acc[idx - N] -= product;
                }
                j += 1;
            }
            i += 1;
        }

        let mut out = [0i16; N];
        let mut k = 0;
        while k < N {
            out[k] = reduce(acc[k]);
            k += 1;
        }
        Self { coeffs: out }
    }

    /// Encode coefficients as packed 12-bit little-endian values.
    pub fn encode_12(&self) -> [u8; 384] {
        let mut out = [0u8; 384];
        let mut i = 0;
        let mut j = 0;

        while i < N {
            let a = reduce(i32::from(self.coeffs[i])) as u16;
            let b = reduce(i32::from(self.coeffs[i + 1])) as u16;

            out[j] = (a & 0xff) as u8;
            out[j + 1] = ((a >> 8) as u8) | (((b & 0x0f) as u8) << 4);
            out[j + 2] = (b >> 4) as u8;

            i += 2;
            j += 3;
        }

        out
    }

    /// Decode coefficients from packed 12-bit little-endian values.
    pub fn decode_12(input: &[u8; 384]) -> Self {
        let mut coeffs = [0i16; N];
        let mut i = 0;
        let mut j = 0;

        while i < N {
            let a = u16::from(input[j]) | ((u16::from(input[j + 1]) & 0x0f) << 8);
            let b = (u16::from(input[j + 1]) >> 4) | (u16::from(input[j + 2]) << 4);

            coeffs[i] = reduce(i32::from(a));
            coeffs[i + 1] = reduce(i32::from(b));

            i += 2;
            j += 3;
        }

        Self { coeffs }
    }

    /// Compress all coefficients to `d` bits.
    pub fn compress<const BYTES: usize>(&self, d: u32) -> [u8; BYTES] {
        let mut out = [0u8; BYTES];
        let mut bit_pos = 0usize;

        let mut i = 0;
        while i < N {
            let value = u32::from(compress_coefficient(self.coeffs[i], d));
            let mut bit = 0;
            while bit < d {
                if ((value >> bit) & 1) == 1 {
                    let pos = bit_pos + bit as usize;
                    out[pos / 8] |= 1u8 << (pos % 8);
                }
                bit += 1;
            }
            bit_pos += d as usize;
            i += 1;
        }

        out
    }

    /// Decompress all coefficients from `d`-bit packed bytes.
    pub fn decompress<const BYTES: usize>(input: &[u8; BYTES], d: u32) -> Self {
        let mut coeffs = [0i16; N];
        let mut bit_pos = 0usize;

        let mut i = 0;
        while i < N {
            let mut value = 0u16;
            let mut bit = 0;
            while bit < d {
                let pos = bit_pos + bit as usize;
                let b = (input[pos / 8] >> (pos % 8)) & 1;
                value |= u16::from(b) << bit;
                bit += 1;
            }
            coeffs[i] = decompress_coefficient(value, d);
            bit_pos += d as usize;
            i += 1;
        }

        Self { coeffs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_12_round_trip_for_canonical_coefficients() {
        let mut coeffs = [0i16; N];
        let mut i = 0;
        while i < N {
            coeffs[i] = (i as i16) % 3329;
            i += 1;
        }

        let poly = Poly::from_coefficients(coeffs);
        let encoded = poly.encode_12();
        let decoded = Poly::decode_12(&encoded);
        assert_eq!(poly, decoded);
    }

    #[test]
    fn schoolbook_multiplication_respects_identity() {
        let mut one = [0i16; N];
        one[0] = 1;

        let mut coeffs = [0i16; N];
        coeffs[0] = 9;
        coeffs[1] = 7;
        coeffs[255] = 5;

        let p = Poly::from_coefficients(coeffs);
        let id = Poly::from_coefficients(one);
        assert_eq!(p.mul_schoolbook(&id), p);
    }

    #[test]
    fn compress_decompress_shapes_are_correct() {
        let p = Poly::zero();
        let c4 = p.compress::<128>(4);
        let c10 = p.compress::<320>(10);
        assert_eq!(c4.len(), 128);
        assert_eq!(c10.len(), 320);

        let _ = Poly::decompress::<128>(&c4, 4);
        let _ = Poly::decompress::<320>(&c10, 10);
    }
}
