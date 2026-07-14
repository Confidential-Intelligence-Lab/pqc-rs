//! Canonical ML-DSA polynomial coefficient encodings.
//!
//! Aggregate key and signature encodings are added in Stage 9D-1B.

use crate::constants::N;
use crate::poly::Poly;
use crate::rounding::{Gamma2, D};

/// Encoded byte length of an `eta = 2` polynomial.
pub const POLY_ETA2_BYTES: usize = 96;
/// Encoded byte length of an `eta = 4` polynomial.
pub const POLY_ETA4_BYTES: usize = 128;
/// Encoded byte length of a `t1` polynomial.
pub const POLY_T1_BYTES: usize = 320;
/// Encoded byte length of a `t0` polynomial.
pub const POLY_T0_BYTES: usize = 416;
/// Encoded byte length of a `z` polynomial when `gamma1 = 2^17`.
pub const POLY_Z_17_BYTES: usize = 576;
/// Encoded byte length of a `z` polynomial when `gamma1 = 2^19`.
pub const POLY_Z_19_BYTES: usize = 640;
/// Encoded byte length of a `w1` polynomial for `(Q - 1) / 88`.
pub const POLY_W1_88_BYTES: usize = 192;
/// Encoded byte length of a `w1` polynomial for `(Q - 1) / 32`.
pub const POLY_W1_32_BYTES: usize = 128;

/// Error returned by strict ML-DSA coefficient encoding and decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodingError {
    /// The supplied byte slice has the wrong length.
    InvalidLength,
    /// A coefficient is outside the canonical encoding range.
    NonCanonicalCoefficient,
    /// The selected ML-DSA parameter value is unsupported.
    UnsupportedParameter,
}

/// Encode a bounded secret polynomial with coefficients in `[-eta, eta]`.
pub fn encode_eta(poly: &Poly, eta: i32) -> Result<Vec<u8>, EncodingError> {
    let (bits, bytes) = match eta {
        2 => (3, POLY_ETA2_BYTES),
        4 => (4, POLY_ETA4_BYTES),
        _ => return Err(EncodingError::UnsupportedParameter),
    };
    let mut values = [0_u32; N];
    for (out, c) in values.iter_mut().zip(poly.coeffs()) {
        if !(-eta..=eta).contains(c) {
            return Err(EncodingError::NonCanonicalCoefficient);
        }
        *out = (eta - *c) as u32;
    }
    Ok(pack_values(&values, bits, bytes))
}

/// Strictly decode a bounded secret polynomial.
pub fn decode_eta(input: &[u8], eta: i32) -> Result<Poly, EncodingError> {
    let (bits, bytes, max) = match eta {
        2 => (3, POLY_ETA2_BYTES, 4_u32),
        4 => (4, POLY_ETA4_BYTES, 8_u32),
        _ => return Err(EncodingError::UnsupportedParameter),
    };
    let values = unpack_values(input, bits, bytes)?;
    let mut coeffs = [0_i32; N];
    for (out, v) in coeffs.iter_mut().zip(values) {
        if v > max {
            return Err(EncodingError::NonCanonicalCoefficient);
        }
        *out = eta - v as i32;
    }
    Ok(Poly::from_coeffs(coeffs))
}

/// Encode a `t1` polynomial with coefficients in `[0, 1024)`.
pub fn encode_t1(poly: &Poly) -> Result<Vec<u8>, EncodingError> {
    encode_unsigned(poly, 10, POLY_T1_BYTES, 1 << 10)
}

/// Strictly decode a `t1` polynomial.
pub fn decode_t1(input: &[u8]) -> Result<Poly, EncodingError> {
    decode_unsigned(input, 10, POLY_T1_BYTES, 1 << 10)
}

/// Encode a centered `t0` polynomial.
pub fn encode_t0(poly: &Poly) -> Result<Vec<u8>, EncodingError> {
    let bound = 1_i32 << (D - 1);
    let mut values = [0_u32; N];
    for (out, c) in values.iter_mut().zip(poly.coeffs()) {
        if *c <= -bound || *c > bound {
            return Err(EncodingError::NonCanonicalCoefficient);
        }
        *out = (bound - *c) as u32;
    }
    Ok(pack_values(&values, 13, POLY_T0_BYTES))
}

/// Strictly decode a centered `t0` polynomial.
pub fn decode_t0(input: &[u8]) -> Result<Poly, EncodingError> {
    let bound = 1_i32 << (D - 1);
    let values = unpack_values(input, 13, POLY_T0_BYTES)?;
    let mut coeffs = [0_i32; N];
    for (out, v) in coeffs.iter_mut().zip(values) {
        let c = bound - v as i32;
        if c <= -bound || c > bound {
            return Err(EncodingError::NonCanonicalCoefficient);
        }
        *out = c;
    }
    Ok(Poly::from_coeffs(coeffs))
}

/// Encode a signing-mask polynomial `z` for the selected `gamma1`.
pub fn encode_z(poly: &Poly, gamma1: i32) -> Result<Vec<u8>, EncodingError> {
    let (bits, bytes) = z_parameters(gamma1)?;
    let mut values = [0_u32; N];
    for (out, c) in values.iter_mut().zip(poly.coeffs()) {
        if *c < -gamma1 + 1 || *c > gamma1 {
            return Err(EncodingError::NonCanonicalCoefficient);
        }
        *out = (gamma1 - *c) as u32;
    }
    Ok(pack_values(&values, bits, bytes))
}

/// Strictly decode a signing-mask polynomial `z`.
pub fn decode_z(input: &[u8], gamma1: i32) -> Result<Poly, EncodingError> {
    let (bits, bytes) = z_parameters(gamma1)?;
    let values = unpack_values(input, bits, bytes)?;
    let max = (2 * gamma1 - 1) as u32;
    let mut coeffs = [0_i32; N];
    for (out, v) in coeffs.iter_mut().zip(values) {
        if v > max {
            return Err(EncodingError::NonCanonicalCoefficient);
        }
        *out = gamma1 - v as i32;
    }
    Ok(Poly::from_coeffs(coeffs))
}

/// Encode a `w1` polynomial for the selected `gamma2`.
pub fn encode_w1(poly: &Poly, gamma2: Gamma2) -> Result<Vec<u8>, EncodingError> {
    match gamma2 {
        Gamma2::QMinusOneOver88 => encode_unsigned(poly, 6, POLY_W1_88_BYTES, 44),
        Gamma2::QMinusOneOver32 => encode_unsigned(poly, 4, POLY_W1_32_BYTES, 16),
    }
}

/// Strictly decode a `w1` polynomial for the selected `gamma2`.
pub fn decode_w1(input: &[u8], gamma2: Gamma2) -> Result<Poly, EncodingError> {
    match gamma2 {
        Gamma2::QMinusOneOver88 => decode_unsigned(input, 6, POLY_W1_88_BYTES, 44),
        Gamma2::QMinusOneOver32 => decode_unsigned(input, 4, POLY_W1_32_BYTES, 16),
    }
}

fn z_parameters(gamma1: i32) -> Result<(usize, usize), EncodingError> {
    match gamma1 {
        x if x == 1 << 17 => Ok((18, POLY_Z_17_BYTES)),
        x if x == 1 << 19 => Ok((20, POLY_Z_19_BYTES)),
        _ => Err(EncodingError::UnsupportedParameter),
    }
}

fn encode_unsigned(
    poly: &Poly,
    bits: usize,
    bytes: usize,
    upper: i32,
) -> Result<Vec<u8>, EncodingError> {
    let mut values = [0_u32; N];
    for (out, c) in values.iter_mut().zip(poly.coeffs()) {
        if !(0..upper).contains(c) {
            return Err(EncodingError::NonCanonicalCoefficient);
        }
        *out = *c as u32;
    }
    Ok(pack_values(&values, bits, bytes))
}

fn decode_unsigned(
    input: &[u8],
    bits: usize,
    bytes: usize,
    upper: i32,
) -> Result<Poly, EncodingError> {
    let values = unpack_values(input, bits, bytes)?;
    let mut coeffs = [0_i32; N];
    for (out, v) in coeffs.iter_mut().zip(values) {
        if v >= upper as u32 {
            return Err(EncodingError::NonCanonicalCoefficient);
        }
        *out = v as i32;
    }
    Ok(Poly::from_coeffs(coeffs))
}

fn pack_values(values: &[u32; N], bits: usize, bytes: usize) -> Vec<u8> {
    debug_assert_eq!(N * bits, bytes * 8);
    let mut output = vec![0_u8; bytes];
    let mut acc = 0_u64;
    let mut acc_bits = 0_usize;
    let mut out_index = 0_usize;
    for value in values {
        acc |= u64::from(*value) << acc_bits;
        acc_bits += bits;
        while acc_bits >= 8 {
            output[out_index] = acc as u8;
            out_index += 1;
            acc >>= 8;
            acc_bits -= 8;
        }
    }
    output
}

fn unpack_values(input: &[u8], bits: usize, bytes: usize) -> Result<[u32; N], EncodingError> {
    if input.len() != bytes {
        return Err(EncodingError::InvalidLength);
    }
    let mut values = [0_u32; N];
    let mut acc = 0_u64;
    let mut acc_bits = 0_usize;
    let mut in_index = 0_usize;
    let mask = (1_u64 << bits) - 1;
    for value in &mut values {
        while acc_bits < bits {
            acc |= u64::from(input[in_index]) << acc_bits;
            in_index += 1;
            acc_bits += 8;
        }
        *value = (acc & mask) as u32;
        acc >>= bits;
        acc_bits -= bits;
    }
    if in_index != bytes || acc != 0 {
        return Err(EncodingError::NonCanonicalCoefficient);
    }
    Ok(values)
}
