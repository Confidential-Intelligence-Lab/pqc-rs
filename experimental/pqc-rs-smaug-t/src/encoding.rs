// SPDX-License-Identifier: MIT

//! Experimental SMAUG-T polynomial serialization.
//!
//! This module implements checked, canonical encodings.
//! Reference C compatibility must be established by differential tests.

pub const POLY_N: usize = 256;
pub const SECRET_POLY_BYTES: usize = POLY_N / 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodingError {
    InvalidWidth,
    InvalidLength,
    CoefficientOutOfRange,
    InvalidSecretCoefficient,
    NonCanonicalSecretEncoding,
}

/// Number of bytes required to encode 256 coefficients at `width` bits.
pub fn packed_len(width: u8) -> Result<usize, EncodingError> {
    if !(3..=11).contains(&width) {
        return Err(EncodingError::InvalidWidth);
    }
    Ok(POLY_N * usize::from(width) / 8)
}

/// Pack canonical nonnegative coefficients, least-significant bit first.
pub fn pack_unsigned(coefficients: &[u16; POLY_N], width: u8) -> Result<Vec<u8>, EncodingError> {
    let len = packed_len(width)?;
    let limit = 1u16 << width;

    if coefficients.iter().any(|&x| x >= limit) {
        return Err(EncodingError::CoefficientOutOfRange);
    }

    let mut output = vec![0u8; len];

    for (index, &coefficient) in coefficients.iter().enumerate() {
        let bit_offset = index * usize::from(width);

        for bit in 0..usize::from(width) {
            let position = bit_offset + bit;
            let value = ((coefficient >> bit) & 1) as u8;
            output[position / 8] |= value << (position % 8);
        }
    }

    Ok(output)
}

/// Unpack exactly 256 canonical unsigned coefficients.
pub fn unpack_unsigned(bytes: &[u8], width: u8) -> Result<[u16; POLY_N], EncodingError> {
    let len = packed_len(width)?;

    if bytes.len() != len {
        return Err(EncodingError::InvalidLength);
    }

    let mut coefficients = [0u16; POLY_N];

    for (index, coefficient) in coefficients.iter_mut().enumerate() {
        let bit_offset = index * usize::from(width);
        let mut value = 0u16;

        for bit in 0..usize::from(width) {
            let position = bit_offset + bit;
            let extracted = (bytes[position / 8] >> (position % 8)) & 1;
            value |= u16::from(extracted) << bit;
        }

        *coefficient = value;
    }

    Ok(coefficients)
}

/// Encode a canonical secret polynomial with coefficients in {-1, 0, 1}.
pub fn pack_secret(coefficients: &[i16; POLY_N]) -> Result<[u8; SECRET_POLY_BYTES], EncodingError> {
    let mut output = [0u8; SECRET_POLY_BYTES];

    for (index, &coefficient) in coefficients.iter().enumerate() {
        if !(-1..=1).contains(&coefficient) {
            return Err(EncodingError::InvalidSecretCoefficient);
        }

        let encoded = (1 - coefficient) as u8;
        output[index / 4] |= encoded << (2 * (index % 4));
    }

    Ok(output)
}

/// Decode a canonical secret polynomial.
///
/// Unlike the reference C decoder, this rejects the unused codeword 3.
pub fn unpack_secret(bytes: &[u8]) -> Result<[i16; POLY_N], EncodingError> {
    if bytes.len() != SECRET_POLY_BYTES {
        return Err(EncodingError::InvalidLength);
    }

    let mut coefficients = [0i16; POLY_N];

    for (index, coefficient) in coefficients.iter_mut().enumerate() {
        let encoded = (bytes[index / 4] >> (2 * (index % 4))) & 3;

        if encoded == 3 {
            return Err(EncodingError::NonCanonicalSecretEncoding);
        }

        *coefficient = 1 - i16::from(encoded);
    }

    Ok(coefficients)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIDTHS: [u8; 7] = [3, 4, 5, 7, 8, 9, 10];

    #[test]
    fn unsigned_roundtrip_all_widths() {
        for width in 3..=11 {
            let limit = 1u16 << width;
            let mut coefficients = [0u16; POLY_N];

            for (i, coefficient) in coefficients.iter_mut().enumerate() {
                *coefficient = ((i * 73 + 19) as u16) % limit;
            }

            let bytes = pack_unsigned(&coefficients, width).unwrap();
            assert_eq!(bytes.len(), packed_len(width).unwrap());
            assert_eq!(unpack_unsigned(&bytes, width).unwrap(), coefficients);
        }
    }

    #[test]
    fn independent_bit_position_oracle() {
        for width in 3..=11 {
            let mut coefficients = [0u16; POLY_N];

            for index in [0, 1, 7, 8, 127, 254, 255] {
                coefficients[index] = 1;

                let bytes = pack_unsigned(&coefficients, width).unwrap();
                let position = index * usize::from(width);

                assert_eq!(bytes[position / 8], 1 << (position % 8));
                assert_eq!(bytes.iter().map(|b| b.count_ones()).sum::<u32>(), 1);

                coefficients[index] = 0;
            }
        }
    }

    #[test]
    fn all_maximum_coefficients() {
        for width in 3..=11 {
            let coefficients = [(1u16 << width) - 1; POLY_N];
            let bytes = pack_unsigned(&coefficients, width).unwrap();

            assert!(bytes.iter().all(|&b| b == 0xff));
            assert_eq!(unpack_unsigned(&bytes, width).unwrap(), coefficients);
        }
    }

    #[test]
    fn secret_known_encoding() {
        let mut coefficients = [0i16; POLY_N];
        coefficients[0] = 1;
        coefficients[1] = 0;
        coefficients[2] = -1;
        coefficients[3] = 1;

        let bytes = pack_secret(&coefficients).unwrap();

        assert_eq!(bytes[0], 0b00_10_01_00);
        assert_eq!(unpack_secret(&bytes).unwrap(), coefficients);
    }

    #[test]
    fn secret_rejects_noncanonical_values() {
        let mut coefficients = [0i16; POLY_N];
        coefficients[0] = -2;

        assert_eq!(
            pack_secret(&coefficients),
            Err(EncodingError::InvalidSecretCoefficient)
        );

        let mut bytes = [0u8; SECRET_POLY_BYTES];
        bytes[0] = 3;

        assert_eq!(
            unpack_secret(&bytes),
            Err(EncodingError::NonCanonicalSecretEncoding)
        );
    }

    #[test]
    fn rejects_invalid_width_and_length() {
        assert_eq!(packed_len(2), Err(EncodingError::InvalidWidth));
        assert_eq!(packed_len(12), Err(EncodingError::InvalidWidth));

        assert_eq!(unpack_unsigned(&[], 8), Err(EncodingError::InvalidLength));

        assert_eq!(unpack_secret(&[]), Err(EncodingError::InvalidLength));
    }

    #[test]
    fn rejects_out_of_range_coefficients() {
        for width in WIDTHS.into_iter().chain([11]) {
            let mut coefficients = [0u16; POLY_N];
            coefficients[255] = 1u16 << width;

            assert_eq!(
                pack_unsigned(&coefficients, width),
                Err(EncodingError::CoefficientOutOfRange)
            );
        }
    }
}
