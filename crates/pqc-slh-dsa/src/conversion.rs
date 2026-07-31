//! Byte and integer conversion utilities used by FIPS 205.

use core::fmt;

/// Errors produced by internal byte-conversion operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConversionError {
    /// The requested integer representation is wider than a `u64`.
    IntegerTooWide {
        /// Requested width in bytes.
        requested: usize,
    },

    /// The input does not contain enough bits for the requested digits.
    InsufficientInput {
        /// Required number of bits.
        required_bits: usize,

        /// Available number of bits.
        available_bits: usize,
    },

    /// The requested base-2^b digit width is unsupported.
    InvalidDigitWidth {
        /// Requested digit width.
        bits: usize,
    },
}

impl fmt::Display for ConversionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegerTooWide { requested } => {
                write!(
                    formatter,
                    "integer encoding width {requested} exceeds eight bytes"
                )
            }
            Self::InsufficientInput {
                required_bits,
                available_bits,
            } => {
                write!(
                    formatter,
                    "insufficient input: need {required_bits} bits, have {available_bits}"
                )
            }
            Self::InvalidDigitWidth { bits } => {
                write!(formatter, "invalid base-2^b digit width: {bits}")
            }
        }
    }
}

/// Encode an unsigned integer as a big-endian byte string.
///
/// This implements the FIPS 205 `toByte(x, n)` operation for values that fit
/// in a `u64`. If the requested output is shorter than eight bytes, the
/// low-order bytes are retained.
pub fn to_byte(value: u64, output: &mut [u8]) -> Result<(), ConversionError> {
    if output.len() > size_of::<u64>() {
        return Err(ConversionError::IntegerTooWide {
            requested: output.len(),
        });
    }

    let encoded = value.to_be_bytes();
    let start = encoded.len() - output.len();
    output.copy_from_slice(&encoded[start..]);

    Ok(())
}

/// Decode a big-endian byte string as an unsigned integer.
///
/// Inputs of at most eight bytes are accepted.
pub fn to_int(input: &[u8]) -> Result<u64, ConversionError> {
    if input.len() > size_of::<u64>() {
        return Err(ConversionError::IntegerTooWide {
            requested: input.len(),
        });
    }

    let mut encoded = [0_u8; size_of::<u64>()];
    let start = encoded.len() - input.len();
    encoded[start..].copy_from_slice(input);

    Ok(u64::from_be_bytes(encoded))
}

/// Convert a byte string into base-2^b digits.
///
/// Digits are extracted most-significant bit first. The output slice length
/// determines the number of digits requested.
pub fn base_2b(input: &[u8], bits: usize, output: &mut [u32]) -> Result<(), ConversionError> {
    if !(1..=8).contains(&bits) {
        return Err(ConversionError::InvalidDigitWidth { bits });
    }

    let available_bits = input.len().saturating_mul(8);
    let required_bits =
        output
            .len()
            .checked_mul(bits)
            .ok_or(ConversionError::InsufficientInput {
                required_bits: usize::MAX,
                available_bits,
            })?;

    if required_bits > available_bits {
        return Err(ConversionError::InsufficientInput {
            required_bits,
            available_bits,
        });
    }

    let mask = (1_u32 << bits) - 1;
    let mut input_index = 0_usize;
    let mut accumulator = 0_u32;
    let mut accumulator_bits = 0_usize;

    for digit in output {
        while accumulator_bits < bits {
            accumulator = (accumulator << 8) | u32::from(input[input_index]);
            input_index += 1;
            accumulator_bits += 8;
        }

        accumulator_bits -= bits;
        *digit = (accumulator >> accumulator_bits) & mask;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_byte_uses_big_endian_encoding() {
        let mut output = [0_u8; 4];

        to_byte(0x0102_0304, &mut output).unwrap();

        assert_eq!(output, [1, 2, 3, 4]);
    }

    #[test]
    fn to_byte_returns_requested_low_order_bytes() {
        let mut output = [0_u8; 3];

        to_byte(0x0102_0304, &mut output).unwrap();

        assert_eq!(output, [2, 3, 4]);
    }

    #[test]
    fn to_byte_accepts_empty_output() {
        let mut output = [];

        assert_eq!(to_byte(0x0102_0304, &mut output), Ok(()));
    }

    #[test]
    fn to_byte_rejects_widths_larger_than_u64() {
        let mut output = [0_u8; 9];

        assert_eq!(
            to_byte(0, &mut output),
            Err(ConversionError::IntegerTooWide { requested: 9 })
        );
    }

    #[test]
    fn to_int_uses_big_endian_encoding() {
        assert_eq!(to_int(&[1, 2, 3, 4]), Ok(0x0102_0304));
    }

    #[test]
    fn to_int_accepts_empty_input() {
        assert_eq!(to_int(&[]), Ok(0));
    }

    #[test]
    fn to_int_rejects_widths_larger_than_u64() {
        assert_eq!(
            to_int(&[0_u8; 9]),
            Err(ConversionError::IntegerTooWide { requested: 9 })
        );
    }

    #[test]
    fn base_2b_extracts_digits_most_significant_first() {
        let mut output = [0_u32; 4];

        base_2b(&[0b1101_0010], 2, &mut output).unwrap();

        assert_eq!(output, [3, 1, 0, 2]);
    }

    #[test]
    fn base_2b_crosses_byte_boundaries() {
        let mut output = [0_u32; 4];

        base_2b(&[0b1010_1100, 0b0111_0000], 3, &mut output).unwrap();

        assert_eq!(output, [5, 3, 0, 7]);
    }

    #[test]
    fn base_2b_rejects_invalid_digit_widths() {
        let mut output = [0_u32; 1];

        assert_eq!(
            base_2b(&[0], 0, &mut output),
            Err(ConversionError::InvalidDigitWidth { bits: 0 })
        );

        assert_eq!(
            base_2b(&[0], 9, &mut output),
            Err(ConversionError::InvalidDigitWidth { bits: 9 })
        );
    }

    #[test]
    fn base_2b_rejects_insufficient_input() {
        let mut output = [0_u32; 3];

        assert_eq!(
            base_2b(&[0], 3, &mut output),
            Err(ConversionError::InsufficientInput {
                required_bits: 9,
                available_bits: 8,
            })
        );
    }

    #[test]
    fn base_2b_accepts_empty_output() {
        let mut output = [];

        assert_eq!(base_2b(&[], 4, &mut output), Ok(()));
    }
}
