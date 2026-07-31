//! Winternitz one-time-signature parameter and message-digit operations.
//!
//! This module implements the non-cryptographic WOTS+ preprocessing defined
//! by FIPS 205. Hash-chain generation, signing, and public-key reconstruction
//! are introduced in subsequent stages.

use core::fmt;

use crate::{
    conversion::{base_2b, ConversionError},
    params::SlhDsaParameters,
};

/// Winternitz parameter used by every FIPS 205 SLH-DSA parameter set.
pub const WOTS_W: u32 = 16;

/// Base-two logarithm of [`WOTS_W`].
pub const WOTS_LOG_W: usize = 4;

/// Maximum number of WOTS+ chains among the approved FIPS 205 parameter sets.
pub const MAX_WOTS_LEN: usize = 67;

/// Errors returned by WOTS+ preprocessing operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WotsError {
    /// The supplied message has the wrong length.
    InvalidMessageLength {
        /// Required message length in bytes.
        expected: usize,

        /// Supplied message length in bytes.
        actual: usize,
    },

    /// The output slice has the wrong number of base-`w` digits.
    InvalidDigitCount {
        /// Required number of digits.
        expected: usize,

        /// Supplied number of digits.
        actual: usize,
    },

    /// A WOTS+ parameter or checksum calculation overflowed.
    ParameterOverflow,

    /// Byte-to-base conversion failed.
    Conversion(ConversionError),
}

impl fmt::Display for WotsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMessageLength { expected, actual } => {
                write!(
                    formatter,
                    "invalid WOTS+ message length: expected {expected} bytes, got {actual}"
                )
            }
            Self::InvalidDigitCount { expected, actual } => {
                write!(
                    formatter,
                    "invalid WOTS+ digit count: expected {expected}, got {actual}"
                )
            }
            Self::ParameterOverflow => {
                write!(
                    formatter,
                    "WOTS+ parameter or checksum calculation overflowed"
                )
            }
            Self::Conversion(error) => {
                write!(formatter, "WOTS+ base conversion failed: {error}")
            }
        }
    }
}

impl From<ConversionError> for WotsError {
    fn from(error: ConversionError) -> Self {
        Self::Conversion(error)
    }
}

/// Return `len_1`, the number of base-`w` digits encoding an `n`-byte message.
///
/// FIPS 205 fixes `w = 16`, so each byte contributes two base-16 digits.
pub fn len_1(parameters: &SlhDsaParameters) -> Result<usize, WotsError> {
    parameters
        .n
        .checked_mul(8)
        .and_then(|message_bits| message_bits.checked_add(WOTS_LOG_W - 1))
        .map(|rounded_bits| rounded_bits / WOTS_LOG_W)
        .ok_or(WotsError::ParameterOverflow)
}

/// Return `len_2`, the number of base-`w` digits encoding the WOTS+ checksum.
///
/// This computes:
///
/// `len_2 = floor(log_w(len_1 * (w - 1))) + 1`.
pub fn len_2(parameters: &SlhDsaParameters) -> Result<usize, WotsError> {
    let maximum_checksum = len_1(parameters)?
        .checked_mul((WOTS_W - 1) as usize)
        .ok_or(WotsError::ParameterOverflow)?;

    let mut value = maximum_checksum;
    let mut digits = 0_usize;

    while value > 0 {
        digits = digits.checked_add(1).ok_or(WotsError::ParameterOverflow)?;
        value /= WOTS_W as usize;
    }

    Ok(digits.max(1))
}

/// Return `len`, the total number of WOTS+ chains.
///
/// `len = len_1 + len_2`.
pub fn len(parameters: &SlhDsaParameters) -> Result<usize, WotsError> {
    len_1(parameters)?
        .checked_add(len_2(parameters)?)
        .ok_or(WotsError::ParameterOverflow)
}

/// Return the number of bytes used to encode the WOTS+ checksum.
pub fn checksum_bytes(parameters: &SlhDsaParameters) -> Result<usize, WotsError> {
    len_2(parameters)?
        .checked_mul(WOTS_LOG_W)
        .and_then(|bits| bits.checked_add(7))
        .map(|rounded_bits| rounded_bits / 8)
        .ok_or(WotsError::ParameterOverflow)
}

/// Convert an `n`-byte message into its `len_1` base-`w` digits.
pub fn message_digits(
    parameters: &SlhDsaParameters,
    message: &[u8],
    output: &mut [u32],
) -> Result<(), WotsError> {
    if message.len() != parameters.n {
        return Err(WotsError::InvalidMessageLength {
            expected: parameters.n,
            actual: message.len(),
        });
    }

    let expected = len_1(parameters)?;

    if output.len() != expected {
        return Err(WotsError::InvalidDigitCount {
            expected,
            actual: output.len(),
        });
    }

    base_2b(message, WOTS_LOG_W, output)?;

    Ok(())
}

/// Compute the integer WOTS+ checksum for a sequence of message digits.
///
/// The input must contain exactly `len_1` digits. Every digit must have been
/// produced by the base-`w` message conversion and is therefore in
/// `0..WOTS_W`.
pub fn checksum(parameters: &SlhDsaParameters, message_digits: &[u32]) -> Result<u64, WotsError> {
    let expected = len_1(parameters)?;

    if message_digits.len() != expected {
        return Err(WotsError::InvalidDigitCount {
            expected,
            actual: message_digits.len(),
        });
    }

    message_digits.iter().try_fold(0_u64, |sum, digit| {
        let complement = WOTS_W
            .checked_sub(1)
            .and_then(|maximum| maximum.checked_sub(*digit))
            .ok_or(WotsError::ParameterOverflow)?;

        sum.checked_add(u64::from(complement))
            .ok_or(WotsError::ParameterOverflow)
    })
}

/// Convert the WOTS+ checksum into its `len_2` base-`w` digits.
///
/// FIPS 205 left-shifts the checksum so the base-`w` conversion consumes a
/// whole number of bytes.
pub fn checksum_digits(
    parameters: &SlhDsaParameters,
    message_digits: &[u32],
    output: &mut [u32],
) -> Result<(), WotsError> {
    let expected = len_2(parameters)?;

    if output.len() != expected {
        return Err(WotsError::InvalidDigitCount {
            expected,
            actual: output.len(),
        });
    }

    let checksum_bits = expected
        .checked_mul(WOTS_LOG_W)
        .ok_or(WotsError::ParameterOverflow)?;

    let padding_bits = (8 - (checksum_bits % 8)) % 8;
    let shifted_checksum = checksum(parameters, message_digits)?
        .checked_shl(u32::try_from(padding_bits).map_err(|_| WotsError::ParameterOverflow)?)
        .ok_or(WotsError::ParameterOverflow)?;

    let encoded_bytes = checksum_bytes(parameters)?;

    if encoded_bytes > size_of::<u64>() {
        return Err(WotsError::ParameterOverflow);
    }

    let encoded = shifted_checksum.to_be_bytes();
    let start = encoded.len() - encoded_bytes;

    base_2b(&encoded[start..], WOTS_LOG_W, output)?;

    Ok(())
}

/// Convert a message into all `len` WOTS+ chain lengths.
///
/// The first `len_1` entries encode the message. The remaining `len_2`
/// entries encode its checksum.
pub fn chain_lengths(
    parameters: &SlhDsaParameters,
    message: &[u8],
    output: &mut [u32],
) -> Result<(), WotsError> {
    let message_digit_count = len_1(parameters)?;
    let checksum_digit_count = len_2(parameters)?;
    let expected = message_digit_count
        .checked_add(checksum_digit_count)
        .ok_or(WotsError::ParameterOverflow)?;

    if output.len() != expected {
        return Err(WotsError::InvalidDigitCount {
            expected,
            actual: output.len(),
        });
    }

    let (message_output, checksum_output) = output.split_at_mut(message_digit_count);

    message_digits(parameters, message, message_output)?;
    checksum_digits(parameters, message_output, checksum_output)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::SlhDsaParameterSet;

    const PARAMETER_SETS: [SlhDsaParameterSet; 12] = [
        SlhDsaParameterSet::Sha2_128s,
        SlhDsaParameterSet::Sha2_128f,
        SlhDsaParameterSet::Sha2_192s,
        SlhDsaParameterSet::Sha2_192f,
        SlhDsaParameterSet::Sha2_256s,
        SlhDsaParameterSet::Sha2_256f,
        SlhDsaParameterSet::Shake128s,
        SlhDsaParameterSet::Shake128f,
        SlhDsaParameterSet::Shake192s,
        SlhDsaParameterSet::Shake192f,
        SlhDsaParameterSet::Shake256s,
        SlhDsaParameterSet::Shake256f,
    ];

    #[test]
    fn fips_parameter_sets_have_the_expected_wots_lengths() {
        let expected = [
            (SlhDsaParameterSet::Sha2_128s, 32, 3, 35),
            (SlhDsaParameterSet::Sha2_128f, 32, 3, 35),
            (SlhDsaParameterSet::Sha2_192s, 48, 3, 51),
            (SlhDsaParameterSet::Sha2_192f, 48, 3, 51),
            (SlhDsaParameterSet::Sha2_256s, 64, 3, 67),
            (SlhDsaParameterSet::Sha2_256f, 64, 3, 67),
            (SlhDsaParameterSet::Shake128s, 32, 3, 35),
            (SlhDsaParameterSet::Shake128f, 32, 3, 35),
            (SlhDsaParameterSet::Shake192s, 48, 3, 51),
            (SlhDsaParameterSet::Shake192f, 48, 3, 51),
            (SlhDsaParameterSet::Shake256s, 64, 3, 67),
            (SlhDsaParameterSet::Shake256f, 64, 3, 67),
        ];

        for (parameter_set, expected_len_1, expected_len_2, expected_len) in expected {
            let parameters = parameter_set.parameters();

            assert_eq!(len_1(&parameters), Ok(expected_len_1));
            assert_eq!(len_2(&parameters), Ok(expected_len_2));
            assert_eq!(len(&parameters), Ok(expected_len));
        }
    }

    #[test]
    fn maximum_fips_wots_length_matches_the_constant() {
        for parameter_set in PARAMETER_SETS {
            assert!(len(&parameter_set.parameters()).unwrap() <= MAX_WOTS_LEN);
        }

        assert_eq!(
            len(&SlhDsaParameterSet::Sha2_256s.parameters()),
            Ok(MAX_WOTS_LEN)
        );
    }

    #[test]
    fn every_fips_checksum_uses_two_bytes() {
        for parameter_set in PARAMETER_SETS {
            assert_eq!(checksum_bytes(&parameter_set.parameters()), Ok(2));
        }
    }

    #[test]
    fn message_digits_are_extracted_most_significant_first() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.n = 2;

        let mut output = [0_u32; 4];

        message_digits(&parameters, &[0xab, 0x4d], &mut output).unwrap();

        assert_eq!(output, [10, 11, 4, 13]);
    }

    #[test]
    fn message_digits_reject_the_wrong_message_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let mut output = [0_u32; 32];

        assert_eq!(
            message_digits(&parameters, &[0_u8; 15], &mut output),
            Err(WotsError::InvalidMessageLength {
                expected: 16,
                actual: 15,
            })
        );
    }

    #[test]
    fn message_digits_reject_the_wrong_output_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let message = [0_u8; 16];
        let mut output = [0_u32; 31];

        assert_eq!(
            message_digits(&parameters, &message, &mut output),
            Err(WotsError::InvalidDigitCount {
                expected: 32,
                actual: 31,
            })
        );
    }

    #[test]
    fn checksum_is_the_sum_of_digit_complements() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.n = 2;

        let digits = [10, 11, 4, 13];

        assert_eq!(checksum(&parameters, &digits), Ok((5 + 4 + 11 + 2) as u64));
    }

    #[test]
    fn all_zero_message_has_the_maximal_checksum() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let digits = [0_u32; 32];

        assert_eq!(checksum(&parameters, &digits), Ok(32 * 15));
    }

    #[test]
    fn all_maximal_digits_have_zero_checksum() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let digits = [15_u32; 32];

        assert_eq!(checksum(&parameters, &digits), Ok(0));
    }

    #[test]
    fn checksum_rejects_digits_outside_base_w() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let mut digits = [0_u32; 32];
        digits[7] = WOTS_W;

        assert_eq!(
            checksum(&parameters, &digits),
            Err(WotsError::ParameterOverflow)
        );
    }

    #[test]
    fn checksum_digits_include_the_required_left_shift() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let digits = [0_u32; 32];
        let mut output = [0_u32; 3];

        checksum_digits(&parameters, &digits, &mut output).unwrap();

        // checksum = 32 * 15 = 480 = 0x01e0.
        // FIPS 205 shifts it left by four bits before base-16 conversion:
        // 0x1e00 -> [1, 14, 0].
        assert_eq!(output, [1, 14, 0]);
    }

    #[test]
    fn chain_lengths_concatenate_message_and_checksum_digits() {
        let mut parameters = SlhDsaParameterSet::Shake128s.parameters();
        parameters.n = 2;

        let mut output = [0_u32; 6];

        chain_lengths(&parameters, &[0xab, 0x4d], &mut output).unwrap();

        assert_eq!(&output[..4], &[10, 11, 4, 13]);
        assert_eq!(&output[4..], &[1, 6]);
    }

    #[test]
    fn every_chain_length_is_bounded_by_w_minus_one() {
        for parameter_set in PARAMETER_SETS {
            let parameters = parameter_set.parameters();
            let message = [0xa5_u8; 32];
            let mut output = [0_u32; MAX_WOTS_LEN];
            let output_length = len(&parameters).unwrap();

            chain_lengths(
                &parameters,
                &message[..parameters.n],
                &mut output[..output_length],
            )
            .unwrap();

            assert!(output[..output_length].iter().all(|digit| *digit < WOTS_W));
        }
    }

    #[test]
    fn chain_lengths_reject_the_wrong_output_length() {
        let parameters = SlhDsaParameterSet::Shake128s.parameters();
        let message = [0_u8; 16];
        let mut output = [0_u32; 34];

        assert_eq!(
            chain_lengths(&parameters, &message, &mut output),
            Err(WotsError::InvalidDigitCount {
                expected: 35,
                actual: 34,
            })
        );
    }
}
