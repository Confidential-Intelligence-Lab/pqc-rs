//! Non-allocating protocol encoding and decoding contracts.

use crate::{ProtocolError, ProtocolResult};

/// A protocol value that can be encoded into caller-provided storage.
///
/// Implementations must either write the complete canonical encoding or
/// return an error. They must not silently truncate the encoding.
pub trait ProtocolEncode {
    /// Return the exact number of bytes required by the canonical encoding.
    fn encoded_len(&self) -> usize;

    /// Encode into `output` and return the number of bytes written.
    ///
    /// If `output` is too small, implementations must return
    /// [`ProtocolError::BufferTooSmall`] without reporting success.
    fn encode_into(&self, output: &mut [u8]) -> ProtocolResult<usize>;
}

/// A protocol value that can be decoded from a byte sequence.
///
/// Prefix decoding supports parsing one value from the start of a larger
/// frame or receive buffer. Exact decoding additionally rejects trailing
/// bytes.
pub trait ProtocolDecode: Sized {
    /// Decode exactly one value from the beginning of `input`.
    ///
    /// Implementations must not inspect bytes beyond those required to decode
    /// the returned value.
    ///
    /// The returned byte count is the exact number of bytes consumed and lets
    /// higher-level framing code continue parsing the remaining input.
    fn decode_prefix(input: &[u8]) -> ProtocolResult<(Self, usize)>;

    /// Decode one value and require that it consumes the complete input.
    fn decode_exact(input: &[u8]) -> ProtocolResult<Self> {
        let (value, consumed) = Self::decode_prefix(input)?;

        if consumed != input.len() {
            return Err(ProtocolError::TrailingData);
        }

        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TwoByteValue([u8; 2]);

    impl ProtocolEncode for TwoByteValue {
        fn encoded_len(&self) -> usize {
            self.0.len()
        }

        fn encode_into(&self, output: &mut [u8]) -> ProtocolResult<usize> {
            let required = self.encoded_len();

            if output.len() < required {
                return Err(ProtocolError::BufferTooSmall {
                    required,
                    available: output.len(),
                });
            }

            output[..required].copy_from_slice(&self.0);
            Ok(required)
        }
    }

    impl ProtocolDecode for TwoByteValue {
        fn decode_prefix(input: &[u8]) -> ProtocolResult<(Self, usize)> {
            const ENCODED_LENGTH: usize = 2;

            if input.len() < ENCODED_LENGTH {
                return Err(ProtocolError::UnexpectedEnd);
            }

            Ok((Self([input[0], input[1]]), ENCODED_LENGTH))
        }
    }

    #[test]
    fn encoding_writes_to_caller_buffer() {
        let value = TwoByteValue([0x12, 0x34]);
        let mut output = [0_u8; 4];

        let written = value.encode_into(&mut output).unwrap();

        assert_eq!(value.encoded_len(), written);
        assert_eq!(written, 2);
        assert_eq!(&output[..written], &[0x12, 0x34]);
        assert_eq!(&output[written..], &[0x00, 0x00]);
    }

    #[test]
    fn encoding_rejects_insufficient_output() {
        let value = TwoByteValue([0x12, 0x34]);
        let mut output = [0_u8; 1];

        assert_eq!(
            value.encode_into(&mut output),
            Err(ProtocolError::BufferTooSmall {
                required: 2,
                available: 1,
            })
        );
    }

    #[test]
    fn prefix_decoding_reports_consumption() {
        let input = [0x12, 0x34, 0x56];

        let (value, consumed) = TwoByteValue::decode_prefix(&input).unwrap();

        assert_eq!(value, TwoByteValue([0x12, 0x34]));
        assert_eq!(consumed, 2);
    }

    #[test]
    fn prefix_decoding_rejects_truncated_input() {
        assert_eq!(
            TwoByteValue::decode_prefix(&[0x12]),
            Err(ProtocolError::UnexpectedEnd)
        );
    }

    #[test]
    fn exact_decoding_accepts_complete_input() {
        assert_eq!(
            TwoByteValue::decode_exact(&[0x12, 0x34]).unwrap(),
            TwoByteValue([0x12, 0x34])
        );
    }

    #[test]
    fn exact_decoding_rejects_trailing_input() {
        assert_eq!(
            TwoByteValue::decode_exact(&[0x12, 0x34, 0x56]),
            Err(ProtocolError::TrailingData)
        );
    }
}
