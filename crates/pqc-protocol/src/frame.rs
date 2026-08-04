//! Transport-independent complete protocol frame representation.

use crate::{
    MessageClass, MessageId, ProtocolDecode, ProtocolDirection, ProtocolEncode, ProtocolError,
    ProtocolId, ProtocolResult, ProtocolVersion, WireHeader, WIRE_HEADER_LEN,
};

/// Maximum payload length representable by a complete frame on this target.
///
/// The bound accounts for both the 32-bit payload-length field and the
/// address-space space required by the fixed header.
pub const MAX_FRAME_PAYLOAD_LEN: usize = {
    let field_maximum = u32::MAX as usize;
    let address_space_maximum = usize::MAX - WIRE_HEADER_LEN;

    if field_maximum < address_space_maximum {
        field_maximum
    } else {
        address_space_maximum
    }
};

/// Borrowed, transport-independent view of one complete protocol frame.
///
/// A frame consists of a validated fixed [`WireHeader`] followed immediately
/// by exactly the number of payload bytes declared by that header. The payload
/// is borrowed rather than copied or allocated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolFrame<'a> {
    header: WireHeader,
    payload: &'a [u8],
}

impl<'a> ProtocolFrame<'a> {
    /// Construct a frame from a header and borrowed payload.
    ///
    /// The declared and actual payload lengths must agree.
    pub fn new(header: WireHeader, payload: &'a [u8]) -> ProtocolResult<Self> {
        validate_payload_length(payload.len())?;

        if header.payload_length() != payload.len() as u32 {
            return Err(ProtocolError::PayloadLengthMismatch {
                declared: header.payload_length(),
                actual: payload.len(),
            });
        }

        Ok(Self { header, payload })
    }

    /// Construct a frame using the current wire version and no flags.
    pub fn current(
        protocol_version: ProtocolVersion,
        protocol_id: ProtocolId,
        message_id: MessageId,
        message_class: MessageClass,
        direction: ProtocolDirection,
        payload: &'a [u8],
    ) -> ProtocolResult<Self> {
        validate_payload_length(payload.len())?;

        let header = WireHeader::current(
            protocol_version,
            protocol_id,
            message_id,
            message_class,
            direction,
            payload.len() as u32,
        );

        Ok(Self { header, payload })
    }

    /// Decode one complete frame from the beginning of `input`.
    ///
    /// The returned frame borrows its payload directly from `input`. Any bytes
    /// following the decoded frame remain unconsumed.
    pub fn decode_prefix(input: &'a [u8]) -> ProtocolResult<(Self, usize)> {
        let (header, header_length) = WireHeader::decode_prefix(input)?;
        let payload_length = header.payload_length() as usize;

        validate_payload_length(payload_length)?;

        let frame_length = header_length + payload_length;

        if input.len() < frame_length {
            return Err(ProtocolError::UnexpectedEnd);
        }

        let payload = &input[header_length..frame_length];

        Ok((Self { header, payload }, frame_length))
    }

    /// Decode exactly one complete frame and reject trailing bytes.
    pub fn decode_exact(input: &'a [u8]) -> ProtocolResult<Self> {
        let (frame, consumed) = Self::decode_prefix(input)?;

        if consumed != input.len() {
            return Err(ProtocolError::TrailingData);
        }

        Ok(frame)
    }

    /// Return the validated wire header.
    pub const fn header(&self) -> WireHeader {
        self.header
    }

    /// Return the borrowed payload.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Return the complete encoded frame length.
    pub const fn frame_len(&self) -> usize {
        WIRE_HEADER_LEN + self.payload.len()
    }

    /// Consume the frame and return its header and payload.
    pub fn into_parts(self) -> (WireHeader, &'a [u8]) {
        (self.header, self.payload)
    }
}

impl ProtocolEncode for ProtocolFrame<'_> {
    fn encoded_len(&self) -> usize {
        self.frame_len()
    }

    fn encode_into(&self, output: &mut [u8]) -> ProtocolResult<usize> {
        let required = self.frame_len();

        if output.len() < required {
            return Err(ProtocolError::BufferTooSmall {
                required,
                available: output.len(),
            });
        }

        self.header.encode_into(&mut output[..WIRE_HEADER_LEN])?;
        output[WIRE_HEADER_LEN..required].copy_from_slice(self.payload);

        Ok(required)
    }
}

fn validate_payload_length(length: usize) -> ProtocolResult<()> {
    if length > MAX_FRAME_PAYLOAD_LEN {
        return Err(ProtocolError::PayloadTooLarge {
            length,
            maximum: MAX_FRAME_PAYLOAD_LEN,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WIRE_MAGIC;

    const PAYLOAD: &[u8] = &[0x10, 0x20, 0x30, 0x40];

    fn frame() -> ProtocolFrame<'static> {
        ProtocolFrame::current(
            ProtocolVersion::new(1, 2),
            ProtocolId::new(0x0100),
            MessageId::new(0x0200),
            MessageClass::Application,
            ProtocolDirection::ClientToServer,
            PAYLOAD,
        )
        .unwrap()
    }

    fn encoded_frame() -> [u8; WIRE_HEADER_LEN + PAYLOAD.len()] {
        let mut encoded = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len()];
        let written = frame().encode_into(&mut encoded).unwrap();

        assert_eq!(written, encoded.len());
        encoded
    }

    #[test]
    fn current_frame_derives_payload_length() {
        let frame = frame();

        assert_eq!(frame.header().payload_length(), PAYLOAD.len() as u32);
        assert_eq!(frame.payload(), PAYLOAD);
        assert_eq!(frame.frame_len(), WIRE_HEADER_LEN + PAYLOAD.len());
    }

    #[test]
    fn constructor_rejects_payload_length_mismatch() {
        let header = WireHeader::current(
            ProtocolVersion::new(1, 2),
            ProtocolId::new(0x0100),
            MessageId::new(0x0200),
            MessageClass::Application,
            ProtocolDirection::ClientToServer,
            3,
        );

        assert_eq!(
            ProtocolFrame::new(header, PAYLOAD),
            Err(ProtocolError::PayloadLengthMismatch {
                declared: 3,
                actual: 4,
            })
        );
    }

    #[test]
    fn frame_encoding_concatenates_header_and_payload() {
        let encoded = encoded_frame();

        assert_eq!(&encoded[..4], &WIRE_MAGIC);
        assert_eq!(&encoded[WIRE_HEADER_LEN..], PAYLOAD);
        assert_eq!(frame().encoded_len(), encoded.len());
    }

    #[test]
    fn frame_encoding_rejects_short_output() {
        let frame = frame();
        let mut output = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len() - 1];

        assert_eq!(
            frame.encode_into(&mut output),
            Err(ProtocolError::BufferTooSmall {
                required: WIRE_HEADER_LEN + PAYLOAD.len(),
                available: WIRE_HEADER_LEN + PAYLOAD.len() - 1,
            })
        );
    }

    #[test]
    fn prefix_decoding_borrows_payload_and_reports_consumption() {
        let encoded = encoded_frame();
        let mut input = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len() + 2];

        input[..encoded.len()].copy_from_slice(&encoded);
        input[encoded.len()..].copy_from_slice(&[0xaa, 0xbb]);

        let (decoded, consumed) = ProtocolFrame::decode_prefix(&input).unwrap();

        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded.header(), frame().header());
        assert_eq!(decoded.payload(), PAYLOAD);
        assert_eq!(
            decoded.payload().as_ptr(),
            input[WIRE_HEADER_LEN..].as_ptr()
        );
    }

    #[test]
    fn exact_decoding_accepts_complete_frame() {
        let encoded = encoded_frame();
        let decoded = ProtocolFrame::decode_exact(&encoded).unwrap();

        assert_eq!(decoded, frame());
    }

    #[test]
    fn exact_decoding_rejects_trailing_bytes() {
        let encoded = encoded_frame();
        let mut input = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len() + 1];

        input[..encoded.len()].copy_from_slice(&encoded);

        assert_eq!(
            ProtocolFrame::decode_exact(&input),
            Err(ProtocolError::TrailingData)
        );
    }

    #[test]
    fn decoding_rejects_truncated_payload() {
        let encoded = encoded_frame();

        assert_eq!(
            ProtocolFrame::decode_prefix(&encoded[..encoded.len() - 1]),
            Err(ProtocolError::UnexpectedEnd)
        );
    }

    #[test]
    fn zero_length_payload_round_trips() {
        let frame = ProtocolFrame::current(
            ProtocolVersion::new(1, 0),
            ProtocolId::new(1),
            MessageId::new(1),
            MessageClass::Control,
            ProtocolDirection::ServerToClient,
            &[],
        )
        .unwrap();

        let mut encoded = [0_u8; WIRE_HEADER_LEN];
        frame.encode_into(&mut encoded).unwrap();

        let decoded = ProtocolFrame::decode_exact(&encoded).unwrap();

        assert!(decoded.payload().is_empty());
        assert_eq!(decoded.frame_len(), WIRE_HEADER_LEN);
    }

    #[test]
    fn into_parts_preserves_header_and_payload() {
        let original = frame();
        let (header, payload) = original.into_parts();

        assert_eq!(header, frame().header());
        assert_eq!(payload, PAYLOAD);
    }
}
