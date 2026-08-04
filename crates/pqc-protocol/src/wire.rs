//! Fixed, versioned protocol wire-format primitives.

use crate::{
    MessageClass, MessageId, ProtocolDecode, ProtocolDirection, ProtocolEncode, ProtocolError,
    ProtocolId, ProtocolResult, ProtocolVersion,
};

/// Magic prefix identifying a PQC-rs protocol frame.
pub const WIRE_MAGIC: [u8; 4] = *b"PQCR";

/// Fixed encoded length of the initial wire header.
pub const WIRE_HEADER_LEN: usize = 32;

/// Number of bytes reserved for future fixed-header extensions.
pub const WIRE_RESERVED_LEN: usize = 8;

const MAGIC_OFFSET: usize = 0;
const WIRE_VERSION_OFFSET: usize = 4;
const HEADER_LENGTH_OFFSET: usize = 6;
const PROTOCOL_VERSION_MAJOR_OFFSET: usize = 8;
const PROTOCOL_VERSION_MINOR_OFFSET: usize = 10;
const PROTOCOL_ID_OFFSET: usize = 12;
const MESSAGE_ID_OFFSET: usize = 14;
const FLAGS_OFFSET: usize = 16;
const MESSAGE_CLASS_OFFSET: usize = 18;
const DIRECTION_OFFSET: usize = 19;
const PAYLOAD_LENGTH_OFFSET: usize = 20;
const RESERVED_OFFSET: usize = 24;

const CONTROL_CLASS: u8 = 0;
const HANDSHAKE_CLASS: u8 = 1;
const APPLICATION_CLASS: u8 = 2;

const CLIENT_TO_SERVER_DIRECTION: u8 = 0;
const SERVER_TO_CLIENT_DIRECTION: u8 = 1;

/// Version of the binary framing format.
///
/// Wire-format versions are independent from [`ProtocolVersion`]. A wire
/// version identifies the binary representation, while a protocol version
/// identifies the semantics interpreted within that representation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WireVersion(u16);

impl WireVersion {
    /// Initial PQC-rs wire-format version.
    pub const V1: Self = Self(1);

    /// Construct a wire-format version from its registry value.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the numeric wire-format version.
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Return whether this version is supported by the current implementation.
    pub const fn is_supported(self) -> bool {
        self.0 == Self::V1.0
    }
}

/// Bit flags carried by a protocol wire header.
///
/// Stage 12A.6A reserves the complete flag field. Consequently, only
/// [`WireFlags::NONE`] is currently supported. Individual assignments will be
/// introduced only when their protocol semantics are specified.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct WireFlags(u16);

impl WireFlags {
    /// No optional wire-format behavior is requested.
    pub const NONE: Self = Self(0);

    /// Construct a flag set from its raw representation.
    ///
    /// Unsupported bits are retained so a decoder can report them explicitly.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Return the raw flag representation.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Return whether no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Return whether all selected flags are currently supported.
    pub const fn is_supported(self) -> bool {
        self.is_empty()
    }
}

/// Semantic representation of a fixed PQC-rs wire header.
///
/// The header identifies the wire format, protocol semantics, message type,
/// logical direction, and payload extent. It deliberately does not own or
/// borrow the payload.
///
/// Magic bytes, encoded header length, and reserved bytes are format
/// constants and therefore are not stored as mutable per-frame fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireHeader {
    wire_version: WireVersion,
    protocol_version: ProtocolVersion,
    protocol_id: ProtocolId,
    message_id: MessageId,
    flags: WireFlags,
    message_class: MessageClass,
    direction: ProtocolDirection,
    payload_length: u32,
}

impl WireHeader {
    /// Construct a wire header.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        wire_version: WireVersion,
        protocol_version: ProtocolVersion,
        protocol_id: ProtocolId,
        message_id: MessageId,
        flags: WireFlags,
        message_class: MessageClass,
        direction: ProtocolDirection,
        payload_length: u32,
    ) -> Self {
        Self {
            wire_version,
            protocol_version,
            protocol_id,
            message_id,
            flags,
            message_class,
            direction,
            payload_length,
        }
    }

    /// Construct a header using the current wire version and no flags.
    pub const fn current(
        protocol_version: ProtocolVersion,
        protocol_id: ProtocolId,
        message_id: MessageId,
        message_class: MessageClass,
        direction: ProtocolDirection,
        payload_length: u32,
    ) -> Self {
        Self::new(
            WireVersion::V1,
            protocol_version,
            protocol_id,
            message_id,
            WireFlags::NONE,
            message_class,
            direction,
            payload_length,
        )
    }

    /// Return the binary wire-format version.
    pub const fn wire_version(&self) -> WireVersion {
        self.wire_version
    }

    /// Return the protocol semantic version.
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Return the protocol family or profile identifier.
    pub const fn protocol_id(&self) -> ProtocolId {
        self.protocol_id
    }

    /// Return the protocol-scoped message identifier.
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// Return the wire-header flags.
    pub const fn flags(&self) -> WireFlags {
        self.flags
    }

    /// Return the semantic message class.
    pub const fn message_class(&self) -> MessageClass {
        self.message_class
    }

    /// Return the logical message direction.
    pub const fn direction(&self) -> ProtocolDirection {
        self.direction
    }

    /// Return the number of payload bytes following the header.
    pub const fn payload_length(&self) -> u32 {
        self.payload_length
    }
}

impl ProtocolEncode for WireHeader {
    fn encoded_len(&self) -> usize {
        WIRE_HEADER_LEN
    }

    fn encode_into(&self, output: &mut [u8]) -> ProtocolResult<usize> {
        if output.len() < WIRE_HEADER_LEN {
            return Err(ProtocolError::BufferTooSmall {
                required: WIRE_HEADER_LEN,
                available: output.len(),
            });
        }

        if !self.wire_version.is_supported() {
            return Err(ProtocolError::UnsupportedWireVersion {
                version: self.wire_version.value(),
            });
        }

        if !self.flags.is_supported() {
            return Err(ProtocolError::UnsupportedWireFlags {
                bits: self.flags.bits(),
            });
        }

        output[MAGIC_OFFSET..WIRE_VERSION_OFFSET].copy_from_slice(&WIRE_MAGIC);
        write_u16(output, WIRE_VERSION_OFFSET, self.wire_version.value());
        write_u16(output, HEADER_LENGTH_OFFSET, WIRE_HEADER_LEN as u16);
        write_u16(
            output,
            PROTOCOL_VERSION_MAJOR_OFFSET,
            self.protocol_version.major(),
        );
        write_u16(
            output,
            PROTOCOL_VERSION_MINOR_OFFSET,
            self.protocol_version.minor(),
        );
        write_u16(output, PROTOCOL_ID_OFFSET, self.protocol_id.value());
        write_u16(output, MESSAGE_ID_OFFSET, self.message_id.value());
        write_u16(output, FLAGS_OFFSET, self.flags.bits());
        output[MESSAGE_CLASS_OFFSET] = encode_message_class(self.message_class);
        output[DIRECTION_OFFSET] = encode_direction(self.direction);
        write_u32(output, PAYLOAD_LENGTH_OFFSET, self.payload_length);
        output[RESERVED_OFFSET..WIRE_HEADER_LEN].fill(0);

        Ok(WIRE_HEADER_LEN)
    }
}

impl ProtocolDecode for WireHeader {
    fn decode_prefix(input: &[u8]) -> ProtocolResult<(Self, usize)> {
        if input.len() < WIRE_HEADER_LEN {
            return Err(ProtocolError::UnexpectedEnd);
        }

        if input[MAGIC_OFFSET..WIRE_VERSION_OFFSET] != WIRE_MAGIC {
            return Err(ProtocolError::InvalidWireMagic);
        }

        let wire_version = WireVersion::new(read_u16(input, WIRE_VERSION_OFFSET));

        if !wire_version.is_supported() {
            return Err(ProtocolError::UnsupportedWireVersion {
                version: wire_version.value(),
            });
        }

        let encoded_header_length = read_u16(input, HEADER_LENGTH_OFFSET);

        if encoded_header_length != WIRE_HEADER_LEN as u16 {
            return Err(ProtocolError::InvalidWireHeaderLength {
                expected: WIRE_HEADER_LEN as u16,
                actual: encoded_header_length,
            });
        }

        let flags = WireFlags::from_bits(read_u16(input, FLAGS_OFFSET));

        if !flags.is_supported() {
            return Err(ProtocolError::UnsupportedWireFlags { bits: flags.bits() });
        }

        let message_class = decode_message_class(input[MESSAGE_CLASS_OFFSET])?;
        let direction = decode_direction(input[DIRECTION_OFFSET])?;

        if input[RESERVED_OFFSET..WIRE_HEADER_LEN]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ProtocolError::NonzeroReservedBytes);
        }

        let header = Self::new(
            wire_version,
            ProtocolVersion::new(
                read_u16(input, PROTOCOL_VERSION_MAJOR_OFFSET),
                read_u16(input, PROTOCOL_VERSION_MINOR_OFFSET),
            ),
            ProtocolId::new(read_u16(input, PROTOCOL_ID_OFFSET)),
            MessageId::new(read_u16(input, MESSAGE_ID_OFFSET)),
            flags,
            message_class,
            direction,
            read_u32(input, PAYLOAD_LENGTH_OFFSET),
        );

        Ok((header, WIRE_HEADER_LEN))
    }
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) {
    output[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) {
    output[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

fn read_u32(input: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        input[offset],
        input[offset + 1],
        input[offset + 2],
        input[offset + 3],
    ])
}

const fn encode_message_class(message_class: MessageClass) -> u8 {
    match message_class {
        MessageClass::Control => CONTROL_CLASS,
        MessageClass::Handshake => HANDSHAKE_CLASS,
        MessageClass::Application => APPLICATION_CLASS,
    }
}

const fn decode_message_class(value: u8) -> ProtocolResult<MessageClass> {
    match value {
        CONTROL_CLASS => Ok(MessageClass::Control),
        HANDSHAKE_CLASS => Ok(MessageClass::Handshake),
        APPLICATION_CLASS => Ok(MessageClass::Application),
        _ => Err(ProtocolError::InvalidMessageClass { value }),
    }
}

const fn encode_direction(direction: ProtocolDirection) -> u8 {
    match direction {
        ProtocolDirection::ClientToServer => CLIENT_TO_SERVER_DIRECTION,
        ProtocolDirection::ServerToClient => SERVER_TO_CLIENT_DIRECTION,
    }
}

const fn decode_direction(value: u8) -> ProtocolResult<ProtocolDirection> {
    match value {
        CLIENT_TO_SERVER_DIRECTION => Ok(ProtocolDirection::ClientToServer),
        SERVER_TO_CLIENT_DIRECTION => Ok(ProtocolDirection::ServerToClient),
        _ => Err(ProtocolError::InvalidProtocolDirection { value }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> WireHeader {
        WireHeader::current(
            ProtocolVersion::new(1, 2),
            ProtocolId::new(0x0100),
            MessageId::new(0x0200),
            MessageClass::Application,
            ProtocolDirection::ClientToServer,
            4096,
        )
    }

    #[test]
    fn wire_constants_define_fixed_header_shape() {
        assert_eq!(WIRE_MAGIC, *b"PQCR");
        assert_eq!(WIRE_HEADER_LEN, 32);
        assert_eq!(WIRE_RESERVED_LEN, 8);
    }

    #[test]
    fn initial_wire_version_is_supported() {
        assert_eq!(WireVersion::V1.value(), 1);
        assert!(WireVersion::V1.is_supported());
        assert!(!WireVersion::new(2).is_supported());
    }

    #[test]
    fn only_empty_flags_are_currently_supported() {
        assert!(WireFlags::NONE.is_empty());
        assert!(WireFlags::NONE.is_supported());

        let unknown = WireFlags::from_bits(0x0001);
        assert_eq!(unknown.bits(), 0x0001);
        assert!(!unknown.is_empty());
        assert!(!unknown.is_supported());
    }

    #[test]
    fn current_header_uses_initial_wire_defaults() {
        let header = header();

        assert_eq!(header.wire_version(), WireVersion::V1);
        assert_eq!(header.flags(), WireFlags::NONE);
    }

    #[test]
    fn header_preserves_protocol_and_message_metadata() {
        let header = header();

        assert_eq!(header.protocol_version(), ProtocolVersion::new(1, 2));
        assert_eq!(header.protocol_id(), ProtocolId::new(0x0100));
        assert_eq!(header.message_id(), MessageId::new(0x0200));
        assert_eq!(header.message_class(), MessageClass::Application);
        assert_eq!(header.direction(), ProtocolDirection::ClientToServer);
    }

    #[test]
    fn header_preserves_payload_length_without_owning_payload() {
        assert_eq!(header().payload_length(), 4096);
    }

    fn encoded_header() -> [u8; WIRE_HEADER_LEN] {
        let mut encoded = [0_u8; WIRE_HEADER_LEN];
        let written = header().encode_into(&mut encoded).unwrap();

        assert_eq!(written, WIRE_HEADER_LEN);
        encoded
    }

    #[test]
    fn header_encoding_matches_fixed_big_endian_layout() {
        let encoded = encoded_header();

        assert_eq!(&encoded[0..4], b"PQCR");
        assert_eq!(&encoded[4..6], &[0x00, 0x01]);
        assert_eq!(&encoded[6..8], &[0x00, 0x20]);
        assert_eq!(&encoded[8..10], &[0x00, 0x01]);
        assert_eq!(&encoded[10..12], &[0x00, 0x02]);
        assert_eq!(&encoded[12..14], &[0x01, 0x00]);
        assert_eq!(&encoded[14..16], &[0x02, 0x00]);
        assert_eq!(&encoded[16..18], &[0x00, 0x00]);
        assert_eq!(encoded[18], APPLICATION_CLASS);
        assert_eq!(encoded[19], CLIENT_TO_SERVER_DIRECTION);
        assert_eq!(&encoded[20..24], &[0x00, 0x00, 0x10, 0x00]);
        assert_eq!(&encoded[24..32], &[0_u8; WIRE_RESERVED_LEN]);
    }

    #[test]
    fn encoding_reports_exact_length_and_rejects_short_output() {
        let header = header();
        let mut short = [0_u8; WIRE_HEADER_LEN - 1];

        assert_eq!(header.encoded_len(), WIRE_HEADER_LEN);
        assert_eq!(
            header.encode_into(&mut short),
            Err(ProtocolError::BufferTooSmall {
                required: WIRE_HEADER_LEN,
                available: WIRE_HEADER_LEN - 1,
            })
        );
    }

    #[test]
    fn encoding_rejects_unsupported_version_and_flags() {
        let unsupported_version = WireHeader::new(
            WireVersion::new(2),
            ProtocolVersion::new(1, 2),
            ProtocolId::new(0x0100),
            MessageId::new(0x0200),
            WireFlags::NONE,
            MessageClass::Application,
            ProtocolDirection::ClientToServer,
            4096,
        );

        let unsupported_flags = WireHeader::new(
            WireVersion::V1,
            ProtocolVersion::new(1, 2),
            ProtocolId::new(0x0100),
            MessageId::new(0x0200),
            WireFlags::from_bits(1),
            MessageClass::Application,
            ProtocolDirection::ClientToServer,
            4096,
        );

        let mut output = [0_u8; WIRE_HEADER_LEN];

        assert_eq!(
            unsupported_version.encode_into(&mut output),
            Err(ProtocolError::UnsupportedWireVersion { version: 2 })
        );
        assert_eq!(
            unsupported_flags.encode_into(&mut output),
            Err(ProtocolError::UnsupportedWireFlags { bits: 1 })
        );
    }

    #[test]
    fn prefix_decoding_round_trips_and_reports_consumption() {
        let mut input = [0_u8; WIRE_HEADER_LEN + 3];
        header().encode_into(&mut input[..WIRE_HEADER_LEN]).unwrap();
        input[WIRE_HEADER_LEN..].copy_from_slice(&[7, 8, 9]);

        let (decoded, consumed) = WireHeader::decode_prefix(&input).unwrap();

        assert_eq!(decoded, header());
        assert_eq!(consumed, WIRE_HEADER_LEN);
    }

    #[test]
    fn exact_decoding_rejects_bytes_after_header() {
        let mut input = [0_u8; WIRE_HEADER_LEN + 1];
        header().encode_into(&mut input[..WIRE_HEADER_LEN]).unwrap();

        assert_eq!(
            WireHeader::decode_exact(&input),
            Err(ProtocolError::TrailingData)
        );
    }

    #[test]
    fn decoding_rejects_truncated_header() {
        assert_eq!(
            WireHeader::decode_prefix(&[0_u8; WIRE_HEADER_LEN - 1]),
            Err(ProtocolError::UnexpectedEnd)
        );
    }

    #[test]
    fn decoding_rejects_invalid_magic() {
        let mut encoded = encoded_header();
        encoded[0] ^= 0xff;

        assert_eq!(
            WireHeader::decode_exact(&encoded),
            Err(ProtocolError::InvalidWireMagic)
        );
    }

    #[test]
    fn decoding_rejects_unsupported_wire_version() {
        let mut encoded = encoded_header();
        encoded[WIRE_VERSION_OFFSET..WIRE_VERSION_OFFSET + 2].copy_from_slice(&2_u16.to_be_bytes());

        assert_eq!(
            WireHeader::decode_exact(&encoded),
            Err(ProtocolError::UnsupportedWireVersion { version: 2 })
        );
    }

    #[test]
    fn decoding_rejects_incorrect_header_length() {
        let mut encoded = encoded_header();
        encoded[HEADER_LENGTH_OFFSET..HEADER_LENGTH_OFFSET + 2]
            .copy_from_slice(&31_u16.to_be_bytes());

        assert_eq!(
            WireHeader::decode_exact(&encoded),
            Err(ProtocolError::InvalidWireHeaderLength {
                expected: WIRE_HEADER_LEN as u16,
                actual: 31,
            })
        );
    }

    #[test]
    fn decoding_rejects_unsupported_flags() {
        let mut encoded = encoded_header();
        encoded[FLAGS_OFFSET..FLAGS_OFFSET + 2].copy_from_slice(&1_u16.to_be_bytes());

        assert_eq!(
            WireHeader::decode_exact(&encoded),
            Err(ProtocolError::UnsupportedWireFlags { bits: 1 })
        );
    }

    #[test]
    fn decoding_rejects_unknown_message_class() {
        let mut encoded = encoded_header();
        encoded[MESSAGE_CLASS_OFFSET] = 0xff;

        assert_eq!(
            WireHeader::decode_exact(&encoded),
            Err(ProtocolError::InvalidMessageClass { value: 0xff })
        );
    }

    #[test]
    fn decoding_rejects_unknown_direction() {
        let mut encoded = encoded_header();
        encoded[DIRECTION_OFFSET] = 0xff;

        assert_eq!(
            WireHeader::decode_exact(&encoded),
            Err(ProtocolError::InvalidProtocolDirection { value: 0xff })
        );
    }

    #[test]
    fn decoding_rejects_nonzero_reserved_bytes() {
        let mut encoded = encoded_header();
        encoded[RESERVED_OFFSET] = 1;

        assert_eq!(
            WireHeader::decode_exact(&encoded),
            Err(ProtocolError::NonzeroReservedBytes)
        );
    }
}
