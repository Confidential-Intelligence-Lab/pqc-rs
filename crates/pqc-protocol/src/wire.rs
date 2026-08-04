//! Fixed, versioned protocol wire-format primitives.

use crate::{MessageClass, MessageId, ProtocolDirection, ProtocolId, ProtocolVersion};

/// Magic prefix identifying a PQC-rs protocol frame.
pub const WIRE_MAGIC: [u8; 4] = *b"PQCR";

/// Fixed encoded length of the initial wire header.
pub const WIRE_HEADER_LEN: usize = 32;

/// Number of bytes reserved for future fixed-header extensions.
pub const WIRE_RESERVED_LEN: usize = 8;

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
}
