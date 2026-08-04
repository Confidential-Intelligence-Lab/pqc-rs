//! Protocol-layer error types.

/// Result type used by protocol-layer operations.
pub type ProtocolResult<T> = core::result::Result<T, ProtocolError>;

/// Error produced by protocol-layer validation and processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    /// The protocol version is unsupported.
    UnsupportedVersion,
    /// The selected cryptographic policy is unsupported.
    UnsupportedPolicy,
    /// A protocol identifier has an invalid encoding or value.
    InvalidIdentifier,
    /// The output buffer cannot hold the complete encoding.
    BufferTooSmall {
        /// Number of bytes required by the encoding.
        required: usize,
        /// Number of bytes available in the output buffer.
        available: usize,
    },
    /// The input ended before a complete value could be decoded.
    UnexpectedEnd,
    /// Bytes remained after exact decoding completed.
    TrailingData,
    /// The input does not contain a valid protocol encoding.
    InvalidEncoding,
    /// The frame does not begin with the PQC-rs wire magic value.
    InvalidWireMagic,
    /// The encoded wire-header length is not supported.
    InvalidWireHeaderLength {
        /// Header length required by this implementation.
        expected: u16,
        /// Header length found in the encoded input.
        actual: u16,
    },
    /// The encoded binary wire-format version is unsupported.
    UnsupportedWireVersion {
        /// Unsupported wire-format version value.
        version: u16,
    },
    /// The encoded wire-header flags contain unsupported bits.
    UnsupportedWireFlags {
        /// Unsupported raw flag bits.
        bits: u16,
    },
    /// The encoded message-class discriminant is unknown.
    InvalidMessageClass {
        /// Unknown message-class discriminant.
        value: u8,
    },
    /// The encoded protocol-direction discriminant is unknown.
    InvalidProtocolDirection {
        /// Unknown direction discriminant.
        value: u8,
    },
    /// Reserved wire-header bytes are nonzero.
    NonzeroReservedBytes,
    /// The participant role is invalid for the requested operation.
    InvalidRole,
    /// The requested session-state transition is not permitted.
    InvalidStateTransition,
    /// A protocol invariant was violated.
    ProtocolInvariantFailed,
}

impl core::fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::UnsupportedVersion => "unsupported protocol version",
            Self::UnsupportedPolicy => "unsupported cryptographic policy",
            Self::InvalidIdentifier => "invalid protocol identifier",
            Self::BufferTooSmall { .. } => "protocol encoding output buffer is too small",
            Self::UnexpectedEnd => "unexpected end of protocol input",
            Self::TrailingData => "trailing data after protocol value",
            Self::InvalidEncoding => "invalid protocol encoding",
            Self::InvalidWireMagic => "invalid protocol wire magic",
            Self::InvalidWireHeaderLength { .. } => "invalid protocol wire-header length",
            Self::UnsupportedWireVersion { .. } => "unsupported protocol wire-format version",
            Self::UnsupportedWireFlags { .. } => "unsupported protocol wire-header flags",
            Self::InvalidMessageClass { .. } => "invalid protocol message-class encoding",
            Self::InvalidProtocolDirection { .. } => "invalid protocol-direction encoding",
            Self::NonzeroReservedBytes => "nonzero reserved protocol wire-header bytes",
            Self::InvalidRole => "invalid protocol role",
            Self::InvalidStateTransition => "invalid protocol session-state transition",
            Self::ProtocolInvariantFailed => "protocol invariant failed",
        };

        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtocolError {}
