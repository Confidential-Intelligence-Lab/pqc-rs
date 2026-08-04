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
    /// The participant role is invalid for the requested operation.
    InvalidRole,
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
            Self::InvalidRole => "invalid protocol role",
            Self::ProtocolInvariantFailed => "protocol invariant failed",
        };

        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtocolError {}
