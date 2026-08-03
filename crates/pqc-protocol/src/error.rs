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
            Self::InvalidRole => "invalid protocol role",
            Self::ProtocolInvariantFailed => "protocol invariant failed",
        };

        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtocolError {}
