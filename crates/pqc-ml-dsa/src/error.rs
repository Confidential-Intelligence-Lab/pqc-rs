//! ML-DSA error types.

/// Error returned by ML-DSA operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaError {
    /// Public-key encoding has the wrong length or form.
    InvalidPublicKey,
    /// Private-key encoding has the wrong length or form.
    InvalidPrivateKey,
    /// Signature encoding has the wrong length or form.
    InvalidSignature,
    /// Context string exceeds the supported limit.
    ContextTooLong,
    /// Randomness input has the wrong length.
    InvalidRandomness,
    /// Internal rejection-sampling limit was exceeded.
    RejectionLimitExceeded,
    /// The requested operation is not implemented yet.
    NotImplemented,
}

impl core::fmt::Display for MlDsaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPublicKey => "invalid ML-DSA public key",
            Self::InvalidPrivateKey => "invalid ML-DSA private key",
            Self::InvalidSignature => "invalid ML-DSA signature",
            Self::ContextTooLong => "ML-DSA context is too long",
            Self::InvalidRandomness => "invalid ML-DSA randomness length",
            Self::RejectionLimitExceeded => "ML-DSA rejection limit exceeded",
            Self::NotImplemented => "ML-DSA operation is not implemented",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MlDsaError {}
