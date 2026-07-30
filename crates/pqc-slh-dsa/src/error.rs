//! Publication-facing SLH-DSA error type.

/// Error returned by public SLH-DSA operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlhDsaError {
    /// Public-key encoding has an invalid length or form.
    InvalidPublicKey,
    /// Private-key encoding has an invalid length or form.
    InvalidPrivateKey,
    /// Signature encoding has an invalid length or form.
    InvalidSignature,
    /// Key-generation seed has the wrong length.
    InvalidKeyGenSeed,
    /// Context string exceeds the FIPS 205 limit of 255 bytes.
    ContextTooLong,
    /// An object belongs to a different SLH-DSA parameter set.
    ParameterSetMismatch,
    /// Caller-supplied random-number generation failed.
    RandomnessFailure,
    /// The requested operation is not implemented in the current stage.
    NotImplemented,
    /// An internal cryptographic invariant failed.
    InternalError,
}

impl core::fmt::Display for SlhDsaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPublicKey => "invalid SLH-DSA public key",
            Self::InvalidPrivateKey => "invalid SLH-DSA private key",
            Self::InvalidSignature => "invalid SLH-DSA signature",
            Self::InvalidKeyGenSeed => "invalid SLH-DSA key-generation seed",
            Self::ContextTooLong => "SLH-DSA context exceeds 255 bytes",
            Self::ParameterSetMismatch => "SLH-DSA parameter-set mismatch",
            Self::RandomnessFailure => "SLH-DSA randomness generation failed",
            Self::NotImplemented => "SLH-DSA operation is not implemented",
            Self::InternalError => "internal SLH-DSA operation failed",
        })
    }
}

impl std::error::Error for SlhDsaError {}
