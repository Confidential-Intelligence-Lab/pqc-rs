//! HPKE error types.

/// HPKE setup and KDF error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HpkeError {
    /// The supplied PRK is not a valid HKDF pseudorandom key.
    InvalidPrk,
    /// The requested expansion length cannot be represented or exceeds HKDF limits.
    OutputTooLong,
    /// PSK and PSK identifier presence are inconsistent.
    InconsistentPskInputs,
    /// A PSK was supplied to Base or Auth mode.
    UnexpectedPsk,
    /// PSK or AuthPSK mode omitted the required PSK inputs.
    MissingPsk,
    /// The selected KDF does not match the suite KDF identifier.
    KdfIdentifierMismatch,

    /// The KEM identifier does not match the selected KEM.
    KemIdentifierMismatch,
    /// The selected KDF identifier is unsupported.
    UnsupportedKdf,
    /// The selected AEAD identifier is unsupported.
    UnsupportedAead,
    /// Caller-supplied randomness generation failed.
    RandomnessFailure,
    /// The HPKE KEM operation failed.
    KemError,
    /// The AEAD key length is invalid.
    InvalidAeadKey,
    /// The AEAD nonce length is invalid.
    InvalidAeadNonce,
    /// AEAD encryption failed.
    SealError,
    /// AEAD authentication or decryption failed.
    OpenError,
    /// The context is export-only.
    ExportOnly,
    /// The HPKE message limit has been reached.
    MessageLimitReached,
}

impl core::fmt::Display for HpkeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::InvalidPrk => "invalid HKDF PRK",
            Self::OutputTooLong => "requested HKDF output is too long",
            Self::InconsistentPskInputs => "inconsistent PSK inputs",
            Self::UnexpectedPsk => "PSK input provided when not needed",
            Self::MissingPsk => "required PSK input is missing",
            Self::KdfIdentifierMismatch => "KDF implementation does not match suite identifier",

            Self::KemIdentifierMismatch => "KEM implementation does not match suite identifier",
            Self::UnsupportedKdf => "unsupported HPKE KDF",
            Self::UnsupportedAead => "unsupported HPKE AEAD",
            Self::RandomnessFailure => "HPKE randomness generation failed",
            Self::KemError => "HPKE KEM operation failed",
            Self::InvalidAeadKey => "invalid AEAD key length",
            Self::InvalidAeadNonce => "invalid AEAD nonce length",
            Self::SealError => "AEAD encryption failed",
            Self::OpenError => "AEAD authentication or decryption failed",
            Self::ExportOnly => "message operation on export-only context",
            Self::MessageLimitReached => "HPKE message limit reached",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for HpkeError {}
