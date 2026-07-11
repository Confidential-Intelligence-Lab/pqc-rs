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
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for HpkeError {}
