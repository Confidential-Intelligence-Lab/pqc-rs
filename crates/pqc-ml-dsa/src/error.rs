//! ML-DSA error types.

use crate::hash_mldsa::HashMlDsaError;
use crate::keygen::KeyGenError;
use crate::signature::SignatureError;
use crate::signing::SigningError;
use crate::verification::VerificationError;

/// Error returned by publication-facing ML-DSA operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsaError {
    /// Public-key encoding has the wrong length or is not canonical.
    InvalidPublicKey,
    /// Private-key encoding has the wrong length or is not canonical.
    InvalidPrivateKey,
    /// Signature encoding has the wrong length or is not canonical.
    InvalidSignature,
    /// Context string exceeds the FIPS 204 limit of 255 bytes.
    ContextTooLong,
    /// A key or signature belongs to a different ML-DSA parameter set.
    ParameterSetMismatch,
    /// The caller-supplied random-number generator failed.
    RandomnessFailure,
    /// The signing rejection loop exceeded its safety limit.
    RejectionLimitExceeded,
    /// An internal cryptographic invariant failed.
    InternalError,
}

impl core::fmt::Display for MlDsaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPublicKey => "invalid ML-DSA public key",
            Self::InvalidPrivateKey => "invalid ML-DSA private key",
            Self::InvalidSignature => "invalid ML-DSA signature",
            Self::ContextTooLong => "ML-DSA context exceeds 255 bytes",
            Self::ParameterSetMismatch => "ML-DSA parameter-set mismatch",
            Self::RandomnessFailure => "ML-DSA randomness generation failed",
            Self::RejectionLimitExceeded => "ML-DSA rejection limit exceeded",
            Self::InternalError => "internal ML-DSA operation failed",
        })
    }
}

impl From<KeyGenError> for MlDsaError {
    fn from(_: KeyGenError) -> Self {
        Self::InternalError
    }
}

impl From<SigningError> for MlDsaError {
    fn from(error: SigningError) -> Self {
        match error {
            SigningError::InvalidPrivateKeyLength | SigningError::InvalidPrivateKeyEncoding => {
                Self::InvalidPrivateKey
            }
            SigningError::ContextTooLong => Self::ContextTooLong,
            SigningError::NonceOverflow => Self::InternalError,
        }
    }
}

impl From<SignatureError> for MlDsaError {
    fn from(error: SignatureError) -> Self {
        match error {
            SignatureError::RejectionLimitExceeded => Self::RejectionLimitExceeded,
            SignatureError::Preparation
            | SignatureError::Arithmetic
            | SignatureError::Encoding
            | SignatureError::NonceOverflow => Self::InternalError,
        }
    }
}

impl From<VerificationError> for MlDsaError {
    fn from(error: VerificationError) -> Self {
        match error {
            VerificationError::InvalidPublicKeyLength
            | VerificationError::InvalidPublicKeyEncoding => Self::InvalidPublicKey,
            VerificationError::InvalidSignatureLength
            | VerificationError::InvalidSignatureEncoding => Self::InvalidSignature,
            VerificationError::ContextTooLong => Self::ContextTooLong,
            VerificationError::Arithmetic => Self::InternalError,
        }
    }
}

impl From<HashMlDsaError> for MlDsaError {
    fn from(error: HashMlDsaError) -> Self {
        match error {
            HashMlDsaError::ContextTooLong => Self::ContextTooLong,
            HashMlDsaError::UnsupportedHashAlgorithm
            | HashMlDsaError::Signing
            | HashMlDsaError::Verification => Self::InternalError,
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MlDsaError {}
