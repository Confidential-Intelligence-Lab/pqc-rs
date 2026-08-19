use core::fmt;

use pqc_ml_dsa::{MlDsaError, MlDsaParameterSet};
use pqc_protocol::{CapabilityId, EstablishedProtocolContext, AUTH_ML_DSA_65};

/// Locally implemented authentication profiles.
///
/// A profile is a complete local cryptographic interpretation of negotiated
/// authentication capability evidence. Peers negotiate opaque capability
/// identifiers; they do not directly select ML-DSA parameter sets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationProfile {
    /// Pure ML-DSA-65 challenge-response authentication.
    MlDsa65,
}

impl AuthenticationProfile {
    /// Return the ML-DSA parameter set used by this authentication profile.
    pub const fn parameter_set(self) -> MlDsaParameterSet {
        match self {
            Self::MlDsa65 => MlDsaParameterSet::MlDsa65,
        }
    }
}

/// Error produced while resolving established protocol evidence into an
/// authentication profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationError {
    /// The established protocol capability has no authentication realization
    /// in this crate.
    UnsupportedCapability {
        /// Negotiated capability that could not be resolved.
        capability: CapabilityId,
    },

    /// The application context exceeds the canonical transcript limit.
    ApplicationContextTooLong {
        /// Actual application-context length.
        length: usize,
        /// Maximum accepted application-context length.
        maximum: usize,
    },

    /// The resolved ML-DSA operation failed.
    MlDsa(MlDsaError),
}

impl fmt::Display for AuthenticationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedCapability { .. } => {
                formatter.write_str("negotiated capability has no supported authentication profile")
            }
            Self::ApplicationContextTooLong { length, maximum } => write!(
                formatter,
                "authentication application context length {length} exceeds maximum {maximum}"
            ),
            Self::MlDsa(error) => {
                write!(formatter, "ML-DSA authentication operation failed: {error}")
            }
        }
    }
}

impl std::error::Error for AuthenticationError {}

impl From<MlDsaError> for AuthenticationError {
    fn from(error: MlDsaError) -> Self {
        Self::MlDsa(error)
    }
}

/// Resolve established negotiation evidence into a local authentication
/// profile.
///
/// Resolution deliberately accepts an [`EstablishedProtocolContext`] rather
/// than a bare [`CapabilityId`]. This preserves the authority boundary between
/// peer-controlled protocol input and executable cryptographic configuration:
/// callers must first obtain validated negotiation evidence and establish the
/// protocol context before authentication semantics can be assigned.
///
/// Unsupported capabilities fail closed rather than being translated into a
/// fallback authentication mechanism.
pub fn resolve_authentication_profile(
    context: &EstablishedProtocolContext,
) -> Result<AuthenticationProfile, AuthenticationError> {
    match context.capability() {
        AUTH_ML_DSA_65 => Ok(AuthenticationProfile::MlDsa65),
        capability => Err(AuthenticationError::UnsupportedCapability { capability }),
    }
}
