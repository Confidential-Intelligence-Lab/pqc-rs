//! Opt-in secure-channel activation guarded by versioned transition decisions.
//!
//! This boundary prevents HPKE activation through these functions when a
//! snapshot is stale or the gate's current assessments do not permit use.
//! The caller must supply trustworthy policy/evidence assessments, advance the
//! gate on every relevant change, and avoid the unguarded activation entrypoints.
//! Provider and implementation-revision identities remain caller-attested;
//! the gate does not inspect a physical or externally selected provider.

use core::fmt;

use pqc_protocol::{
    AssessedExecutionContext, EstablishedProtocolContext, EvidenceScope, ExecutionGateError,
    TransitionExecutionGate, HPKE_ML_KEM_1024, HPKE_ML_KEM_768, HPKE_ML_KEM_768_CHACHA20,
    HPKE_ML_KEM_768_X25519,
};
use rand_core::{CryptoRng, RngCore};

use crate::{
    activate_receiver, activate_sender, SecureChannelError, SecureChannelReceiver, SenderActivation,
};

/// Error returned by a guarded HPKE activation attempt.
#[derive(Debug)]
pub enum GuardedActivationError {
    /// The transition does not authorize the corresponding KEM operation.
    OperationMismatch,
    /// The transition destination does not identify the negotiated HPKE profile.
    CapabilityMismatch,
    /// The transition destination has an inconsistent parameter-set identifier.
    ParameterMismatch,
    /// The negotiated capability is not a supported secure-channel HPKE profile.
    UnsupportedCapability,
    /// Execution was rejected by the versioned transition gate.
    Gate(ExecutionGateError),
    /// A permitted activation encountered an underlying HPKE error.
    Channel(SecureChannelError),
}

impl fmt::Display for GuardedActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperationMismatch => {
                formatter.write_str("transition operation does not match HPKE activation")
            }
            Self::CapabilityMismatch => {
                formatter.write_str("transition destination does not match negotiated capability")
            }
            Self::ParameterMismatch => {
                formatter.write_str("transition parameter set does not match negotiated capability")
            }
            Self::UnsupportedCapability => {
                formatter.write_str("unsupported secure-channel capability")
            }
            Self::Gate(error) => {
                write!(formatter, "transition gate rejected activation: {error:?}")
            }
            Self::Channel(error) => write!(formatter, "secure-channel activation failed: {error}"),
        }
    }
}

impl std::error::Error for GuardedActivationError {}

/// Check that a gate's destination denotes the negotiated HPKE suite.
///
/// For this opt-in binding, the `AlgorithmId` is the complete registered
/// capability identifier, and the `ParameterSetId` is the ML-KEM strength
/// parameter (768 or 1024). The provider and revision are supplied externally.
fn validate_activation_binding(
    gate: &TransitionExecutionGate,
    established: &EstablishedProtocolContext,
    expected_operation: EvidenceScope,
) -> Result<(), GuardedActivationError> {
    let transition = gate.snapshot().transition;
    if transition.operation() != expected_operation {
        return Err(GuardedActivationError::OperationMismatch);
    }

    let capability = established.capability();
    let parameters = if capability == HPKE_ML_KEM_768
        || capability == HPKE_ML_KEM_768_CHACHA20
        || capability == HPKE_ML_KEM_768_X25519
    {
        768
    } else if capability == HPKE_ML_KEM_1024 {
        1024
    } else {
        return Err(GuardedActivationError::UnsupportedCapability);
    };

    let destination = transition.destination();
    if destination.algorithm().value() != u32::from(capability.value()) {
        return Err(GuardedActivationError::CapabilityMismatch);
    }
    if destination.parameters().value() != parameters {
        return Err(GuardedActivationError::ParameterMismatch);
    }
    Ok(())
}

/// Activate an HPKE sender only when the current transition is admissible.
///
/// This function checks the destination against the established negotiated
/// profile and applies the gate immediately around `activate_sender`. A stale
/// or non-affirmative decision prevents encapsulation and RNG consumption.
///
/// This is opt-in local enforcement. The caller must maintain the gate's
/// revisions and trusted inputs; unguarded APIs are not affected.
///
/// # Errors
///
/// Returns [`GuardedActivationError`] if the binding, gate decision, or HPKE
/// activation fails.
pub fn activate_sender_guarded<R>(
    gate: &TransitionExecutionGate,
    assessed: AssessedExecutionContext,
    established: &EstablishedProtocolContext,
    recipient_public_key: &[u8],
    application_context: &[u8],
    rng: &mut R,
) -> Result<SenderActivation, GuardedActivationError>
where
    R: CryptoRng + RngCore,
{
    validate_activation_binding(gate, established, EvidenceScope::Encapsulation)?;
    gate.execute(assessed, || {
        activate_sender(established, recipient_public_key, application_context, rng)
    })
    .map_err(GuardedActivationError::Gate)?
    .map_err(GuardedActivationError::Channel)
}

/// Activate an HPKE receiver only when the current transition is admissible.
///
/// This function checks the destination against the established negotiated
/// profile and applies the gate immediately around `activate_receiver`.
///
/// This is opt-in local enforcement. It does not revalidate an already-active
/// HPKE context on every `open` operation.
///
/// # Errors
///
/// Returns [`GuardedActivationError`] if the binding, gate decision, or HPKE
/// activation fails.
pub fn activate_receiver_guarded(
    gate: &TransitionExecutionGate,
    assessed: AssessedExecutionContext,
    established: &EstablishedProtocolContext,
    recipient_private_key: &[u8],
    encapsulated_key: &[u8],
    application_context: &[u8],
) -> Result<SecureChannelReceiver, GuardedActivationError> {
    validate_activation_binding(gate, established, EvidenceScope::Decapsulation)?;
    gate.execute(assessed, || {
        activate_receiver(
            established,
            recipient_private_key,
            encapsulated_key,
            application_context,
        )
    })
    .map_err(GuardedActivationError::Gate)?
    .map_err(GuardedActivationError::Channel)
}
