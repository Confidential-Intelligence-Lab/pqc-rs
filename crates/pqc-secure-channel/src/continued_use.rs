//! Opt-in continued-use authorization for established HPKE channels.
//!
//! This module revalidates the activation authorization before each `seal`
//! and `open` operation. A shared, mutex-protected transition gate serializes
//! recorded state updates with the complete protected HPKE operation.
//!
//! The guard only observes changes explicitly recorded through `advance`.
//! The KEM authorization scope is reused to govern the lifetime of the
//! established channel; no independent per-message AEAD assurance assertion
//! is made. Original unguarded channel APIs remain available outside this
//! opt-in boundary. The implementation does not authenticate external evidence.

use core::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use pqc_protocol::{
    AssessedExecutionContext, EstablishedProtocolContext, ExecutionContextChange,
    ExecutionGateError, ExecutionGateUpdateError, NegotiatedCapability, TransitionAssessments,
    TransitionExecutionGate,
};
use rand_core::{CryptoRng, RngCore};

use crate::{
    activate_receiver_guarded, activate_sender_guarded, GuardedActivationError, SecureChannelError,
    SecureChannelReceiver, SecureChannelSender,
};

/// Error from opt-in continued-use HPKE authorization or execution.
#[derive(Debug)]
pub enum ContinuedUseError {
    /// The gate mutex was poisoned by an earlier panic; fail closed.
    PoisonedGate,
    /// A recorded context revision could not be advanced.
    Update(ExecutionGateUpdateError),
    /// The current snapshot or assessments do not authorize execution.
    Gate(ExecutionGateError),
    /// The guarded activation entry point rejected the operation.
    Activation(GuardedActivationError),
    /// An authorized HPKE operation failed.
    Channel(SecureChannelError),
}

impl fmt::Display for ContinuedUseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PoisonedGate => formatter.write_str("continued-use gate mutex is poisoned"),
            Self::Update(error) => write!(formatter, "gate context update failed: {error:?}"),
            Self::Gate(error) => {
                write!(formatter, "continued-use authorization rejected: {error:?}")
            }
            Self::Activation(error) => write!(formatter, "guarded activation failed: {error}"),
            Self::Channel(error) => write!(formatter, "authorized HPKE operation failed: {error}"),
        }
    }
}

impl std::error::Error for ContinuedUseError {}

/// Cloneable handle to one shared, state-versioned authorization gate.
///
/// All clones refer to the same gate. Updates and protected HPKE operations
/// acquire the same mutex, providing local ordering for recorded changes.
/// The mutex is held throughout the entire HPKE operation, not only the
/// authorization check. This is an in-process guarantee, not remote revocation.
#[derive(Clone)]
pub struct SharedTransitionGate {
    inner: Arc<Mutex<TransitionExecutionGate>>,
}

impl SharedTransitionGate {
    /// Own an existing transition gate behind a shared synchronization boundary.
    pub fn new(gate: TransitionExecutionGate) -> Self {
        Self {
            inner: Arc::new(Mutex::new(gate)),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, TransitionExecutionGate>, ContinuedUseError> {
        self.inner
            .lock()
            .map_err(|_| ContinuedUseError::PoisonedGate)
    }

    /// Capture the current context revision for subsequent activation.
    ///
    /// A snapshot is not proof of authorization. The current assessments are
    /// rechecked whenever a guarded operation executes.
    ///
    /// # Errors
    ///
    /// Returns an error if the gate mutex is poisoned.
    pub fn snapshot(&self) -> Result<AssessedExecutionContext, ContinuedUseError> {
        Ok(self.lock()?.snapshot())
    }

    /// Record a security-relevant change and replace its current assessment.
    ///
    /// The observer supplying assessments is trusted and must report every
    /// relevant external change. A poisoned gate or exhausted revision fails
    /// closed without running a cryptographic operation.
    ///
    /// # Errors
    ///
    /// Returns a mutex-poisoning or revision-exhaustion error.
    pub fn advance(
        &self,
        change: ExecutionContextChange,
        assessments: TransitionAssessments,
    ) -> Result<(), ContinuedUseError> {
        self.lock()?
            .advance(change, assessments)
            .map_err(ContinuedUseError::Update)
    }
}

/// An activated sender whose HPKE context cannot be extracted in plain form.
///
/// `seal` checks the same shared gate that permitted activation. A stale
/// snapshot remains stale after a change even when authorization is restored;
/// callers must explicitly invoke [`Self::refresh_authorization`].
pub struct ContinuedUseSender {
    inner: SecureChannelSender,
    gate: SharedTransitionGate,
    assessed: AssessedExecutionContext,
}

impl ContinuedUseSender {
    /// Return the next HPKE sequence number without modifying the context.
    pub const fn sequence_number(&self) -> u64 {
        self.inner.sequence_number()
    }

    /// Return the negotiated capability and its protocol policy binding.
    pub const fn negotiated(&self) -> NegotiatedCapability {
        self.inner.negotiated()
    }

    /// Encrypt one message only if the recorded authorization is still valid.
    ///
    /// A rejected authorization does not call HPKE `seal` and therefore cannot
    /// consume a sequence number. The gate lock stays held during encryption.
    ///
    /// # Errors
    ///
    /// Returns a gate, authorization, or underlying HPKE error.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, ContinuedUseError> {
        let gate = self.gate.lock()?;
        let result = gate
            .execute(self.assessed, || self.inner.seal(aad, plaintext))
            .map_err(ContinuedUseError::Gate)?;
        result.map_err(ContinuedUseError::Channel)
    }

    /// Resume after a recorded change only if current assessments permit use.
    ///
    /// This operation never reinitializes HPKE keys or resets sequence state.
    /// Changes that require cryptographic rekeying must use a newly activated
    /// channel instead. Revalidation is a local authorization check, not an
    /// external evidence-verification step.
    ///
    /// # Errors
    ///
    /// Returns a gate or authorization error when revalidation fails.
    pub fn refresh_authorization(&mut self) -> Result<(), ContinuedUseError> {
        let gate = self.gate.lock()?;
        let current = gate.snapshot();
        gate.execute(current, || ())
            .map_err(ContinuedUseError::Gate)?;
        self.assessed = current;
        Ok(())
    }
}

/// An activated receiver whose HPKE context cannot be extracted in plain form.
pub struct ContinuedUseReceiver {
    inner: SecureChannelReceiver,
    gate: SharedTransitionGate,
    assessed: AssessedExecutionContext,
}

impl ContinuedUseReceiver {
    /// Return the next HPKE receive sequence number without mutation.
    pub const fn sequence_number(&self) -> u64 {
        self.inner.sequence_number()
    }

    /// Return the negotiated capability and its protocol policy binding.
    pub const fn negotiated(&self) -> NegotiatedCapability {
        self.inner.negotiated()
    }

    /// Decrypt one message only if the recorded authorization is still valid.
    ///
    /// Rejection happens before HPKE `open`, preserving the sequence number
    /// and leaving the ciphertext available for a later authorized attempt.
    ///
    /// # Errors
    ///
    /// Returns a gate, authorization, or underlying HPKE error.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, ContinuedUseError> {
        let gate = self.gate.lock()?;
        let result = gate
            .execute(self.assessed, || self.inner.open(aad, ciphertext))
            .map_err(ContinuedUseError::Gate)?;
        result.map_err(ContinuedUseError::Channel)
    }

    /// Resume after a recorded change only if current assessments permit use.
    ///
    /// This method preserves the existing HPKE context and sequence number;
    /// it is unsuitable for changes that require cryptographic rekeying.
    ///
    /// # Errors
    ///
    /// Returns a gate or authorization error when revalidation fails.
    pub fn refresh_authorization(&mut self) -> Result<(), ContinuedUseError> {
        let gate = self.gate.lock()?;
        let current = gate.snapshot();
        gate.execute(current, || ())
            .map_err(ContinuedUseError::Gate)?;
        self.assessed = current;
        Ok(())
    }
}

/// A sender activation whose channel remains behind a continued-use gate.
pub struct ContinuedUseSenderActivation {
    encapsulated_key: Vec<u8>,
    channel: ContinuedUseSender,
}

impl ContinuedUseSenderActivation {
    /// Borrow the serialized HPKE encapsulated key for the receiver.
    pub fn encapsulated_key(&self) -> &[u8] {
        &self.encapsulated_key
    }

    /// Consume activation and return the encapsulated key and guarded sender.
    pub fn into_parts(self) -> (Vec<u8>, ContinuedUseSender) {
        (self.encapsulated_key, self.channel)
    }
}

/// Activate a sender and retain an unextractable, continued-use-guarded context.
///
/// The supplied snapshot must be current. The same shared gate is used for
/// activation and all future `seal` operations; no caller-provided gate may
/// be substituted for an already established channel.
///
/// # Errors
///
/// Returns an error for a stale or inadmissible activation, gate poisoning,
/// profile binding mismatch, or HPKE failure.
pub fn activate_sender_continuous<R>(
    gate: &SharedTransitionGate,
    assessed: AssessedExecutionContext,
    established: &EstablishedProtocolContext,
    recipient_public_key: &[u8],
    application_context: &[u8],
    rng: &mut R,
) -> Result<ContinuedUseSenderActivation, ContinuedUseError>
where
    R: CryptoRng + RngCore,
{
    let activated = {
        let guard = gate.lock()?;
        activate_sender_guarded(
            &guard,
            assessed,
            established,
            recipient_public_key,
            application_context,
            rng,
        )
        .map_err(ContinuedUseError::Activation)?
    };
    let (encapsulated_key, channel) = activated.into_parts();
    Ok(ContinuedUseSenderActivation {
        encapsulated_key,
        channel: ContinuedUseSender {
            inner: channel,
            gate: gate.clone(),
            assessed,
        },
    })
}

/// Activate a receiver and retain an unextractable, continued-use-guarded context.
///
/// The supplied gate is bound to the resulting channel for all future `open`
/// operations. The receiver's transition must authorize decapsulation.
///
/// # Errors
///
/// Returns an error for a stale or inadmissible activation, gate poisoning,
/// profile binding mismatch, or HPKE failure.
pub fn activate_receiver_continuous(
    gate: &SharedTransitionGate,
    assessed: AssessedExecutionContext,
    established: &EstablishedProtocolContext,
    recipient_private_key: &[u8],
    encapsulated_key: &[u8],
    application_context: &[u8],
) -> Result<ContinuedUseReceiver, ContinuedUseError> {
    let channel = {
        let guard = gate.lock()?;
        activate_receiver_guarded(
            &guard,
            assessed,
            established,
            recipient_private_key,
            encapsulated_key,
            application_context,
        )
        .map_err(ContinuedUseError::Activation)?
    };
    Ok(ContinuedUseReceiver {
        inner: channel,
        gate: gate.clone(),
        assessed,
    })
}
