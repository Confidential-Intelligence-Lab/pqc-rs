//! Compile-time protocol session lifecycle interfaces.

use core::marker::PhantomData;

use crate::{ProtocolId, ProtocolRole, ProtocolSession, ProtocolVersion, SessionId, SessionState};

/// Marker for a newly created protocol session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreatedState;

/// Marker for a protocol session performing establishment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EstablishingState;

/// Marker for an established protocol session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EstablishedState;

/// Marker for a protocol session performing orderly shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosingState;

/// Marker for a protocol session that completed orderly shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClosedState;

/// Marker for a protocol session that terminated because of failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailedState;

/// Marker trait implemented by valid compile-time session phases.
///
/// This trait is sealed by convention through the protocol crate's public
/// phase-marker types. It prevents unrelated types from being used as
/// lifecycle parameters for [`TypedProtocolSession`].
pub trait SessionPhase {}

impl SessionPhase for CreatedState {}
impl SessionPhase for EstablishingState {}
impl SessionPhase for EstablishedState {}
impl SessionPhase for ClosingState {}
impl SessionPhase for ClosedState {}
impl SessionPhase for FailedState {}

/// Protocol session whose lifecycle state is represented in its type.
///
/// The wrapper owns the ordinary runtime [`ProtocolSession`] and introduces
/// no additional runtime state. Legal transitions consume the current value
/// and return a session carrying the next lifecycle marker.
///
/// Terminal typed sessions expose no transition methods.
///
/// Unrelated types cannot be used as lifecycle markers:
///
/// ```compile_fail
/// use pqc_protocol::TypedProtocolSession;
///
/// struct NotASessionPhase;
///
/// let _: Option<TypedProtocolSession<NotASessionPhase>> = None;
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TypedProtocolSession<State>
where
    State: SessionPhase,
{
    session: ProtocolSession,
    state: PhantomData<State>,
}

impl TypedProtocolSession<CreatedState> {
    /// Construct a newly created typed protocol session.
    pub const fn new(
        session_id: SessionId,
        protocol_id: ProtocolId,
        protocol_version: ProtocolVersion,
        role: ProtocolRole,
    ) -> Self {
        Self {
            session: ProtocolSession::new(session_id, protocol_id, protocol_version, role),
            state: PhantomData,
        }
    }

    /// Begin protocol establishment.
    pub fn begin_establishment(self) -> TypedProtocolSession<EstablishingState> {
        transition(self, SessionState::Establishing)
    }

    /// Terminate the newly created session because of failure.
    pub fn fail(self) -> TypedProtocolSession<FailedState> {
        transition(self, SessionState::Failed)
    }
}

impl TypedProtocolSession<EstablishingState> {
    /// Complete protocol establishment.
    pub fn establish(self) -> TypedProtocolSession<EstablishedState> {
        transition(self, SessionState::Established)
    }

    /// Complete establishment while retaining validated negotiation evidence.
    ///
    /// The resulting [`crate::EstablishedProtocolContext`] owns both the
    /// established typed session and the supplied
    /// [`crate::NegotiatedCapability`].
    ///
    /// This transition performs no transport I/O, provider resolution, or
    /// cryptographic execution.
    pub fn establish_with_negotiation(
        self,
        negotiated: crate::NegotiatedCapability,
    ) -> crate::EstablishedProtocolContext {
        let established = self.establish();

        crate::EstablishedProtocolContext::from_parts(established, negotiated)
    }

    /// Terminate establishment because of failure.
    pub fn fail(self) -> TypedProtocolSession<FailedState> {
        transition(self, SessionState::Failed)
    }
}

impl TypedProtocolSession<EstablishedState> {
    /// Begin an orderly session shutdown.
    pub fn begin_closing(self) -> TypedProtocolSession<ClosingState> {
        transition(self, SessionState::Closing)
    }

    /// Terminate the established session because of failure.
    pub fn fail(self) -> TypedProtocolSession<FailedState> {
        transition(self, SessionState::Failed)
    }
}

impl TypedProtocolSession<ClosingState> {
    /// Complete an orderly session shutdown.
    pub fn close(self) -> TypedProtocolSession<ClosedState> {
        transition(self, SessionState::Closed)
    }

    /// Terminate shutdown because of failure.
    pub fn fail(self) -> TypedProtocolSession<FailedState> {
        transition(self, SessionState::Failed)
    }
}

impl<State> TypedProtocolSession<State>
where
    State: SessionPhase,
{
    /// Return the opaque session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.session.session_id()
    }

    /// Return the protocol family or profile identifier.
    pub const fn protocol_id(&self) -> ProtocolId {
        self.session.protocol_id()
    }

    /// Return the protocol version.
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.session.protocol_version()
    }

    /// Return the local participant role.
    pub const fn role(&self) -> ProtocolRole {
        self.session.role()
    }

    /// Return the runtime lifecycle state.
    pub const fn runtime_state(&self) -> SessionState {
        self.session.state()
    }

    /// Borrow the underlying runtime session.
    pub const fn as_runtime(&self) -> &ProtocolSession {
        &self.session
    }

    /// Consume the wrapper and return the runtime session.
    pub fn into_runtime(self) -> ProtocolSession {
        self.session
    }
}

fn transition<Current, Next>(
    current: TypedProtocolSession<Current>,
    next: SessionState,
) -> TypedProtocolSession<Next>
where
    Current: SessionPhase,
    Next: SessionPhase,
{
    let mut session = current.session;

    if session.transition_to(next).is_err() {
        unreachable!("typestate transition disagrees with the runtime lifecycle");
    }

    TypedProtocolSession {
        session,
        state: PhantomData,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn created() -> TypedProtocolSession<CreatedState> {
        TypedProtocolSession::new(
            SessionId::from_bytes([0x5a; 16]),
            ProtocolId::new(0x0100),
            ProtocolVersion::new(1, 0),
            ProtocolRole::Client,
        )
    }

    #[test]
    fn typed_session_preserves_metadata() {
        let session = created();

        assert_eq!(session.session_id(), SessionId::from_bytes([0x5a; 16]));
        assert_eq!(session.protocol_id(), ProtocolId::new(0x0100));
        assert_eq!(session.protocol_version(), ProtocolVersion::new(1, 0));
        assert_eq!(session.role(), ProtocolRole::Client);
        assert_eq!(session.runtime_state(), SessionState::Created);
    }

    #[test]
    fn ordinary_typestate_lifecycle_reaches_closed() {
        let establishing = created().begin_establishment();
        assert_eq!(establishing.runtime_state(), SessionState::Establishing);

        let established = establishing.establish();
        assert_eq!(established.runtime_state(), SessionState::Established);

        let closing = established.begin_closing();
        assert_eq!(closing.runtime_state(), SessionState::Closing);

        let closed = closing.close();
        assert_eq!(closed.runtime_state(), SessionState::Closed);
        assert!(closed.as_runtime().is_terminal());
    }

    #[test]
    fn created_session_can_fail() {
        let failed = created().fail();

        assert_eq!(failed.runtime_state(), SessionState::Failed);
        assert!(failed.as_runtime().is_terminal());
    }

    #[test]
    fn establishing_session_can_fail() {
        let failed = created().begin_establishment().fail();

        assert_eq!(failed.runtime_state(), SessionState::Failed);
    }

    #[test]
    fn established_session_can_fail() {
        let failed = created().begin_establishment().establish().fail();

        assert_eq!(failed.runtime_state(), SessionState::Failed);
    }

    #[test]
    fn typed_session_can_return_to_runtime_representation() {
        let runtime = created().begin_establishment().establish().into_runtime();

        assert_eq!(runtime.state(), SessionState::Established);
        assert_eq!(runtime.role(), ProtocolRole::Client);
    }
}
