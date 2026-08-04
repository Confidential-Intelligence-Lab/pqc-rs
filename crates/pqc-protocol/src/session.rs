//! Transport-independent protocol session metadata.

use crate::{ProtocolId, ProtocolResult, ProtocolRole, ProtocolVersion, SessionId, SessionState};

/// Transport-independent metadata and lifecycle state for one protocol session.
///
/// This type binds a session identifier to a protocol family, protocol
/// version, participant role, and validated lifecycle state. It deliberately
/// contains no cryptographic context, transport handle, message queue, or
/// protocol-specific handshake state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolSession {
    session_id: SessionId,
    protocol_id: ProtocolId,
    protocol_version: ProtocolVersion,
    role: ProtocolRole,
    state: SessionState,
}

impl ProtocolSession {
    /// Construct a newly created protocol session.
    ///
    /// Every new session begins in [`SessionState::Created`].
    pub const fn new(
        session_id: SessionId,
        protocol_id: ProtocolId,
        protocol_version: ProtocolVersion,
        role: ProtocolRole,
    ) -> Self {
        Self {
            session_id,
            protocol_id,
            protocol_version,
            role,
            state: SessionState::Created,
        }
    }

    /// Return the opaque session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Return the protocol family or profile identifier.
    pub const fn protocol_id(&self) -> ProtocolId {
        self.protocol_id
    }

    /// Return the protocol version associated with this session.
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Return the local participant role.
    pub const fn role(&self) -> ProtocolRole {
        self.role
    }

    /// Return the current lifecycle state.
    pub const fn state(&self) -> SessionState {
        self.state
    }

    /// Return whether the session is established.
    pub const fn is_established(&self) -> bool {
        self.state.is_established()
    }

    /// Return whether the session is terminal.
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Apply a validated lifecycle transition.
    ///
    /// On failure, the session remains in its previous state.
    pub const fn transition_to(&mut self, next: SessionState) -> ProtocolResult<()> {
        match self.state.transition_to(next) {
            Ok(validated) => {
                self.state = validated;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProtocolError;

    fn session(role: ProtocolRole) -> ProtocolSession {
        ProtocolSession::new(
            SessionId::from_bytes([0x5a; 16]),
            ProtocolId::new(0x0100),
            ProtocolVersion::new(1, 0),
            role,
        )
    }

    #[test]
    fn new_session_binds_metadata_and_starts_created() {
        let session = session(ProtocolRole::Client);

        assert_eq!(session.session_id(), SessionId::from_bytes([0x5a; 16]));
        assert_eq!(session.protocol_id(), ProtocolId::new(0x0100));
        assert_eq!(session.protocol_version(), ProtocolVersion::new(1, 0));
        assert_eq!(session.role(), ProtocolRole::Client);
        assert_eq!(session.state(), SessionState::Created);
        assert!(!session.is_established());
        assert!(!session.is_terminal());
    }

    #[test]
    fn session_applies_validated_lifecycle_transitions() {
        let mut session = session(ProtocolRole::Server);

        session.transition_to(SessionState::Establishing).unwrap();
        assert_eq!(session.state(), SessionState::Establishing);

        session.transition_to(SessionState::Established).unwrap();
        assert!(session.is_established());

        session.transition_to(SessionState::Closing).unwrap();
        session.transition_to(SessionState::Closed).unwrap();

        assert_eq!(session.state(), SessionState::Closed);
        assert!(session.is_terminal());
    }

    #[test]
    fn rejected_transition_preserves_previous_state() {
        let mut session = session(ProtocolRole::Client);

        assert_eq!(
            session.transition_to(SessionState::Established),
            Err(ProtocolError::InvalidStateTransition)
        );
        assert_eq!(session.state(), SessionState::Created);
    }

    #[test]
    fn session_can_enter_failed_terminal_state() {
        let mut session = session(ProtocolRole::Client);

        session.transition_to(SessionState::Establishing).unwrap();
        session.transition_to(SessionState::Failed).unwrap();

        assert_eq!(session.state(), SessionState::Failed);
        assert!(session.is_terminal());
        assert!(!session.is_established());
    }

    #[test]
    fn terminal_session_rejects_further_transitions() {
        let mut session = session(ProtocolRole::Server);

        session.transition_to(SessionState::Failed).unwrap();

        assert_eq!(
            session.transition_to(SessionState::Created),
            Err(ProtocolError::InvalidStateTransition)
        );
        assert_eq!(session.state(), SessionState::Failed);
    }
}
