//! Transport-independent protocol session lifecycle.

use crate::{ProtocolError, ProtocolResult};

/// Generic lifecycle state of a protocol session.
///
/// This vocabulary describes session progress without prescribing a concrete
/// handshake, wire format, cryptographic construction, or transport.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionState {
    /// The session exists but establishment has not started.
    Created,
    /// The session is performing protocol establishment.
    Establishing,
    /// The session is ready for ordinary protocol operations.
    Established,
    /// The session is performing an orderly shutdown.
    Closing,
    /// The session completed an orderly shutdown.
    Closed,
    /// The session terminated because establishment or operation failed.
    Failed,
}

impl SessionState {
    /// Return whether the session has completed establishment.
    pub const fn is_established(self) -> bool {
        matches!(self, Self::Established)
    }

    /// Return whether no further state transition is permitted.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Failed)
    }

    /// Return whether transitioning from this state to `next` is permitted.
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::Establishing)
                | (Self::Created, Self::Failed)
                | (Self::Establishing, Self::Established)
                | (Self::Establishing, Self::Failed)
                | (Self::Established, Self::Closing)
                | (Self::Established, Self::Failed)
                | (Self::Closing, Self::Closed)
                | (Self::Closing, Self::Failed)
        )
    }

    /// Perform a validated state transition.
    pub const fn transition_to(self, next: Self) -> ProtocolResult<Self> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(ProtocolError::InvalidStateTransition)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_lifecycle_transitions_are_permitted() {
        assert_eq!(
            SessionState::Created
                .transition_to(SessionState::Establishing)
                .unwrap(),
            SessionState::Establishing
        );
        assert_eq!(
            SessionState::Establishing
                .transition_to(SessionState::Established)
                .unwrap(),
            SessionState::Established
        );
        assert_eq!(
            SessionState::Established
                .transition_to(SessionState::Closing)
                .unwrap(),
            SessionState::Closing
        );
        assert_eq!(
            SessionState::Closing
                .transition_to(SessionState::Closed)
                .unwrap(),
            SessionState::Closed
        );
    }

    #[test]
    fn active_states_may_transition_to_failed() {
        for state in [
            SessionState::Created,
            SessionState::Establishing,
            SessionState::Established,
            SessionState::Closing,
        ] {
            assert_eq!(
                state.transition_to(SessionState::Failed).unwrap(),
                SessionState::Failed
            );
        }
    }

    #[test]
    fn skipped_lifecycle_states_are_rejected() {
        assert_eq!(
            SessionState::Created.transition_to(SessionState::Established),
            Err(ProtocolError::InvalidStateTransition)
        );
        assert_eq!(
            SessionState::Established.transition_to(SessionState::Closed),
            Err(ProtocolError::InvalidStateTransition)
        );
    }

    #[test]
    fn terminal_states_reject_all_transitions() {
        for terminal in [SessionState::Closed, SessionState::Failed] {
            for next in [
                SessionState::Created,
                SessionState::Establishing,
                SessionState::Established,
                SessionState::Closing,
                SessionState::Closed,
                SessionState::Failed,
            ] {
                assert_eq!(
                    terminal.transition_to(next),
                    Err(ProtocolError::InvalidStateTransition)
                );
            }
        }
    }

    #[test]
    fn state_predicates_match_lifecycle_meaning() {
        assert!(SessionState::Established.is_established());
        assert!(!SessionState::Establishing.is_established());

        assert!(SessionState::Closed.is_terminal());
        assert!(SessionState::Failed.is_terminal());
        assert!(!SessionState::Closing.is_terminal());
    }
}
