//! Protocol participant roles.

/// Role assumed by a participant in a two-party protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolRole {
    /// Participant that initiates a protocol session.
    Client,
    /// Participant that accepts an initiated protocol session.
    Server,
}
