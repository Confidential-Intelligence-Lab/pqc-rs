//! Transport-independent protocol metadata.

/// Identifier for a protocol family or protocol profile.
///
/// The numeric registry and wire representation will be specified with the
/// protocol wire format. This type currently provides ownership, comparison,
/// and registry-value semantics only.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolId(u16);

impl ProtocolId {
    /// Construct a protocol identifier.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the numeric protocol identifier.
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Identifier for an optional protocol capability.
///
/// Capability negotiation and registry assignments will be introduced only
/// after their protocol semantics are specified.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CapabilityId(u16);

impl CapabilityId {
    /// Construct a capability identifier.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the numeric capability identifier.
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Logical direction of a protocol operation or message.
///
/// Direction is expressed relative to the client and server roles rather than
/// the underlying transport endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ProtocolDirection {
    /// Operation or message flows from the client to the server.
    ClientToServer,
    /// Operation or message flows from the server to the client.
    ServerToClient,
}

impl ProtocolDirection {
    /// Return the role that originates this direction.
    pub const fn sender(self) -> crate::ProtocolRole {
        match self {
            Self::ClientToServer => crate::ProtocolRole::Client,
            Self::ServerToClient => crate::ProtocolRole::Server,
        }
    }

    /// Return the role that receives this direction.
    pub const fn receiver(self) -> crate::ProtocolRole {
        match self {
            Self::ClientToServer => crate::ProtocolRole::Server,
            Self::ServerToClient => crate::ProtocolRole::Client,
        }
    }

    /// Return the opposite protocol direction.
    pub const fn reverse(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProtocolRole;

    #[test]
    fn protocol_identifier_round_trips() {
        assert_eq!(ProtocolId::new(0x0102).value(), 0x0102);
    }

    #[test]
    fn capability_identifier_round_trips() {
        assert_eq!(CapabilityId::new(0x0203).value(), 0x0203);
    }

    #[test]
    fn direction_reports_participant_roles() {
        assert_eq!(
            ProtocolDirection::ClientToServer.sender(),
            ProtocolRole::Client
        );
        assert_eq!(
            ProtocolDirection::ClientToServer.receiver(),
            ProtocolRole::Server
        );
        assert_eq!(
            ProtocolDirection::ServerToClient.sender(),
            ProtocolRole::Server
        );
        assert_eq!(
            ProtocolDirection::ServerToClient.receiver(),
            ProtocolRole::Client
        );
    }

    #[test]
    fn reversing_direction_is_involutive() {
        let direction = ProtocolDirection::ClientToServer;

        assert_eq!(direction.reverse(), ProtocolDirection::ServerToClient);
        assert_eq!(direction.reverse().reverse(), direction);
    }
}
