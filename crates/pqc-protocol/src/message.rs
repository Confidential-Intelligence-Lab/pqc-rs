//! Transport-independent protocol message identity.

/// Identifier for a message type within a protocol family or profile.
///
/// Registry assignments and wire encoding will be specified with the binary
/// wire format. The identifier is intentionally scoped by [`crate::ProtocolId`]
/// rather than being globally unique across all protocols.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessageId(u16);

impl MessageId {
    /// Construct a message identifier.
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Return the numeric message identifier.
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Broad semantic class of a protocol message.
///
/// Message classes describe protocol purpose only. They do not specify
/// transport reliability, ordering, framing, or cryptographic protection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MessageClass {
    /// Message that manages protocol operation or lifecycle.
    Control,
    /// Message exchanged while establishing or updating protocol state.
    Handshake,
    /// Message carrying application-defined protected content.
    Application,
}

impl MessageClass {
    /// Return whether this class carries application content.
    pub const fn is_application(self) -> bool {
        matches!(self, Self::Application)
    }

    /// Return whether this class participates in protocol establishment.
    pub const fn is_handshake(self) -> bool {
        matches!(self, Self::Handshake)
    }

    /// Return whether this class manages protocol operation or lifecycle.
    pub const fn is_control(self) -> bool {
        matches!(self, Self::Control)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_identifier_round_trips() {
        assert_eq!(MessageId::new(0x0304).value(), 0x0304);
    }

    #[test]
    fn message_classes_report_their_semantics() {
        assert!(MessageClass::Application.is_application());
        assert!(!MessageClass::Application.is_handshake());
        assert!(!MessageClass::Application.is_control());

        assert!(MessageClass::Handshake.is_handshake());
        assert!(!MessageClass::Handshake.is_application());
        assert!(!MessageClass::Handshake.is_control());

        assert!(MessageClass::Control.is_control());
        assert!(!MessageClass::Control.is_application());
        assert!(!MessageClass::Control.is_handshake());
    }
}
