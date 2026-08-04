//! Semantic abstraction for protocol messages.

use crate::{MessageClass, MessageId, ProtocolDirection, ProtocolId, ProtocolVersion};

/// Transport-independent semantic description of a protocol message.
///
/// Implementations identify the protocol, version, message type, semantic
/// class, and logical direction of a message. This trait deliberately does
/// not define payload ownership, serialization, framing, delivery, session
/// state, or cryptographic protection.
pub trait ProtocolMessage {
    /// Return the protocol family or profile identifier.
    fn protocol_id(&self) -> ProtocolId;

    /// Return the protocol version under which the message is interpreted.
    fn protocol_version(&self) -> ProtocolVersion;

    /// Return the message identifier within the selected protocol.
    fn message_id(&self) -> MessageId;

    /// Return the broad semantic class of the message.
    fn message_class(&self) -> MessageClass;

    /// Return the logical direction in which the message is sent.
    fn direction(&self) -> ProtocolDirection;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct TestMessage;

    impl ProtocolMessage for TestMessage {
        fn protocol_id(&self) -> ProtocolId {
            ProtocolId::new(0x0100)
        }

        fn protocol_version(&self) -> ProtocolVersion {
            ProtocolVersion::new(1, 0)
        }

        fn message_id(&self) -> MessageId {
            MessageId::new(0x0001)
        }

        fn message_class(&self) -> MessageClass {
            MessageClass::Handshake
        }

        fn direction(&self) -> ProtocolDirection {
            ProtocolDirection::ClientToServer
        }
    }

    #[test]
    fn trait_exposes_message_semantics() {
        let message = TestMessage;

        assert_eq!(message.protocol_id(), ProtocolId::new(0x0100));
        assert_eq!(message.protocol_version(), ProtocolVersion::new(1, 0));
        assert_eq!(message.message_id(), MessageId::new(0x0001));
        assert_eq!(message.message_class(), MessageClass::Handshake);
        assert_eq!(message.direction(), ProtocolDirection::ClientToServer);
    }
}
