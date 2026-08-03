//! Generic transport-independent protocol message envelope.

use crate::{
    MessageClass, MessageId, ProtocolDirection, ProtocolId, ProtocolMessage,
    ProtocolVersion, SessionId,
};

/// Generic transport-independent protocol message envelope.
///
/// The payload type is intentionally unconstrained. Applications may use
/// borrowed bytes, fixed-size arrays, owned buffers, or typed protocol
/// payloads without changing the message metadata model.
///
/// This type does not define serialization, framing, delivery guarantees,
/// cryptographic protection, or protocol-state transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolEnvelope<P> {
    protocol_id: ProtocolId,
    protocol_version: ProtocolVersion,
    session_id: SessionId,
    message_id: MessageId,
    message_class: MessageClass,
    direction: ProtocolDirection,
    payload: P,
}

impl<P> ProtocolEnvelope<P> {
    /// Construct a protocol envelope.
    pub const fn new(
        protocol_id: ProtocolId,
        protocol_version: ProtocolVersion,
        session_id: SessionId,
        message_id: MessageId,
        message_class: MessageClass,
        direction: ProtocolDirection,
        payload: P,
    ) -> Self {
        Self {
            protocol_id,
            protocol_version,
            session_id,
            message_id,
            message_class,
            direction,
            payload,
        }
    }

    /// Return the session identifier.
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Borrow the payload.
    pub const fn payload(&self) -> &P {
        &self.payload
    }

    /// Mutably borrow the payload.
    pub const fn payload_mut(&mut self) -> &mut P {
        &mut self.payload
    }

    /// Consume the envelope and return its payload.
    pub fn into_payload(self) -> P {
        self.payload
    }

    /// Transform the payload while preserving all message metadata.
    pub fn map_payload<Q, F>(self, transform: F) -> ProtocolEnvelope<Q>
    where
        F: FnOnce(P) -> Q,
    {
        ProtocolEnvelope {
            protocol_id: self.protocol_id,
            protocol_version: self.protocol_version,
            session_id: self.session_id,
            message_id: self.message_id,
            message_class: self.message_class,
            direction: self.direction,
            payload: transform(self.payload),
        }
    }
}

impl<P> ProtocolMessage for ProtocolEnvelope<P> {
    fn protocol_id(&self) -> ProtocolId {
        self.protocol_id
    }

    fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    fn message_id(&self) -> MessageId {
        self.message_id
    }

    fn message_class(&self) -> MessageClass {
        self.message_class
    }

    fn direction(&self) -> ProtocolDirection {
        self.direction
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope<P>(payload: P) -> ProtocolEnvelope<P> {
        ProtocolEnvelope::new(
            ProtocolId::new(0x0100),
            ProtocolVersion::new(1, 0),
            SessionId::from_bytes([0x5a; 16]),
            MessageId::new(0x0001),
            MessageClass::Application,
            ProtocolDirection::ClientToServer,
            payload,
        )
    }

    #[test]
    fn envelope_exposes_protocol_semantics() {
        let message = envelope([1_u8, 2, 3]);

        assert_eq!(message.protocol_id(), ProtocolId::new(0x0100));
        assert_eq!(message.protocol_version(), ProtocolVersion::new(1, 0));
        assert_eq!(message.session_id(), SessionId::from_bytes([0x5a; 16]));
        assert_eq!(message.message_id(), MessageId::new(0x0001));
        assert_eq!(message.message_class(), MessageClass::Application);
        assert_eq!(
            message.direction(),
            ProtocolDirection::ClientToServer
        );
    }

    #[test]
    fn payload_can_be_borrowed_and_mutated() {
        let mut message = envelope([1_u8, 2, 3]);

        assert_eq!(message.payload(), &[1, 2, 3]);
        message.payload_mut()[1] = 9;
        assert_eq!(message.payload(), &[1, 9, 3]);
    }

    #[test]
    fn payload_mapping_preserves_metadata() {
        let original = envelope([1_u8, 2, 3]);
        let mapped = original.map_payload(|payload| payload.len());

        assert_eq!(mapped.protocol_id(), ProtocolId::new(0x0100));
        assert_eq!(mapped.protocol_version(), ProtocolVersion::new(1, 0));
        assert_eq!(mapped.session_id(), SessionId::from_bytes([0x5a; 16]));
        assert_eq!(mapped.message_id(), MessageId::new(0x0001));
        assert_eq!(mapped.message_class(), MessageClass::Application);
        assert_eq!(mapped.direction(), ProtocolDirection::ClientToServer);
        assert_eq!(*mapped.payload(), 3);
    }

    #[test]
    fn payload_can_be_recovered_without_allocation() {
        let payload = envelope([4_u8, 5, 6]).into_payload();
        assert_eq!(payload, [4, 5, 6]);
    }
}
