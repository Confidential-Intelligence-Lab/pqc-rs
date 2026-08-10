//! Outbound protocol response contracts.

use crate::{MessageClass, MessageId};

/// Borrowed description of one outbound protocol response.
///
/// The response contains only protocol-specific message identity and payload.
/// Protocol family, protocol version, logical direction, wire version, flags,
/// and encoded payload length are derived by the framework from authoritative
/// session and framing state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundResponse<'a> {
    message_id: MessageId,
    message_class: MessageClass,
    payload: &'a [u8],
}

impl<'a> OutboundResponse<'a> {
    /// Construct an outbound response borrowing `payload`.
    pub const fn new(
        message_id: MessageId,
        message_class: MessageClass,
        payload: &'a [u8],
    ) -> Self {
        Self {
            message_id,
            message_class,
            payload,
        }
    }

    /// Return the protocol-scoped message identifier.
    pub const fn message_id(&self) -> MessageId {
        self.message_id
    }

    /// Return the semantic message class.
    pub const fn message_class(&self) -> MessageClass {
        self.message_class
    }

    /// Return the borrowed response payload.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Return the response payload length.
    pub const fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Return whether the response payload is empty.
    pub const fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }
}

/// Protocol-specific outbound response construction contract.
///
/// Implementations write response bytes into caller-owned storage and return
/// an [`OutboundResponse`] borrowing the initialized portion of that storage.
///
/// The responder does not construct wire headers, select protocol direction,
/// perform transport I/O, or allocate frame storage.
pub trait ProtocolResponder {
    /// Error produced while constructing a protocol-specific response.
    type Error;

    /// Construct one response using caller-owned `output` storage.
    fn write_response<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<OutboundResponse<'a>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        BufferTooSmall,
    }

    struct TestResponder {
        payload: &'static [u8],
    }

    impl ProtocolResponder for TestResponder {
        type Error = TestError;

        fn write_response<'a>(
            &mut self,
            output: &'a mut [u8],
        ) -> Result<OutboundResponse<'a>, Self::Error> {
            if output.len() < self.payload.len() {
                return Err(TestError::BufferTooSmall);
            }

            output[..self.payload.len()].copy_from_slice(self.payload);

            Ok(OutboundResponse::new(
                MessageId::new(0x0200),
                MessageClass::Application,
                &output[..self.payload.len()],
            ))
        }
    }

    #[test]
    fn response_preserves_message_metadata() {
        let payload = [1_u8, 2, 3];
        let response =
            OutboundResponse::new(MessageId::new(0x0102), MessageClass::Handshake, &payload);

        assert_eq!(response.message_id(), MessageId::new(0x0102));
        assert_eq!(response.message_class(), MessageClass::Handshake);
    }

    #[test]
    fn response_borrows_payload_without_copying() {
        let payload = [1_u8, 2, 3, 4];
        let response =
            OutboundResponse::new(MessageId::new(1), MessageClass::Application, &payload);

        assert_eq!(response.payload(), payload);
        assert_eq!(response.payload().as_ptr(), payload.as_ptr());
        assert_eq!(response.payload_len(), payload.len());
        assert!(!response.is_empty());
    }

    #[test]
    fn empty_response_reports_empty_payload() {
        let response = OutboundResponse::new(MessageId::new(1), MessageClass::Control, &[]);

        assert_eq!(response.payload_len(), 0);
        assert!(response.is_empty());
    }

    #[test]
    fn responder_writes_into_caller_owned_storage() {
        let mut responder = TestResponder {
            payload: &[0xaa, 0xbb, 0xcc],
        };
        let mut storage = [0_u8; 8];

        let response = responder.write_response(&mut storage).unwrap();

        assert_eq!(response.payload(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(response.message_id(), MessageId::new(0x0200));
        assert_eq!(response.message_class(), MessageClass::Application);
    }

    #[test]
    fn responder_rejects_insufficient_storage() {
        let mut responder = TestResponder {
            payload: &[1, 2, 3, 4],
        };
        let mut storage = [0_u8; 3];

        assert_eq!(
            responder.write_response(&mut storage),
            Err(TestError::BufferTooSmall)
        );
    }

    #[test]
    fn responder_contract_supports_dynamic_dispatch() {
        let mut concrete = TestResponder { payload: &[0x42] };
        let responder: &mut dyn ProtocolResponder<Error = TestError> = &mut concrete;
        let mut storage = [0_u8; 4];

        let response = responder.write_response(&mut storage).unwrap();

        assert_eq!(response.payload(), &[0x42]);
    }
}
