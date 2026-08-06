//! Protocol-specific frame handling contracts.

use crate::ProtocolFrame;

/// Semantic action requested after processing an inbound protocol frame.
///
/// Actions describe protocol intent only. They do not contain payloads,
/// allocate frame storage, or perform transport operations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HandlerAction {
    /// Continue protocol execution without producing an immediate response.
    Continue,
    /// Produce an outbound response during a later orchestration step.
    Respond,
    /// Begin orderly protocol closure.
    Close,
}

impl HandlerAction {
    /// Return whether the action requests an outbound response.
    pub const fn requires_response(self) -> bool {
        matches!(self, Self::Respond)
    }

    /// Return whether the action requests orderly closure.
    pub const fn requests_close(self) -> bool {
        matches!(self, Self::Close)
    }
}

/// Protocol-specific decision contract for validated inbound frames.
///
/// A handler may inspect the frame and update its own protocol-specific state.
/// It must not perform transport I/O, own frame-transfer state, or assume a
/// particular networking or asynchronous-runtime implementation.
///
/// Outbound payload construction and frame encoding remain separate concerns
/// and will be introduced by later orchestration interfaces.
pub trait ProtocolHandler {
    /// Error produced by protocol-specific frame processing.
    type Error;

    /// Process one validated inbound frame and return the requested next action.
    fn handle_frame(&mut self, frame: &ProtocolFrame<'_>) -> Result<HandlerAction, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MessageClass, MessageId, ProtocolDirection, ProtocolId, ProtocolVersion};

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestError {
        Rejected,
    }

    #[derive(Debug)]
    struct TestHandler {
        action: HandlerAction,
        handled: usize,
        reject: bool,
        observed_payload_length: usize,
    }

    impl TestHandler {
        const fn new(action: HandlerAction) -> Self {
            Self {
                action,
                handled: 0,
                reject: false,
                observed_payload_length: 0,
            }
        }
    }

    impl ProtocolHandler for TestHandler {
        type Error = TestError;

        fn handle_frame(
            &mut self,
            frame: &ProtocolFrame<'_>,
        ) -> Result<HandlerAction, Self::Error> {
            if self.reject {
                return Err(TestError::Rejected);
            }

            self.handled += 1;
            self.observed_payload_length = frame.payload().len();

            Ok(self.action)
        }
    }

    fn frame(payload: &[u8]) -> ProtocolFrame<'_> {
        ProtocolFrame::current(
            ProtocolVersion::new(1, 0),
            ProtocolId::new(0x0100),
            MessageId::new(0x0200),
            MessageClass::Application,
            ProtocolDirection::ClientToServer,
            payload,
        )
        .unwrap()
    }

    #[test]
    fn handler_action_predicates_match_semantics() {
        assert!(!HandlerAction::Continue.requires_response());
        assert!(!HandlerAction::Continue.requests_close());

        assert!(HandlerAction::Respond.requires_response());
        assert!(!HandlerAction::Respond.requests_close());

        assert!(!HandlerAction::Close.requires_response());
        assert!(HandlerAction::Close.requests_close());
    }

    #[test]
    fn handler_receives_borrowed_validated_frame() {
        let payload = [1_u8, 2, 3, 4];
        let frame = frame(&payload);
        let mut handler = TestHandler::new(HandlerAction::Continue);

        assert_eq!(handler.handle_frame(&frame), Ok(HandlerAction::Continue));
        assert_eq!(handler.handled, 1);
        assert_eq!(handler.observed_payload_length, payload.len());
        assert_eq!(frame.payload().as_ptr(), payload.as_ptr());
    }

    #[test]
    fn handler_propagates_semantic_action() {
        let frame = frame(&[1_u8]);

        for action in [
            HandlerAction::Continue,
            HandlerAction::Respond,
            HandlerAction::Close,
        ] {
            let mut handler = TestHandler::new(action);
            assert_eq!(handler.handle_frame(&frame), Ok(action));
        }
    }

    #[test]
    fn handler_preserves_mutable_protocol_state() {
        let first = frame(&[1_u8, 2]);
        let second = frame(&[3_u8, 4, 5]);
        let mut handler = TestHandler::new(HandlerAction::Respond);

        handler.handle_frame(&first).unwrap();
        handler.handle_frame(&second).unwrap();

        assert_eq!(handler.handled, 2);
        assert_eq!(handler.observed_payload_length, 3);
    }

    #[test]
    fn handler_uses_protocol_specific_error_type() {
        let frame = frame(&[]);
        let mut handler = TestHandler::new(HandlerAction::Continue);
        handler.reject = true;

        assert_eq!(handler.handle_frame(&frame), Err(TestError::Rejected));
        assert_eq!(handler.handled, 0);
    }

    #[test]
    fn handler_contract_supports_dynamic_dispatch() {
        let frame = frame(&[0xaa_u8]);
        let mut concrete = TestHandler::new(HandlerAction::Close);
        let handler: &mut dyn ProtocolHandler<Error = TestError> = &mut concrete;

        assert_eq!(handler.handle_frame(&frame), Ok(HandlerAction::Close));
    }
}
