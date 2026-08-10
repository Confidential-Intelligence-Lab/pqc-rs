//! Transport-independent protocol execution context.

/// Error produced while orchestrating a protocol handler.
///
/// Handler failures remain distinct from protocol-layer validation failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriverError<E> {
    /// The protocol-specific handler rejected frame processing.
    Handler(E),
    /// Protocol-layer validation or lifecycle transition failed.
    Protocol(crate::ProtocolError),
}

/// Result type used by protocol-driver orchestration.
pub type DriverResult<T, E> = core::result::Result<T, DriverError<E>>;

impl<E> core::fmt::Display for DriverError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Handler(error) => {
                write!(formatter, "protocol handler failed: {error}")
            }
            Self::Protocol(error) => {
                write!(formatter, "protocol orchestration failed: {error}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for DriverError<E> where E: std::error::Error + 'static {}

/// Transport-independent execution context for driving protocol progress.
///
/// `ProtocolDriver` owns the transport and runtime session associated with
/// one protocol execution. It does not interpret messages, bypass validated
/// lifecycle transitions, perform cryptographic operations, or allocate frame
/// storage.
///
/// Future protocol handlers and session orchestration may build on this
/// context without coupling concrete protocol behavior to a particular
/// transport implementation.
///
/// The driver may coordinate protocol handlers over validated frames, but
/// handler state and errors remain owned by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolDriver<T> {
    transport: T,
    session: crate::ProtocolSession,
}

impl<T> ProtocolDriver<T> {
    /// Construct a protocol driver around `transport` and `session`.
    pub const fn new(transport: T, session: crate::ProtocolSession) -> Self {
        Self { transport, session }
    }

    /// Borrow the underlying transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutably borrow the underlying transport.
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Borrow the runtime protocol session.
    pub const fn session(&self) -> &crate::ProtocolSession {
        &self.session
    }

    /// Mutably borrow the runtime protocol session.
    ///
    /// Lifecycle changes remain validated by
    /// [`crate::ProtocolSession::transition_to`].
    pub fn session_mut(&mut self) -> &mut crate::ProtocolSession {
        &mut self.session
    }

    /// Consume the driver and return its transport and runtime session.
    pub fn into_parts(self) -> (T, crate::ProtocolSession) {
        (self.transport, self.session)
    }

    /// Construct an outbound frame from a protocol response.
    ///
    /// Protocol family and version are derived from the bound runtime session.
    /// Logical direction is derived from the local participant role. Message
    /// identity, class, and payload are supplied by `response`.
    ///
    /// This method performs no transport I/O and does not mutate the session.
    pub fn frame_response<'a>(
        &self,
        response: crate::OutboundResponse<'a>,
    ) -> crate::ProtocolResult<crate::ProtocolFrame<'a>> {
        let direction = match self.session.role() {
            crate::ProtocolRole::Client => crate::ProtocolDirection::ClientToServer,
            crate::ProtocolRole::Server => crate::ProtocolDirection::ServerToClient,
        };

        crate::ProtocolFrame::current(
            self.session.protocol_version(),
            self.session.protocol_id(),
            response.message_id(),
            response.message_class(),
            direction,
            response.payload(),
        )
    }

    /// Invoke `handler` for one validated inbound frame.
    ///
    /// A requested lifecycle transition is validated and applied through the
    /// owned [`crate::ProtocolSession`]. If validation fails, the previous
    /// session state is preserved.
    ///
    /// This method performs no transport I/O or outbound-frame construction.
    pub fn handle_frame<H>(
        &mut self,
        handler: &mut H,
        frame: &crate::ProtocolFrame<'_>,
    ) -> DriverResult<crate::HandlerOutcome, H::Error>
    where
        H: crate::ProtocolHandler + ?Sized,
    {
        let outcome = handler.handle_frame(frame).map_err(DriverError::Handler)?;

        if let Some(next) = outcome.requested_transition() {
            self.session
                .transition_to(next)
                .map_err(DriverError::Protocol)?;
        }

        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryTransport, TransportReceive, TransportTransmit};

    fn session() -> crate::ProtocolSession {
        crate::ProtocolSession::new(
            crate::SessionId::from_bytes([0x5a; 16]),
            crate::ProtocolId::new(0x0100),
            crate::ProtocolVersion::new(1, 0),
            crate::ProtocolRole::Client,
        )
    }

    #[test]
    fn construction_preserves_transport() {
        let transport = MemoryTransport::<8>::new(3).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        assert_eq!(driver.transport().capacity(), 8);
        assert_eq!(driver.transport().transfer_limit(), 3);
    }

    #[test]
    fn immutable_access_exposes_transport_state() {
        let transport = MemoryTransport::<4>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        assert_eq!(driver.transport().buffered_len(), 0);
        assert_eq!(driver.transport().remaining_capacity(), 4);
        assert!(!driver.transport().is_closed());
    }

    #[test]
    fn mutable_access_supports_transport_progress() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());

        assert_eq!(driver.transport_mut().transmit(&[1, 2, 3]), Ok(2));
        assert_eq!(driver.transport().buffered_len(), 2);

        let mut output = [0_u8; 2];
        assert_eq!(driver.transport_mut().receive(&mut output), Ok(2));
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn mutable_access_supports_transport_closure() {
        let transport = MemoryTransport::<4>::new(1).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());

        driver.transport_mut().close();

        assert!(driver.transport().is_closed());
    }

    #[test]
    fn construction_binds_runtime_session() {
        let transport = MemoryTransport::<8>::new(4).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        assert_eq!(
            driver.session().session_id(),
            crate::SessionId::from_bytes([0x5a; 16])
        );
        assert_eq!(
            driver.session().protocol_id(),
            crate::ProtocolId::new(0x0100)
        );
        assert_eq!(
            driver.session().protocol_version(),
            crate::ProtocolVersion::new(1, 0)
        );
        assert_eq!(driver.session().role(), crate::ProtocolRole::Client);
        assert_eq!(driver.session().state(), crate::SessionState::Created);
    }

    #[test]
    fn mutable_session_access_uses_validated_transitions() {
        let transport = MemoryTransport::<8>::new(4).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());

        driver
            .session_mut()
            .transition_to(crate::SessionState::Establishing)
            .unwrap();

        assert_eq!(driver.session().state(), crate::SessionState::Establishing);

        assert_eq!(
            driver
                .session_mut()
                .transition_to(crate::SessionState::Closed),
            Err(crate::ProtocolError::InvalidStateTransition)
        );
        assert_eq!(driver.session().state(), crate::SessionState::Establishing);
    }

    #[test]
    fn into_parts_returns_transport_and_session_ownership() {
        let mut transport = MemoryTransport::<8>::new(4).unwrap();
        transport.transmit(&[1, 2, 3]).unwrap();

        let driver = ProtocolDriver::new(transport, session());
        let (recovered_transport, recovered_session) = driver.into_parts();

        assert_eq!(recovered_transport.buffered_len(), 3);
        assert_eq!(recovered_transport.remaining_capacity(), 5);
        assert_eq!(
            recovered_session.session_id(),
            crate::SessionId::from_bytes([0x5a; 16])
        );
        assert_eq!(recovered_session.state(), crate::SessionState::Created);
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestHandlerError {
        Rejected,
    }

    #[derive(Debug)]
    struct TestHandler {
        action: crate::HandlerAction,
        handled: usize,
        reject: bool,
        observed_payload_len: usize,
    }

    impl TestHandler {
        const fn new(action: crate::HandlerAction) -> Self {
            Self {
                action,
                handled: 0,
                reject: false,
                observed_payload_len: 0,
            }
        }
    }

    impl crate::ProtocolHandler for TestHandler {
        type Error = TestHandlerError;

        fn handle_frame(
            &mut self,
            frame: &crate::ProtocolFrame<'_>,
        ) -> Result<crate::HandlerOutcome, Self::Error> {
            if self.reject {
                return Err(TestHandlerError::Rejected);
            }

            self.handled += 1;
            self.observed_payload_len = frame.payload().len();
            Ok(crate::HandlerOutcome::new(self.action))
        }
    }

    fn test_frame(payload: &[u8]) -> crate::ProtocolFrame<'_> {
        crate::ProtocolFrame::current(
            crate::ProtocolVersion::new(1, 0),
            crate::ProtocolId::new(0x0100),
            crate::MessageId::new(0x0200),
            crate::MessageClass::Application,
            crate::ProtocolDirection::ClientToServer,
            payload,
        )
        .unwrap()
    }

    #[test]
    fn driver_propagates_handler_action_unchanged() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let frame = test_frame(&[1_u8, 2, 3]);

        for action in [
            crate::HandlerAction::Continue,
            crate::HandlerAction::Respond,
            crate::HandlerAction::Close,
        ] {
            let mut handler = TestHandler::new(action);

            assert_eq!(
                driver.handle_frame(&mut handler, &frame),
                Ok(crate::HandlerOutcome::new(action))
            );
        }
    }

    #[test]
    fn driver_preserves_handler_owned_state() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let mut handler = TestHandler::new(crate::HandlerAction::Continue);

        driver
            .handle_frame(&mut handler, &test_frame(&[1_u8, 2]))
            .unwrap();
        driver
            .handle_frame(&mut handler, &test_frame(&[3_u8, 4, 5]))
            .unwrap();

        assert_eq!(handler.handled, 2);
        assert_eq!(handler.observed_payload_len, 3);
    }

    #[test]
    fn driver_propagates_handler_error_unchanged() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let mut handler = TestHandler::new(crate::HandlerAction::Continue);
        handler.reject = true;

        assert_eq!(
            driver.handle_frame(&mut handler, &test_frame(&[])),
            Err(DriverError::Handler(TestHandlerError::Rejected))
        );
        assert_eq!(handler.handled, 0);
    }

    #[test]
    fn frame_handling_does_not_mutate_transport() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let mut handler = TestHandler::new(crate::HandlerAction::Respond);

        driver
            .handle_frame(&mut handler, &test_frame(&[1_u8]))
            .unwrap();

        assert_eq!(driver.transport().buffered_len(), 0);
        assert_eq!(driver.transport().remaining_capacity(), 8);
        assert!(!driver.transport().is_closed());
    }

    #[test]
    fn driver_supports_dynamically_dispatched_handler() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let mut concrete = TestHandler::new(crate::HandlerAction::Close);
        let handler: &mut dyn crate::ProtocolHandler<Error = TestHandlerError> = &mut concrete;

        assert_eq!(
            driver.handle_frame(handler, &test_frame(&[0xaa_u8])),
            Ok(crate::HandlerOutcome::new(crate::HandlerAction::Close))
        );
    }

    struct TransitionRequestHandler;

    impl crate::ProtocolHandler for TransitionRequestHandler {
        type Error = TestHandlerError;

        fn handle_frame(
            &mut self,
            _frame: &crate::ProtocolFrame<'_>,
        ) -> Result<crate::HandlerOutcome, Self::Error> {
            Ok(crate::HandlerOutcome::with_transition(
                crate::HandlerAction::Continue,
                crate::SessionState::Establishing,
            ))
        }
    }

    #[test]
    fn driver_applies_valid_requested_transition() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let mut handler = TransitionRequestHandler;

        let outcome = driver
            .handle_frame(&mut handler, &test_frame(&[1_u8]))
            .unwrap();

        assert_eq!(
            outcome.requested_transition(),
            Some(crate::SessionState::Establishing)
        );
        assert_eq!(driver.session().state(), crate::SessionState::Establishing);
    }

    struct InvalidTransitionHandler;

    impl crate::ProtocolHandler for InvalidTransitionHandler {
        type Error = TestHandlerError;

        fn handle_frame(
            &mut self,
            _frame: &crate::ProtocolFrame<'_>,
        ) -> Result<crate::HandlerOutcome, Self::Error> {
            Ok(crate::HandlerOutcome::with_transition(
                crate::HandlerAction::Continue,
                crate::SessionState::Established,
            ))
        }
    }

    #[test]
    fn invalid_requested_transition_returns_protocol_error() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let mut handler = InvalidTransitionHandler;

        assert_eq!(
            driver.handle_frame(&mut handler, &test_frame(&[1_u8])),
            Err(DriverError::Protocol(
                crate::ProtocolError::InvalidStateTransition
            ))
        );
    }

    #[test]
    fn rejected_transition_preserves_previous_session_state() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let mut handler = InvalidTransitionHandler;

        let previous = driver.session().state();
        let result = driver.handle_frame(&mut handler, &test_frame(&[1_u8]));

        assert_eq!(
            result,
            Err(DriverError::Protocol(
                crate::ProtocolError::InvalidStateTransition
            ))
        );
        assert_eq!(driver.session().state(), previous);
    }

    #[test]
    fn outcome_without_transition_leaves_session_unchanged() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let mut handler = TestHandler::new(crate::HandlerAction::Respond);

        let outcome = driver
            .handle_frame(&mut handler, &test_frame(&[1_u8]))
            .unwrap();

        assert_eq!(outcome.requested_transition(), None);
        assert_eq!(driver.session().state(), crate::SessionState::Created);
    }

    #[test]
    fn handler_error_leaves_session_unchanged() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let mut handler = TestHandler::new(crate::HandlerAction::Continue);
        handler.reject = true;

        assert_eq!(
            driver.handle_frame(&mut handler, &test_frame(&[])),
            Err(DriverError::Handler(TestHandlerError::Rejected))
        );
        assert_eq!(driver.session().state(), crate::SessionState::Created);
    }

    #[test]
    fn frame_response_derives_client_session_metadata() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());
        let payload = [0xaa_u8, 0xbb, 0xcc];

        let response = crate::OutboundResponse::new(
            crate::MessageId::new(0x0200),
            crate::MessageClass::Application,
            &payload,
        );

        let frame = driver.frame_response(response).unwrap();

        assert_eq!(
            frame.header().protocol_version(),
            crate::ProtocolVersion::new(1, 0)
        );
        assert_eq!(frame.header().protocol_id(), crate::ProtocolId::new(0x0100));
        assert_eq!(frame.header().message_id(), crate::MessageId::new(0x0200));
        assert_eq!(
            frame.header().message_class(),
            crate::MessageClass::Application
        );
        assert_eq!(
            frame.header().direction(),
            crate::ProtocolDirection::ClientToServer
        );
        assert_eq!(frame.payload(), &payload);
    }

    #[test]
    fn frame_response_derives_server_direction() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let server_session = crate::ProtocolSession::new(
            crate::SessionId::from_bytes([0x5a; 16]),
            crate::ProtocolId::new(0x0100),
            crate::ProtocolVersion::new(1, 0),
            crate::ProtocolRole::Server,
        );
        let driver = ProtocolDriver::new(transport, server_session);
        let payload = [0x42_u8];

        let response = crate::OutboundResponse::new(
            crate::MessageId::new(0x0300),
            crate::MessageClass::Handshake,
            &payload,
        );

        let frame = driver.frame_response(response).unwrap();

        assert_eq!(
            frame.header().direction(),
            crate::ProtocolDirection::ServerToClient
        );
        assert_eq!(frame.header().protocol_id(), crate::ProtocolId::new(0x0100));
        assert_eq!(
            frame.header().protocol_version(),
            crate::ProtocolVersion::new(1, 0)
        );
    }

    #[test]
    fn frame_response_borrows_payload_without_copying() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());
        let payload = [1_u8, 2, 3, 4];

        let response = crate::OutboundResponse::new(
            crate::MessageId::new(1),
            crate::MessageClass::Control,
            &payload,
        );

        let frame = driver.frame_response(response).unwrap();

        assert_eq!(frame.payload(), &payload);
        assert_eq!(frame.payload().as_ptr(), payload.as_ptr());
    }

    #[test]
    fn frame_response_derives_payload_length() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());
        let payload = [1_u8, 2, 3, 4, 5];

        let response = crate::OutboundResponse::new(
            crate::MessageId::new(1),
            crate::MessageClass::Application,
            &payload,
        );

        let frame = driver.frame_response(response).unwrap();

        assert_eq!(frame.header().payload_length(), payload.len() as u32);
    }

    #[test]
    fn frame_response_uses_current_wire_defaults() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        let response = crate::OutboundResponse::new(
            crate::MessageId::new(1),
            crate::MessageClass::Control,
            &[],
        );

        let frame = driver.frame_response(response).unwrap();

        assert_eq!(frame.header().wire_version(), crate::WireVersion::V1);
        assert_eq!(frame.header().flags(), crate::WireFlags::NONE);
    }

    #[test]
    fn frame_response_does_not_mutate_transport_or_session() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        let previous_session = *driver.session();

        let response = crate::OutboundResponse::new(
            crate::MessageId::new(1),
            crate::MessageClass::Control,
            &[],
        );

        driver.frame_response(response).unwrap();

        assert_eq!(*driver.session(), previous_session);
        assert_eq!(driver.transport().buffered_len(), 0);
        assert_eq!(driver.transport().remaining_capacity(), 8);
        assert!(!driver.transport().is_closed());
    }
}
