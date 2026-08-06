//! Transport-independent protocol execution context.

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

    /// Invoke `handler` for one validated inbound frame.
    ///
    /// This method performs no transport I/O and does not alter the
    /// returned semantic action. Handler-owned state and errors remain
    /// independent from the driver and its transport.
    pub fn handle_frame<H>(
        &mut self,
        handler: &mut H,
        frame: &crate::ProtocolFrame<'_>,
    ) -> Result<crate::HandlerOutcome, H::Error>
    where
        H: crate::ProtocolHandler + ?Sized,
    {
        handler.handle_frame(frame)
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
            Err(TestHandlerError::Rejected)
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
    fn driver_propagates_transition_request_without_applying_it() {
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
        assert_eq!(driver.session().state(), crate::SessionState::Created);
    }
}
