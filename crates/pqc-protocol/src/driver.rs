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

/// Error produced while constructing an outbound protocol response.
///
/// Responder failures remain distinct from protocol-layer framing failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseError<E> {
    /// The protocol-specific responder failed to construct its payload.
    Responder(E),
    /// Protocol-layer validation or frame construction failed.
    Protocol(crate::ProtocolError),
}

/// Result type used by outbound response orchestration.
pub type ResponseResult<T, E> = core::result::Result<T, ResponseError<E>>;

impl<E> core::fmt::Display for ResponseError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Responder(error) => {
                write!(formatter, "protocol responder failed: {error}")
            }
            Self::Protocol(error) => {
                write!(formatter, "protocol response framing failed: {error}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for ResponseError<E> where E: std::error::Error + 'static {}

/// Error produced while preparing an outbound response for transmission.
///
/// Preparation combines protocol-specific response construction, canonical
/// session-bound framing, and encoding into caller-owned frame storage. It
/// performs no transport I/O.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransmitPreparationError<E> {
    /// The protocol-specific responder failed to construct its payload.
    Responder(E),
    /// Protocol framing, validation, or frame encoding failed.
    Protocol(crate::ProtocolError),
}

/// Result type used while preparing resumable outbound transmission.
pub type TransmitPreparationResult<T, E> = core::result::Result<T, TransmitPreparationError<E>>;

impl<E> core::fmt::Display for TransmitPreparationError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Responder(error) => {
                write!(
                    formatter,
                    "protocol transmit preparation responder failed: {error}"
                )
            }
            Self::Protocol(error) => {
                write!(formatter, "protocol transmit preparation failed: {error}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for TransmitPreparationError<E> where E: std::error::Error + 'static {}

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

impl<T> ProtocolDriver<T>
where
    T: crate::TransportTransmit,
{
    /// Advance one outbound framed transfer over the owned transport.
    ///
    /// The caller retains ownership of the [`crate::FrameTransmitter`],
    /// including encoded-frame scratch storage and resumable transmission
    /// state.
    ///
    /// Returns `Ok(true)` once the complete frame has been transmitted and
    /// `Ok(false)` after valid partial progress. Framing and transport errors
    /// are preserved through [`crate::FrameTransferError`].
    ///
    /// This operation does not mutate protocol-session state.
    pub fn advance_transmit(
        &mut self,
        transmitter: &mut crate::FrameTransmitter<'_>,
    ) -> crate::FrameTransferResult<bool> {
        transmitter.advance(&mut self.transport)
    }
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

    /// Construct one outbound protocol frame through `responder`.
    ///
    /// The responder writes protocol-specific payload bytes into caller-owned
    /// `output` storage. The returned response is then framed using authoritative
    /// metadata from the bound runtime session.
    ///
    /// This method performs no transport I/O and does not mutate session state.
    pub fn build_response<'a, R>(
        &self,
        responder: &mut R,
        output: &'a mut [u8],
    ) -> ResponseResult<crate::ProtocolFrame<'a>, R::Error>
    where
        R: crate::ProtocolResponder + ?Sized,
    {
        let response = responder
            .write_response(output)
            .map_err(ResponseError::Responder)?;

        self.frame_response(response)
            .map_err(ResponseError::Protocol)
    }

    /// Prepare one protocol response for resumable transmission.
    ///
    /// `responder` writes protocol-specific bytes into caller-owned
    /// `payload_storage`. The resulting response is framed using authoritative
    /// session metadata and encoded into caller-owned `frame_storage`.
    ///
    /// The returned [`crate::FrameTransmitter`] borrows only `frame_storage`;
    /// response payload storage is not retained after preparation.
    ///
    /// This method performs no transport I/O and does not mutate session state.
    pub fn prepare_response_transmit<'frame, R>(
        &self,
        responder: &mut R,
        payload_storage: &mut [u8],
        frame_storage: &'frame mut [u8],
    ) -> TransmitPreparationResult<crate::FrameTransmitter<'frame>, R::Error>
    where
        R: crate::ProtocolResponder + ?Sized,
    {
        let response = responder
            .write_response(payload_storage)
            .map_err(TransmitPreparationError::Responder)?;

        let frame = self
            .frame_response(response)
            .map_err(TransmitPreparationError::Protocol)?;

        crate::FrameTransmitter::new(&frame, frame_storage)
            .map_err(TransmitPreparationError::Protocol)
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TestResponderError {
        BufferTooSmall,
    }

    struct TestResponder {
        payload: &'static [u8],
        message_id: crate::MessageId,
        message_class: crate::MessageClass,
    }

    impl TestResponder {
        const fn new(
            payload: &'static [u8],
            message_id: crate::MessageId,
            message_class: crate::MessageClass,
        ) -> Self {
            Self {
                payload,
                message_id,
                message_class,
            }
        }
    }

    impl crate::ProtocolResponder for TestResponder {
        type Error = TestResponderError;

        fn write_response<'a>(
            &mut self,
            output: &'a mut [u8],
        ) -> Result<crate::OutboundResponse<'a>, Self::Error> {
            if output.len() < self.payload.len() {
                return Err(TestResponderError::BufferTooSmall);
            }

            output[..self.payload.len()].copy_from_slice(self.payload);

            Ok(crate::OutboundResponse::new(
                self.message_id,
                self.message_class,
                &output[..self.payload.len()],
            ))
        }
    }

    #[test]
    fn build_response_constructs_session_bound_frame() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());
        let mut responder = TestResponder::new(
            &[0xaa, 0xbb, 0xcc],
            crate::MessageId::new(0x0400),
            crate::MessageClass::Application,
        );
        let mut storage = [0_u8; 8];

        let frame = driver.build_response(&mut responder, &mut storage).unwrap();

        assert_eq!(frame.header().protocol_id(), crate::ProtocolId::new(0x0100));
        assert_eq!(
            frame.header().protocol_version(),
            crate::ProtocolVersion::new(1, 0)
        );
        assert_eq!(frame.header().message_id(), crate::MessageId::new(0x0400));
        assert_eq!(
            frame.header().message_class(),
            crate::MessageClass::Application
        );
        assert_eq!(
            frame.header().direction(),
            crate::ProtocolDirection::ClientToServer
        );
        assert_eq!(frame.payload(), &[0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn build_response_borrows_caller_owned_storage() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());
        let mut responder = TestResponder::new(
            &[1, 2, 3, 4],
            crate::MessageId::new(1),
            crate::MessageClass::Control,
        );
        let mut storage = [0_u8; 8];

        let storage_ptr = storage.as_ptr();

        let frame = driver.build_response(&mut responder, &mut storage).unwrap();

        assert_eq!(frame.payload().as_ptr(), storage_ptr);
        assert_eq!(frame.payload(), &[1, 2, 3, 4]);
    }

    #[test]
    fn build_response_preserves_responder_error() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());
        let mut responder = TestResponder::new(
            &[1, 2, 3, 4],
            crate::MessageId::new(1),
            crate::MessageClass::Application,
        );
        let mut storage = [0_u8; 3];

        assert_eq!(
            driver.build_response(&mut responder, &mut storage),
            Err(ResponseError::Responder(TestResponderError::BufferTooSmall))
        );
    }

    #[test]
    fn build_response_does_not_mutate_transport_or_session() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());
        let previous_session = *driver.session();

        let mut responder = TestResponder::new(
            &[0x42],
            crate::MessageId::new(1),
            crate::MessageClass::Handshake,
        );
        let mut storage = [0_u8; 4];

        driver.build_response(&mut responder, &mut storage).unwrap();

        assert_eq!(*driver.session(), previous_session);
        assert_eq!(driver.transport().buffered_len(), 0);
        assert_eq!(driver.transport().remaining_capacity(), 8);
        assert!(!driver.transport().is_closed());
    }

    #[test]
    fn build_response_supports_dynamic_responder_dispatch() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        let mut concrete = TestResponder::new(
            &[0x55],
            crate::MessageId::new(7),
            crate::MessageClass::Control,
        );

        let responder: &mut dyn crate::ProtocolResponder<Error = TestResponderError> =
            &mut concrete;

        let mut storage = [0_u8; 4];

        let frame = driver.build_response(responder, &mut storage).unwrap();

        assert_eq!(frame.payload(), &[0x55]);
        assert_eq!(frame.header().message_id(), crate::MessageId::new(7));
    }

    #[test]
    fn build_response_derives_server_outbound_direction() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let server_session = crate::ProtocolSession::new(
            crate::SessionId::from_bytes([0x5a; 16]),
            crate::ProtocolId::new(0x0100),
            crate::ProtocolVersion::new(1, 0),
            crate::ProtocolRole::Server,
        );
        let driver = ProtocolDriver::new(transport, server_session);

        let mut responder = TestResponder::new(
            &[0x99],
            crate::MessageId::new(8),
            crate::MessageClass::Handshake,
        );
        let mut storage = [0_u8; 4];

        let frame = driver.build_response(&mut responder, &mut storage).unwrap();

        assert_eq!(
            frame.header().direction(),
            crate::ProtocolDirection::ServerToClient
        );
    }

    #[test]
    fn advance_transmit_completes_when_transport_accepts_full_frame() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let frame = test_frame(&[1_u8, 2, 3]);

        let mut scratch = [0_u8; crate::WIRE_HEADER_LEN + 3];
        let mut transmitter = crate::FrameTransmitter::new(&frame, &mut scratch).unwrap();

        assert_eq!(driver.advance_transmit(&mut transmitter), Ok(true));
        assert!(transmitter.is_complete());
        assert_eq!(transmitter.transmitted_len(), transmitter.encoded_len());
    }

    #[test]
    fn advance_transmit_preserves_partial_progress() {
        let transport = MemoryTransport::<64>::new(3).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let frame = test_frame(&[1_u8, 2, 3, 4]);

        let mut scratch = [0_u8; crate::WIRE_HEADER_LEN + 4];
        let mut transmitter = crate::FrameTransmitter::new(&frame, &mut scratch).unwrap();

        assert_eq!(driver.advance_transmit(&mut transmitter), Ok(false));
        assert_eq!(transmitter.transmitted_len(), 3);
        assert_eq!(transmitter.remaining_len(), transmitter.encoded_len() - 3);
    }

    #[test]
    fn repeated_advance_transmit_eventually_completes() {
        let transport = MemoryTransport::<64>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let frame = test_frame(&[0xaa_u8, 0xbb, 0xcc]);

        let mut scratch = [0_u8; crate::WIRE_HEADER_LEN + 3];
        let mut transmitter = crate::FrameTransmitter::new(&frame, &mut scratch).unwrap();

        while !driver.advance_transmit(&mut transmitter).unwrap() {}

        assert!(transmitter.is_complete());
        assert_eq!(transmitter.transmitted_len(), transmitter.encoded_len());
    }

    #[test]
    fn advance_transmit_propagates_pending_without_losing_progress() {
        let transport = MemoryTransport::<4>::new(4).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let frame = test_frame(&[1_u8, 2, 3, 4]);

        let mut scratch = [0_u8; crate::WIRE_HEADER_LEN + 4];
        let mut transmitter = crate::FrameTransmitter::new(&frame, &mut scratch).unwrap();

        assert_eq!(driver.advance_transmit(&mut transmitter), Ok(false));
        let before = transmitter.transmitted_len();

        assert_eq!(
            driver.advance_transmit(&mut transmitter),
            Err(crate::FrameTransferError::Transport(
                crate::TransportError::Pending
            ))
        );
        assert_eq!(transmitter.transmitted_len(), before);
    }

    #[test]
    fn advance_transmit_propagates_closed_transport() {
        let mut transport = MemoryTransport::<64>::new(64).unwrap();
        transport.close();

        let mut driver = ProtocolDriver::new(transport, session());
        let frame = test_frame(&[0x42_u8]);

        let mut scratch = [0_u8; crate::WIRE_HEADER_LEN + 1];
        let mut transmitter = crate::FrameTransmitter::new(&frame, &mut scratch).unwrap();

        assert_eq!(
            driver.advance_transmit(&mut transmitter),
            Err(crate::FrameTransferError::Transport(
                crate::TransportError::Closed
            ))
        );
        assert_eq!(transmitter.transmitted_len(), 0);
    }

    #[test]
    fn advance_transmit_does_not_mutate_session() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let previous = *driver.session();

        let frame = test_frame(&[0x42_u8]);
        let mut scratch = [0_u8; crate::WIRE_HEADER_LEN + 1];
        let mut transmitter = crate::FrameTransmitter::new(&frame, &mut scratch).unwrap();

        driver.advance_transmit(&mut transmitter).unwrap();

        assert_eq!(*driver.session(), previous);
    }

    #[test]
    fn advance_transmit_emits_exact_encoded_frame_bytes() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());
        let frame = test_frame(&[0xde_u8, 0xad, 0xbe, 0xef]);

        let mut expected = [0_u8; crate::WIRE_HEADER_LEN + 4];
        let expected_len = crate::ProtocolEncode::encode_into(&frame, &mut expected).unwrap();

        let mut scratch = [0_u8; crate::WIRE_HEADER_LEN + 4];
        let mut transmitter = crate::FrameTransmitter::new(&frame, &mut scratch).unwrap();

        assert_eq!(driver.advance_transmit(&mut transmitter), Ok(true));

        let mut received = [0_u8; crate::WIRE_HEADER_LEN + 4];
        let mut received_len = 0;

        while received_len < expected_len {
            let progress = driver
                .transport_mut()
                .receive(&mut received[received_len..expected_len])
                .unwrap();

            received_len += progress;
        }

        assert_eq!(received_len, expected_len);
        assert_eq!(&received[..received_len], &expected[..expected_len]);
    }

    #[test]
    fn prepare_response_transmit_returns_initialized_transmitter() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        let mut responder = TestResponder::new(
            &[0xaa, 0xbb, 0xcc],
            crate::MessageId::new(0x0400),
            crate::MessageClass::Application,
        );

        let mut payload_storage = [0_u8; 8];
        let mut frame_storage = [0_u8; crate::WIRE_HEADER_LEN + 8];

        let transmitter = driver
            .prepare_response_transmit(&mut responder, &mut payload_storage, &mut frame_storage)
            .unwrap();

        assert_eq!(transmitter.encoded_len(), crate::WIRE_HEADER_LEN + 3);
        assert_eq!(transmitter.transmitted_len(), 0);
        assert_eq!(transmitter.remaining_len(), transmitter.encoded_len());
        assert!(!transmitter.is_complete());
    }

    #[test]
    fn prepare_response_transmit_uses_canonical_frame_encoding() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        let mut responder = TestResponder::new(
            &[1, 2, 3, 4],
            crate::MessageId::new(0x1234),
            crate::MessageClass::Handshake,
        );

        let mut payload_storage = [0_u8; 8];
        let mut frame_storage = [0_u8; crate::WIRE_HEADER_LEN + 8];

        let transmitter = driver
            .prepare_response_transmit(&mut responder, &mut payload_storage, &mut frame_storage)
            .unwrap();

        assert_eq!(transmitter.encoded_len(), crate::WIRE_HEADER_LEN + 4);
    }

    #[test]
    fn prepare_response_transmit_preserves_responder_error() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        let mut responder = TestResponder::new(
            &[1, 2, 3, 4],
            crate::MessageId::new(1),
            crate::MessageClass::Application,
        );

        let mut payload_storage = [0_u8; 3];
        let mut frame_storage = [0_u8; crate::WIRE_HEADER_LEN + 8];

        assert!(matches!(
            driver.prepare_response_transmit(
                &mut responder,
                &mut payload_storage,
                &mut frame_storage,
            ),
            Err(TransmitPreparationError::Responder(
                TestResponderError::BufferTooSmall
            ))
        ));
    }

    #[test]
    fn prepare_response_transmit_rejects_short_frame_storage() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        let mut responder = TestResponder::new(
            &[1, 2, 3, 4],
            crate::MessageId::new(1),
            crate::MessageClass::Application,
        );

        let mut payload_storage = [0_u8; 8];
        let mut frame_storage = [0_u8; crate::WIRE_HEADER_LEN];

        assert!(matches!(
            driver.prepare_response_transmit(
                &mut responder,
                &mut payload_storage,
                &mut frame_storage,
            ),
            Err(TransmitPreparationError::Protocol(
                crate::ProtocolError::BufferTooSmall {
                    required,
                    available,
                }
            )) if required == crate::WIRE_HEADER_LEN + 4
                && available == crate::WIRE_HEADER_LEN
        ));
    }

    #[test]
    fn prepare_response_transmit_performs_no_transport_io() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        let mut responder = TestResponder::new(
            &[0x42],
            crate::MessageId::new(1),
            crate::MessageClass::Control,
        );

        let mut payload_storage = [0_u8; 4];
        let mut frame_storage = [0_u8; crate::WIRE_HEADER_LEN + 4];

        let _transmitter = driver
            .prepare_response_transmit(&mut responder, &mut payload_storage, &mut frame_storage)
            .unwrap();

        assert_eq!(driver.transport().buffered_len(), 0);
        assert_eq!(driver.transport().remaining_capacity(), 64);
    }

    #[test]
    fn prepare_response_transmit_does_not_mutate_session() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let driver = ProtocolDriver::new(transport, session());
        let previous = *driver.session();

        let mut responder = TestResponder::new(
            &[0x42],
            crate::MessageId::new(1),
            crate::MessageClass::Control,
        );

        let mut payload_storage = [0_u8; 4];
        let mut frame_storage = [0_u8; crate::WIRE_HEADER_LEN + 4];

        let _transmitter = driver
            .prepare_response_transmit(&mut responder, &mut payload_storage, &mut frame_storage)
            .unwrap();

        assert_eq!(*driver.session(), previous);
    }

    #[test]
    fn prepared_response_can_be_advanced_through_driver() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());

        let mut responder = TestResponder::new(
            &[0xde, 0xad, 0xbe, 0xef],
            crate::MessageId::new(0x0200),
            crate::MessageClass::Application,
        );

        let mut payload_storage = [0_u8; 8];
        let mut frame_storage = [0_u8; crate::WIRE_HEADER_LEN + 8];

        let mut transmitter = driver
            .prepare_response_transmit(&mut responder, &mut payload_storage, &mut frame_storage)
            .unwrap();

        assert_eq!(driver.advance_transmit(&mut transmitter), Ok(true));
        assert!(transmitter.is_complete());
        assert_eq!(
            driver.transport().buffered_len(),
            crate::WIRE_HEADER_LEN + 4
        );
    }

    #[test]
    fn prepared_transmitter_does_not_borrow_payload_storage() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let mut driver = ProtocolDriver::new(transport, session());

        let mut responder = TestResponder::new(
            &[0x10, 0x20, 0x30],
            crate::MessageId::new(0x0200),
            crate::MessageClass::Application,
        );

        let mut payload_storage = [0_u8; 8];
        let mut frame_storage = [0_u8; crate::WIRE_HEADER_LEN + 8];

        let mut transmitter = driver
            .prepare_response_transmit(&mut responder, &mut payload_storage, &mut frame_storage)
            .unwrap();

        // This mutation is intentionally performed while `transmitter`
        // remains alive. Successful compilation proves the transmitter does
        // not retain a borrow of response payload storage.
        payload_storage.fill(0xff);

        while !driver.advance_transmit(&mut transmitter).unwrap() {}

        let mut received = [0_u8; crate::WIRE_HEADER_LEN + 3];
        let mut offset = 0;

        while offset < received.len() {
            let progress = driver
                .transport_mut()
                .receive(&mut received[offset..])
                .unwrap();
            offset += progress;
        }

        assert_eq!(&received[crate::WIRE_HEADER_LEN..], &[0x10, 0x20, 0x30]);
    }

    #[test]
    fn prepare_response_transmit_supports_dynamic_responder_dispatch() {
        let transport = MemoryTransport::<64>::new(64).unwrap();
        let driver = ProtocolDriver::new(transport, session());

        let mut concrete = TestResponder::new(
            &[0x77],
            crate::MessageId::new(7),
            crate::MessageClass::Control,
        );

        let responder: &mut dyn crate::ProtocolResponder<Error = TestResponderError> =
            &mut concrete;

        let mut payload_storage = [0_u8; 4];
        let mut frame_storage = [0_u8; crate::WIRE_HEADER_LEN + 4];

        let transmitter = driver
            .prepare_response_transmit(responder, &mut payload_storage, &mut frame_storage)
            .unwrap();

        assert_eq!(transmitter.encoded_len(), crate::WIRE_HEADER_LEN + 1);
    }
}
