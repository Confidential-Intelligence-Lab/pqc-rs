//! Transport-independent protocol execution context.

/// Transport-independent execution context for driving protocol progress.
///
/// `ProtocolDriver` owns the transport used by a protocol execution. It does
/// not interpret messages, manage protocol state transitions, perform
/// cryptographic operations, or allocate frame storage.
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
}

impl<T> ProtocolDriver<T> {
    /// Construct a protocol driver around `transport`.
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport.
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Mutably borrow the underlying transport.
    pub const fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consume the driver and return the underlying transport.
    pub fn into_transport(self) -> T {
        self.transport
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
    ) -> Result<crate::HandlerAction, H::Error>
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

    #[test]
    fn construction_preserves_transport() {
        let transport = MemoryTransport::<8>::new(3).unwrap();
        let driver = ProtocolDriver::new(transport);

        assert_eq!(driver.transport().capacity(), 8);
        assert_eq!(driver.transport().transfer_limit(), 3);
    }

    #[test]
    fn immutable_access_exposes_transport_state() {
        let transport = MemoryTransport::<4>::new(2).unwrap();
        let driver = ProtocolDriver::new(transport);

        assert_eq!(driver.transport().buffered_len(), 0);
        assert_eq!(driver.transport().remaining_capacity(), 4);
        assert!(!driver.transport().is_closed());
    }

    #[test]
    fn mutable_access_supports_transport_progress() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport);

        assert_eq!(driver.transport_mut().transmit(&[1, 2, 3]), Ok(2));
        assert_eq!(driver.transport().buffered_len(), 2);

        let mut output = [0_u8; 2];
        assert_eq!(driver.transport_mut().receive(&mut output), Ok(2));
        assert_eq!(output, [1, 2]);
    }

    #[test]
    fn mutable_access_supports_transport_closure() {
        let transport = MemoryTransport::<4>::new(1).unwrap();
        let mut driver = ProtocolDriver::new(transport);

        driver.transport_mut().close();

        assert!(driver.transport().is_closed());
    }

    #[test]
    fn into_transport_returns_transport_ownership() {
        let mut transport = MemoryTransport::<8>::new(4).unwrap();
        transport.transmit(&[1, 2, 3]).unwrap();

        let driver = ProtocolDriver::new(transport);
        let recovered = driver.into_transport();

        assert_eq!(recovered.buffered_len(), 3);
        assert_eq!(recovered.remaining_capacity(), 5);
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
        ) -> Result<crate::HandlerAction, Self::Error> {
            if self.reject {
                return Err(TestHandlerError::Rejected);
            }

            self.handled += 1;
            self.observed_payload_len = frame.payload().len();
            Ok(self.action)
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
        let mut driver = ProtocolDriver::new(transport);
        let frame = test_frame(&[1_u8, 2, 3]);

        for action in [
            crate::HandlerAction::Continue,
            crate::HandlerAction::Respond,
            crate::HandlerAction::Close,
        ] {
            let mut handler = TestHandler::new(action);

            assert_eq!(driver.handle_frame(&mut handler, &frame), Ok(action));
        }
    }

    #[test]
    fn driver_preserves_handler_owned_state() {
        let transport = MemoryTransport::<8>::new(2).unwrap();
        let mut driver = ProtocolDriver::new(transport);
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
        let mut driver = ProtocolDriver::new(transport);
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
        let mut driver = ProtocolDriver::new(transport);
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
        let mut driver = ProtocolDriver::new(transport);
        let mut concrete = TestHandler::new(crate::HandlerAction::Close);
        let handler: &mut dyn crate::ProtocolHandler<Error = TestHandlerError> = &mut concrete;

        assert_eq!(
            driver.handle_frame(handler, &test_frame(&[0xaa_u8])),
            Ok(crate::HandlerAction::Close)
        );
    }
}
