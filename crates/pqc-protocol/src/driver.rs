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
}
