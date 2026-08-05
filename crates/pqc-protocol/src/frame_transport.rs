//! Resumable integration between protocol frames and byte transports.

use crate::{
    ProtocolDecode, ProtocolEncode, ProtocolError, ProtocolFrame, ProtocolResult, TransportError,
    TransportReceive, TransportTransmit, WireHeader, WIRE_HEADER_LEN,
};

/// Result type used by framed transport operations.
pub type FrameTransferResult<T> = core::result::Result<T, FrameTransferError>;

/// Error produced while transferring a complete protocol frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameTransferError {
    /// Protocol encoding or validation failed.
    Protocol(ProtocolError),
    /// The underlying byte transport failed.
    Transport(TransportError),
}

impl From<ProtocolError> for FrameTransferError {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

impl From<TransportError> for FrameTransferError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl core::fmt::Display for FrameTransferError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Protocol(error) => {
                write!(formatter, "protocol frame transfer failed: {error}")
            }
            Self::Transport(error) => {
                write!(formatter, "protocol transport failed: {error}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FrameTransferError {}

/// Resumable transmitter for one canonically encoded protocol frame.
///
/// Construction encodes the frame exactly once into caller-provided scratch
/// storage. Repeated calls to [`FrameTransmitter::advance`] preserve progress
/// across partial writes and retryable transport conditions.
#[derive(Debug)]
pub struct FrameTransmitter<'a> {
    encoded: &'a [u8],
    transmitted: usize,
}

impl<'a> FrameTransmitter<'a> {
    /// Encode `frame` into `scratch` and initialize transmission state.
    pub fn new(frame: &ProtocolFrame<'_>, scratch: &'a mut [u8]) -> ProtocolResult<Self> {
        let encoded_len = frame.encode_into(scratch)?;

        Ok(Self {
            encoded: &scratch[..encoded_len],
            transmitted: 0,
        })
    }

    /// Advance transmission by one transport operation.
    ///
    /// Returns `Ok(true)` once the complete frame has been transmitted and
    /// `Ok(false)` after valid partial progress. Retryable transport conditions
    /// are returned as [`FrameTransferError::Transport`].
    pub fn advance<T>(&mut self, transport: &mut T) -> FrameTransferResult<bool>
    where
        T: TransportTransmit,
    {
        if self.is_complete() {
            return Ok(true);
        }

        let remaining = &self.encoded[self.transmitted..];
        let progress = transport.transmit(remaining)?;

        if progress == 0 || progress > remaining.len() {
            return Err(FrameTransferError::Transport(
                TransportError::InvalidOperation,
            ));
        }

        self.transmitted += progress;
        Ok(self.is_complete())
    }

    /// Return the complete encoded frame length.
    pub const fn encoded_len(&self) -> usize {
        self.encoded.len()
    }

    /// Return the number of bytes transmitted so far.
    pub const fn transmitted_len(&self) -> usize {
        self.transmitted
    }

    /// Return the number of bytes still awaiting transmission.
    pub const fn remaining_len(&self) -> usize {
        self.encoded.len() - self.transmitted
    }

    /// Return whether the complete frame has been transmitted.
    pub const fn is_complete(&self) -> bool {
        self.transmitted == self.encoded.len()
    }
}

/// Resumable receiver for one complete protocol frame.
///
/// The receiver first acquires exactly the fixed header. Once the header is
/// validated, it acquires exactly the declared payload length. It never asks
/// the transport for bytes belonging to a subsequent frame.
#[derive(Debug)]
pub struct FrameReceiver<'a> {
    buffer: &'a mut [u8],
    received: usize,
    expected: Option<usize>,
}

impl<'a> FrameReceiver<'a> {
    /// Construct a receiver using caller-provided frame storage.
    ///
    /// The buffer must hold at least one fixed wire header. Payload capacity is
    /// validated after the header has been received and decoded.
    pub fn new(buffer: &'a mut [u8]) -> ProtocolResult<Self> {
        if buffer.len() < WIRE_HEADER_LEN {
            return Err(ProtocolError::BufferTooSmall {
                required: WIRE_HEADER_LEN,
                available: buffer.len(),
            });
        }

        Ok(Self {
            buffer,
            received: 0,
            expected: None,
        })
    }

    /// Advance reception by one transport operation.
    ///
    /// Returns `Ok(true)` once one complete frame is available and `Ok(false)`
    /// after valid partial progress.
    pub fn advance<T>(&mut self, transport: &mut T) -> FrameTransferResult<bool>
    where
        T: TransportReceive,
    {
        if self.is_complete() {
            return Ok(true);
        }

        let target = self.expected.unwrap_or(WIRE_HEADER_LEN);
        let output = &mut self.buffer[self.received..target];
        let progress = transport.receive(output)?;

        if progress == 0 || progress > output.len() {
            return Err(FrameTransferError::Transport(
                TransportError::InvalidOperation,
            ));
        }

        self.received += progress;

        if self.expected.is_none() && self.received == WIRE_HEADER_LEN {
            let header = WireHeader::decode_exact(&self.buffer[..WIRE_HEADER_LEN])?;
            let expected = WIRE_HEADER_LEN + header.payload_length() as usize;

            if expected > self.buffer.len() {
                return Err(FrameTransferError::Protocol(
                    ProtocolError::BufferTooSmall {
                        required: expected,
                        available: self.buffer.len(),
                    },
                ));
            }

            self.expected = Some(expected);
        }

        Ok(self.is_complete())
    }

    /// Return the number of bytes received so far.
    pub const fn received_len(&self) -> usize {
        self.received
    }

    /// Return the complete expected frame length once the header is known.
    pub const fn expected_len(&self) -> Option<usize> {
        self.expected
    }

    /// Return whether one complete frame has been received.
    pub const fn is_complete(&self) -> bool {
        match self.expected {
            Some(expected) => self.received == expected,
            None => false,
        }
    }

    /// Borrow the completed frame.
    ///
    /// Returns `Ok(None)` while reception is incomplete.
    pub fn frame(&self) -> ProtocolResult<Option<ProtocolFrame<'_>>> {
        let Some(expected) = self.expected else {
            return Ok(None);
        };

        if self.received != expected {
            return Ok(None);
        }

        ProtocolFrame::decode_exact(&self.buffer[..expected]).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MemoryTransport, MessageClass, MessageId, ProtocolDirection, ProtocolId, ProtocolVersion,
        TransportResult,
    };

    const PAYLOAD: &[u8] = &[0x10, 0x20, 0x30, 0x40];

    fn frame() -> ProtocolFrame<'static> {
        ProtocolFrame::current(
            ProtocolVersion::new(1, 0),
            ProtocolId::new(0x0100),
            MessageId::new(0x0200),
            MessageClass::Application,
            ProtocolDirection::ClientToServer,
            PAYLOAD,
        )
        .unwrap()
    }

    #[test]
    fn transmitter_rejects_insufficient_scratch_storage() {
        let mut scratch = [0_u8; WIRE_HEADER_LEN];

        assert!(matches!(
            FrameTransmitter::new(&frame(), &mut scratch),
            Err(ProtocolError::BufferTooSmall {
                required,
                available,
            }) if required == WIRE_HEADER_LEN + PAYLOAD.len()
                && available == WIRE_HEADER_LEN
        ));
    }

    #[test]
    fn transmitter_preserves_partial_progress() {
        let mut scratch = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len()];
        let mut transmitter = FrameTransmitter::new(&frame(), &mut scratch).unwrap();
        let mut transport = MemoryTransport::<64>::new(3).unwrap();

        assert_eq!(transmitter.advance(&mut transport), Ok(false));
        assert_eq!(transmitter.transmitted_len(), 3);
        assert_eq!(
            transmitter.remaining_len(),
            WIRE_HEADER_LEN + PAYLOAD.len() - 3
        );

        while !transmitter.advance(&mut transport).unwrap() {}

        assert!(transmitter.is_complete());
        assert_eq!(transmitter.transmitted_len(), transmitter.encoded_len());
    }

    #[test]
    fn completed_transmitter_is_idempotent() {
        let mut scratch = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len()];
        let mut transmitter = FrameTransmitter::new(&frame(), &mut scratch).unwrap();
        let mut transport = MemoryTransport::<64>::new(64).unwrap();

        assert_eq!(transmitter.advance(&mut transport), Ok(true));
        let buffered = transport.buffered_len();

        assert_eq!(transmitter.advance(&mut transport), Ok(true));
        assert_eq!(transport.buffered_len(), buffered);
    }

    struct ZeroProgressTransport;

    impl TransportTransmit for ZeroProgressTransport {
        fn transmit(&mut self, _input: &[u8]) -> TransportResult<usize> {
            Ok(0)
        }
    }

    #[test]
    fn transmitter_rejects_invalid_zero_progress() {
        let mut scratch = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len()];
        let mut transmitter = FrameTransmitter::new(&frame(), &mut scratch).unwrap();

        assert_eq!(
            transmitter.advance(&mut ZeroProgressTransport),
            Err(FrameTransferError::Transport(
                TransportError::InvalidOperation
            ))
        );
    }

    #[test]
    fn receiver_rejects_storage_smaller_than_header() {
        let mut storage = [0_u8; WIRE_HEADER_LEN - 1];

        assert!(matches!(
            FrameReceiver::new(&mut storage),
            Err(ProtocolError::BufferTooSmall {
                required,
                available,
            }) if required == WIRE_HEADER_LEN
                && available == WIRE_HEADER_LEN - 1
        ));
    }

    #[test]
    fn receiver_preserves_partial_progress_and_borrows_frame() {
        let mut encoded = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len()];
        frame().encode_into(&mut encoded).unwrap();

        let mut transport = MemoryTransport::<64>::new(3).unwrap();
        let mut offset = 0;

        while offset != encoded.len() {
            offset += transport.transmit(&encoded[offset..]).unwrap();
        }

        let mut storage = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len()];
        let mut receiver = FrameReceiver::new(&mut storage).unwrap();

        while !receiver.advance(&mut transport).unwrap() {}

        assert_eq!(
            receiver.expected_len(),
            Some(WIRE_HEADER_LEN + PAYLOAD.len())
        );

        let decoded = receiver.frame().unwrap().unwrap();
        assert_eq!(decoded, frame());
    }

    #[test]
    fn receiver_reports_pending_without_losing_state() {
        let mut transport = MemoryTransport::<64>::new(4).unwrap();
        let mut storage = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len()];
        let mut receiver = FrameReceiver::new(&mut storage).unwrap();

        assert_eq!(
            receiver.advance(&mut transport),
            Err(FrameTransferError::Transport(TransportError::Pending))
        );
        assert_eq!(receiver.received_len(), 0);
        assert_eq!(receiver.expected_len(), None);
    }

    #[test]
    fn receiver_rejects_payload_larger_than_storage() {
        let large_payload = [0x55_u8; 8];
        let large_frame = ProtocolFrame::current(
            ProtocolVersion::new(1, 0),
            ProtocolId::new(1),
            MessageId::new(1),
            MessageClass::Application,
            ProtocolDirection::ClientToServer,
            &large_payload,
        )
        .unwrap();

        let mut encoded = [0_u8; WIRE_HEADER_LEN + 8];
        large_frame.encode_into(&mut encoded).unwrap();

        let mut transport = MemoryTransport::<64>::new(WIRE_HEADER_LEN).unwrap();
        assert_eq!(
            transport.transmit(&encoded[..WIRE_HEADER_LEN]),
            Ok(WIRE_HEADER_LEN)
        );

        let mut storage = [0_u8; WIRE_HEADER_LEN + 4];
        let mut receiver = FrameReceiver::new(&mut storage).unwrap();

        assert_eq!(
            receiver.advance(&mut transport),
            Err(FrameTransferError::Protocol(
                ProtocolError::BufferTooSmall {
                    required: WIRE_HEADER_LEN + 8,
                    available: WIRE_HEADER_LEN + 4,
                }
            ))
        );
    }

    #[test]
    fn frame_round_trips_through_transport_state_machines() {
        let mut transport = MemoryTransport::<64>::new(5).unwrap();

        let mut transmit_storage = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len()];
        let mut transmitter = FrameTransmitter::new(&frame(), &mut transmit_storage).unwrap();

        while !transmitter.advance(&mut transport).unwrap() {}

        let mut receive_storage = [0_u8; WIRE_HEADER_LEN + PAYLOAD.len()];
        let mut receiver = FrameReceiver::new(&mut receive_storage).unwrap();

        while !receiver.advance(&mut transport).unwrap() {}

        assert_eq!(receiver.frame().unwrap(), Some(frame()));
    }
}
