//! Fixed-capacity in-memory reference transport.

use crate::{TransportError, TransportReceive, TransportResult, TransportTransmit};

/// Allocation-free in-memory byte transport with deterministic partial I/O.
///
/// Bytes transmitted into this transport become available to its receive side.
/// The const-generic capacity fixes the maximum number of buffered bytes, while
/// the transfer limit bounds progress made by each transmit or receive call.
///
/// The implementation uses a linear queue with compaction. This favors a small,
/// auditable state model over ring-buffer complexity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryTransport<const N: usize> {
    buffer: [u8; N],
    read_offset: usize,
    write_offset: usize,
    transfer_limit: usize,
    closed: bool,
}

impl<const N: usize> MemoryTransport<N> {
    /// Construct an empty transport with a per-operation transfer limit.
    ///
    /// A zero transfer limit is rejected because nonempty operations would
    /// otherwise be unable to satisfy the transport progress contract.
    pub fn new(transfer_limit: usize) -> TransportResult<Self> {
        if transfer_limit == 0 {
            return Err(TransportError::InvalidOperation);
        }

        Ok(Self {
            buffer: [0_u8; N],
            read_offset: 0,
            write_offset: 0,
            transfer_limit,
            closed: false,
        })
    }

    /// Return the fixed byte capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Return the number of bytes currently available to receive.
    pub const fn buffered_len(&self) -> usize {
        self.write_offset - self.read_offset
    }

    /// Return the number of additional bytes that can be buffered.
    pub const fn remaining_capacity(&self) -> usize {
        N - self.buffered_len()
    }

    /// Return the maximum progress permitted in one operation.
    pub const fn transfer_limit(&self) -> usize {
        self.transfer_limit
    }

    /// Return whether the transport has been closed.
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Close the transport.
    ///
    /// Further transmission is rejected immediately. Already buffered bytes
    /// remain receivable; once drained, receives report
    /// [`TransportError::Closed`].
    pub fn close(&mut self) {
        self.closed = true;
    }

    fn compact(&mut self) {
        if self.read_offset == 0 {
            return;
        }

        let buffered = self.buffered_len();

        if buffered != 0 {
            self.buffer
                .copy_within(self.read_offset..self.write_offset, 0);
        }

        self.read_offset = 0;
        self.write_offset = buffered;
    }
}

impl<const N: usize> TransportTransmit for MemoryTransport<N> {
    fn transmit(&mut self, input: &[u8]) -> TransportResult<usize> {
        if input.is_empty() {
            return Ok(0);
        }

        if self.closed {
            return Err(TransportError::Closed);
        }

        if self.remaining_capacity() == 0 {
            return Err(TransportError::Pending);
        }

        if self.write_offset == N && self.read_offset != 0 {
            self.compact();
        }

        let writable = N - self.write_offset;
        let progress = core::cmp::min(core::cmp::min(input.len(), writable), self.transfer_limit);

        self.buffer[self.write_offset..self.write_offset + progress]
            .copy_from_slice(&input[..progress]);
        self.write_offset += progress;

        Ok(progress)
    }
}

impl<const N: usize> TransportReceive for MemoryTransport<N> {
    fn receive(&mut self, output: &mut [u8]) -> TransportResult<usize> {
        if output.is_empty() {
            return Ok(0);
        }

        let available = self.buffered_len();

        if available == 0 {
            return if self.closed {
                Err(TransportError::Closed)
            } else {
                Err(TransportError::Pending)
            };
        }

        let progress = core::cmp::min(core::cmp::min(output.len(), available), self.transfer_limit);

        output[..progress]
            .copy_from_slice(&self.buffer[self.read_offset..self.read_offset + progress]);
        self.read_offset += progress;

        if self.read_offset == self.write_offset {
            self.read_offset = 0;
            self.write_offset = 0;
        }

        Ok(progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructor_rejects_zero_transfer_limit() {
        assert_eq!(
            MemoryTransport::<8>::new(0),
            Err(TransportError::InvalidOperation)
        );
    }

    #[test]
    fn transport_reports_capacity_and_initial_state() {
        let transport = MemoryTransport::<8>::new(3).unwrap();

        assert_eq!(transport.capacity(), 8);
        assert_eq!(transport.buffered_len(), 0);
        assert_eq!(transport.remaining_capacity(), 8);
        assert_eq!(transport.transfer_limit(), 3);
        assert!(!transport.is_closed());
    }

    #[test]
    fn transmit_and_receive_obey_transfer_limit() {
        let mut transport = MemoryTransport::<8>::new(2).unwrap();
        let mut output = [0_u8; 4];

        assert_eq!(transport.transmit(&[1, 2, 3, 4]), Ok(2));
        assert_eq!(transport.buffered_len(), 2);
        assert_eq!(transport.receive(&mut output), Ok(2));
        assert_eq!(&output[..2], &[1, 2]);
    }

    #[test]
    fn empty_operations_report_zero_progress() {
        let mut transport = MemoryTransport::<4>::new(2).unwrap();
        let mut output = [];

        assert_eq!(transport.transmit(&[]), Ok(0));
        assert_eq!(transport.receive(&mut output), Ok(0));
    }

    #[test]
    fn empty_and_full_open_transport_report_pending() {
        let mut transport = MemoryTransport::<2>::new(2).unwrap();
        let mut output = [0_u8; 1];

        assert_eq!(transport.receive(&mut output), Err(TransportError::Pending));

        assert_eq!(transport.transmit(&[1, 2]), Ok(2));
        assert_eq!(transport.transmit(&[3]), Err(TransportError::Pending));
    }

    #[test]
    fn compaction_reclaims_consumed_prefix_capacity() {
        let mut transport = MemoryTransport::<6>::new(6).unwrap();
        let mut first = [0_u8; 4];
        let mut second = [0_u8; 4];

        assert_eq!(transport.transmit(&[1, 2, 3, 4, 5, 6]), Ok(6));
        assert_eq!(transport.receive(&mut first), Ok(4));
        assert_eq!(first, [1, 2, 3, 4]);

        assert_eq!(transport.transmit(&[7, 8, 9, 10]), Ok(4));
        assert_eq!(transport.buffered_len(), 6);
        assert_eq!(transport.remaining_capacity(), 0);

        assert_eq!(transport.receive(&mut second), Ok(4));
        assert_eq!(second, [5, 6, 7, 8]);

        let mut tail = [0_u8; 2];
        assert_eq!(transport.receive(&mut tail), Ok(2));
        assert_eq!(tail, [9, 10]);
    }

    #[test]
    fn draining_all_bytes_resets_queue_state() {
        let mut transport = MemoryTransport::<4>::new(4).unwrap();
        let mut output = [0_u8; 4];

        transport.transmit(&[1, 2, 3, 4]).unwrap();
        transport.receive(&mut output).unwrap();

        assert_eq!(transport.buffered_len(), 0);
        assert_eq!(transport.remaining_capacity(), 4);
        assert_eq!(transport.transmit(&[5, 6, 7, 8]), Ok(4));
    }

    #[test]
    fn closure_rejects_transmit_but_allows_buffer_drain() {
        let mut transport = MemoryTransport::<4>::new(4).unwrap();
        let mut output = [0_u8; 2];

        transport.transmit(&[1, 2]).unwrap();
        transport.close();

        assert!(transport.is_closed());
        assert_eq!(transport.transmit(&[3]), Err(TransportError::Closed));
        assert_eq!(transport.receive(&mut output), Ok(2));
        assert_eq!(output, [1, 2]);
        assert_eq!(transport.receive(&mut output), Err(TransportError::Closed));
    }

    #[test]
    fn zero_capacity_transport_handles_empty_operations_only() {
        let mut transport = MemoryTransport::<0>::new(1).unwrap();
        let mut empty = [];
        let mut output = [0_u8; 1];

        assert_eq!(transport.transmit(&[]), Ok(0));
        assert_eq!(transport.receive(&mut empty), Ok(0));
        assert_eq!(transport.transmit(&[1]), Err(TransportError::Pending));
        assert_eq!(transport.receive(&mut output), Err(TransportError::Pending));
    }
}
