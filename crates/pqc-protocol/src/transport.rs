//! Transport-independent byte movement contracts.

/// Result type used by transport-layer operations.
pub type TransportResult<T> = core::result::Result<T, TransportError>;

/// Portable classification of transport-layer failures.
///
/// These errors describe failures while moving bytes. They are intentionally
/// separate from protocol parsing, validation, and lifecycle errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    /// The transport cannot currently make progress and may be retried.
    Pending,
    /// The transport has been closed and cannot make further progress.
    Closed,
    /// The operation was interrupted before progress was made and may be retried.
    Interrupted,
    /// The transport rejected the requested operation.
    InvalidOperation,
    /// The underlying transport reported an implementation-specific failure.
    Other,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Pending => "transport operation is pending",
            Self::Closed => "transport is closed",
            Self::Interrupted => "transport operation was interrupted",
            Self::InvalidOperation => "invalid transport operation",
            Self::Other => "other transport operation failure",
        };

        formatter.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TransportError {}

/// Transport-independent contract for transmitting bytes.
///
/// Implementations may make partial progress and return fewer bytes than were
/// supplied. For a nonempty input slice, successful implementations must
/// return a strictly positive byte count no greater than `input.len()`.
///
/// An implementation that cannot currently progress must return
/// [`TransportError::Pending`] rather than `Ok(0)`. A permanently closed
/// transport must return [`TransportError::Closed`].
pub trait TransportTransmit {
    /// Attempt to transmit bytes from `input`.
    ///
    /// Empty input may return `Ok(0)`.
    fn transmit(&mut self, input: &[u8]) -> TransportResult<usize>;
}

/// Transport-independent contract for receiving bytes.
///
/// Implementations may make partial progress and return fewer bytes than fit
/// in the supplied output slice. For a nonempty output slice, successful
/// implementations must return a strictly positive byte count no greater than
/// `output.len()`.
///
/// An implementation that cannot currently progress must return
/// [`TransportError::Pending`] rather than `Ok(0)`. A permanently closed
/// transport must return [`TransportError::Closed`].
pub trait TransportReceive {
    /// Attempt to receive bytes into `output`.
    ///
    /// Empty output may return `Ok(0)`.
    fn receive(&mut self, output: &mut [u8]) -> TransportResult<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct ScriptedTransport {
        transmitted: usize,
        received: usize,
        closed: bool,
    }

    impl ScriptedTransport {
        const fn new() -> Self {
            Self {
                transmitted: 0,
                received: 0,
                closed: false,
            }
        }
    }

    impl TransportTransmit for ScriptedTransport {
        fn transmit(&mut self, input: &[u8]) -> TransportResult<usize> {
            if self.closed {
                return Err(TransportError::Closed);
            }

            if input.is_empty() {
                return Ok(0);
            }

            let progress = core::cmp::min(input.len(), 2);
            self.transmitted += progress;
            Ok(progress)
        }
    }

    impl TransportReceive for ScriptedTransport {
        fn receive(&mut self, output: &mut [u8]) -> TransportResult<usize> {
            if self.closed {
                return Err(TransportError::Closed);
            }

            if output.is_empty() {
                return Ok(0);
            }

            let source = [0x10_u8, 0x20, 0x30];
            let remaining = &source[self.received..];

            if remaining.is_empty() {
                return Err(TransportError::Pending);
            }

            let progress = core::cmp::min(output.len(), remaining.len());
            output[..progress].copy_from_slice(&remaining[..progress]);
            self.received += progress;
            Ok(progress)
        }
    }

    #[test]
    fn transmission_contract_allows_partial_progress() {
        let mut transport = ScriptedTransport::new();

        assert_eq!(transport.transmit(&[1, 2, 3, 4]), Ok(2));
        assert_eq!(transport.transmitted, 2);
    }

    #[test]
    fn reception_contract_allows_partial_progress() {
        let mut transport = ScriptedTransport::new();
        let mut output = [0_u8; 2];

        assert_eq!(transport.receive(&mut output), Ok(2));
        assert_eq!(output, [0x10, 0x20]);
    }

    #[test]
    fn empty_operations_may_report_zero_progress() {
        let mut transport = ScriptedTransport::new();
        let mut output = [];

        assert_eq!(transport.transmit(&[]), Ok(0));
        assert_eq!(transport.receive(&mut output), Ok(0));
    }

    #[test]
    fn nonempty_receive_reports_pending_when_no_data_is_available() {
        let mut transport = ScriptedTransport::new();
        let mut first = [0_u8; 3];
        let mut second = [0_u8; 1];

        assert_eq!(transport.receive(&mut first), Ok(3));
        assert_eq!(transport.receive(&mut second), Err(TransportError::Pending));
    }

    #[test]
    fn closed_transport_rejects_transmit_and_receive() {
        let mut transport = ScriptedTransport::new();
        transport.closed = true;
        let mut output = [0_u8; 1];

        assert_eq!(transport.transmit(&[1]), Err(TransportError::Closed));
        assert_eq!(transport.receive(&mut output), Err(TransportError::Closed));
    }

    #[test]
    fn transport_errors_have_stable_descriptions() {
        assert_eq!(
            TransportError::Pending.to_string(),
            "transport operation is pending"
        );
        assert_eq!(TransportError::Closed.to_string(), "transport is closed");
        assert_eq!(
            TransportError::Interrupted.to_string(),
            "transport operation was interrupted"
        );
        assert_eq!(
            TransportError::InvalidOperation.to_string(),
            "invalid transport operation"
        );
        assert_eq!(
            TransportError::Other.to_string(),
            "other transport operation failure"
        );
    }
}
