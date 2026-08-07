//! Error types shared by all crates.

/// Result alias used throughout the workspace.
pub type PqcResult<T> = core::result::Result<T, PqcError>;

/// Workspace-wide error type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PqcError {
    /// The byte string length does not match the selected parameter set.
    InvalidLength {
        /// Expected byte length.
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// The byte string is malformed for the selected object type.
    MalformedEncoding,
    /// The supplied parameter set is unsupported by this crate.
    UnsupportedParameterSet,
    /// Signature verification failed.
    VerificationFailed,
    /// Decapsulation failed or produced an invalid intermediate state.
    DecapsulationFailed,
    /// Randomness generation failed.
    RandomnessFailure,

    /// A cryptographic object belongs to a different parameter set.
    ParameterSetMismatch,

    /// Input violates a constraint of the selected cryptographic operation.
    InvalidInput,

    /// An internal cryptographic invariant failed.
    InternalError,
    /// A protocol-level invariant failed.
    ProtocolInvariantFailed,
}
