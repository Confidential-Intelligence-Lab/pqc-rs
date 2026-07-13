//! Public ML-DSA API surface.
//!
//! Stage 9A intentionally exposes only typed placeholders. Cryptographic
//! operations are added in later Stage 9 increments.

use crate::{MlDsaError, MlDsaParameterSet};

/// ML-DSA implementation selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MlDsa {
    parameter_set: MlDsaParameterSet,
}

impl MlDsa {
    /// Construct an ML-DSA instance.
    pub const fn new(parameter_set: MlDsaParameterSet) -> Self {
        Self { parameter_set }
    }

    /// Return the selected parameter set.
    pub const fn parameter_set(self) -> MlDsaParameterSet {
        self.parameter_set
    }

    /// Return the expected public-key length.
    pub const fn public_key_bytes(self) -> usize {
        self.parameter_set.parameters().public_key_bytes
    }

    /// Return the expected private-key length.
    pub const fn private_key_bytes(self) -> usize {
        self.parameter_set.parameters().private_key_bytes
    }

    /// Return the expected signature length.
    pub const fn signature_bytes(self) -> usize {
        self.parameter_set.parameters().signature_bytes
    }

    /// Stage 9A placeholder for key generation.
    pub fn keygen(&self) -> Result<(), MlDsaError> {
        Err(MlDsaError::NotImplemented)
    }
}
