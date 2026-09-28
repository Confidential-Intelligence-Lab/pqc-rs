//! Unstable engineering and interoperability API.
//!
//! This module exposes HPKE protocol machinery required by repository
//! conformance tests, transcript validation, interoperability tooling, and
//! provider-substitution experiments.
//!
//! It is available only with the `internal-api` feature and is explicitly
//! excluded from the crate's SemVer compatibility commitment.

/// RFC 9180 KDF implementation primitives.
pub mod kdf {
    pub use crate::kdf::KdfAlgorithm;
}

/// RFC 9180 key-schedule machinery.
pub mod key_schedule {
    pub use crate::key_schedule::{
        key_schedule, AeadParameters, HpkeMode, KeyScheduleInputs, KeyScheduleOutput,
    };
}

/// Provider-substitution and transcript setup hooks.
pub mod setup {
    use crate::{HpkeError, HpkeSuiteId, ReceiverContext, SenderContext};

    /// Build a Base-mode sender context from an externally established
    /// KEM shared secret.
    pub fn setup_base_sender_from_shared_secret(
        suite: HpkeSuiteId,
        shared_secret: &[u8],
        info: &[u8],
    ) -> Result<SenderContext, HpkeError> {
        crate::setup::setup_base_sender_from_shared_secret(suite, shared_secret, info)
    }

    /// Build a Base-mode receiver context from an externally established
    /// KEM shared secret.
    pub fn setup_base_receiver_from_shared_secret(
        suite: HpkeSuiteId,
        shared_secret: &[u8],
        info: &[u8],
    ) -> Result<ReceiverContext, HpkeError> {
        crate::setup::setup_base_receiver_from_shared_secret(suite, shared_secret, info)
    }
}
