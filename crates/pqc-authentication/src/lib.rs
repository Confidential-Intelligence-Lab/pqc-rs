#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Capability-bound post-quantum authentication for PQC-Forge.
//!
//! This crate is a sibling integration layer to `pqc-rs-secure-channel`.
//! It consumes established protocol context containing validated capability
//! negotiation evidence and resolves that evidence into a locally defined
//! authentication profile.
//!
//! The protocol layer owns capability identity, negotiation, policy, and
//! established protocol state. This crate owns the local interpretation of
//! authentication capabilities. It deliberately does not depend on HPKE or
//! the secure-channel integration.

mod profile;
mod proof;
mod transcript;
mod verifier;

pub use profile::{resolve_authentication_profile, AuthenticationError, AuthenticationProfile};
pub use proof::{
    prove_authentication_deterministic, prove_authentication_hedged, verify_authentication,
    AuthenticationProof,
};
pub use transcript::{
    authentication_transcript, AuthenticationChallenge, AUTHENTICATION_CHALLENGE_BYTES,
    MAX_APPLICATION_CONTEXT_BYTES,
};

pub use verifier::{Authenticated, AuthenticationVerifier, PendingAuthentication};
