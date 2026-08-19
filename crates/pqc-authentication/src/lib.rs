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

pub use profile::{resolve_authentication_profile, AuthenticationError, AuthenticationProfile};
