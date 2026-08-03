#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Protocol-layer foundations for PQC-rs.
//!
//! This crate defines transport-independent protocol roles, identifiers,
//! versions, and errors. Wire messages, serialization, framing, sessions,
//! and concrete transports will be introduced in later stages after their
//! semantics are specified.
//!
//! The crate intentionally contains no networking code.

mod error;
mod identifiers;
mod message;
mod metadata;
mod role;

pub use error::{ProtocolError, ProtocolResult};
pub use identifiers::{PolicyId, ProtocolVersion, SessionId};
pub use message::{MessageClass, MessageId};
pub use metadata::{CapabilityId, ProtocolDirection, ProtocolId};
pub use role::ProtocolRole;
