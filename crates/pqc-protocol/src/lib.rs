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

mod codec;
mod envelope;
mod error;
mod identifiers;
mod message;
mod message_trait;
mod metadata;
mod role;

pub use codec::{ProtocolDecode, ProtocolEncode};
pub use envelope::ProtocolEnvelope;
pub use error::{ProtocolError, ProtocolResult};
pub use identifiers::{PolicyId, ProtocolVersion, SessionId};
pub use message::{MessageClass, MessageId};
pub use message_trait::ProtocolMessage;
pub use metadata::{CapabilityId, ProtocolDirection, ProtocolId};
pub use role::ProtocolRole;
