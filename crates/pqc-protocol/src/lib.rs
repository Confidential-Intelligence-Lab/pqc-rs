#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Protocol-layer foundations for PQC-rs.
//!
//! This crate defines transport-independent protocol roles, identifiers,
//! messages, sessions, canonical wire framing, and byte-transport
//! contracts. It separates protocol semantics and framing from concrete
//! transport implementations.
//!
//! The crate intentionally contains no networking, operating-system I/O,
//! or asynchronous-runtime dependency.

mod codec;
mod driver;
mod envelope;
mod error;
mod frame;
mod frame_transport;
mod handler;
mod identifiers;
mod memory_transport;
mod message;
mod message_trait;
mod metadata;
mod negotiation;
mod response;
mod role;
mod session;
mod state;
mod transport;
mod typestate;
mod wire;

pub use codec::{ProtocolDecode, ProtocolEncode};
pub use driver::{
    DriverError, DriverResult, ProtocolDriver, ResponseError, ResponseResult,
    TransmitPreparationError, TransmitPreparationResult,
};
pub use envelope::ProtocolEnvelope;
pub use error::{ProtocolError, ProtocolResult};
pub use frame::{ProtocolFrame, MAX_FRAME_PAYLOAD_LEN};
pub use frame_transport::{
    FrameReceiver, FrameTransferError, FrameTransferResult, FrameTransmitter,
};
pub use handler::{HandlerAction, HandlerOutcome, ProtocolHandler};
pub use identifiers::{PolicyId, ProtocolVersion, SessionId};
pub use memory_transport::MemoryTransport;
pub use message::{MessageClass, MessageId};
pub use message_trait::ProtocolMessage;
pub use metadata::{CapabilityId, ProtocolDirection, ProtocolId};
pub use negotiation::{
    negotiate_policy_permitted_common, select_policy_permitted_common, select_preferred_common,
    CapabilityOffer, CapabilityOfferError, CapabilityOfferResult, CapabilityPolicy,
    CapabilityPolicyError, CapabilityPolicyResult, NegotiatedCapability,
};
pub use response::{OutboundResponse, ProtocolResponder};
pub use role::ProtocolRole;
pub use session::ProtocolSession;
pub use state::SessionState;
pub use transport::{TransportError, TransportReceive, TransportResult, TransportTransmit};
pub use typestate::{
    ClosedState, ClosingState, CreatedState, EstablishedState, EstablishingState, FailedState,
    SessionPhase, TypedProtocolSession,
};
pub use wire::{
    WireFlags, WireHeader, WireVersion, WIRE_HEADER_LEN, WIRE_MAGIC, WIRE_RESERVED_LEN,
};
