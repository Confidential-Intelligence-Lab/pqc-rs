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

mod capabilities;
mod codec;
mod driver;
mod envelope;
mod error;
mod establishment;
mod frame;
mod frame_transport;
mod handler;
mod handshake;
mod handshake_state;
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

pub use capabilities::{
    HPKE_ML_KEM_1024, HPKE_ML_KEM_768, HPKE_ML_KEM_768_CHACHA20, HPKE_ML_KEM_768_X25519,
    REGISTERED_CAPABILITIES,
};
pub use codec::{ProtocolDecode, ProtocolEncode};
pub use driver::{
    DriverError, DriverResult, ProtocolDriver, ResponseError, ResponseResult,
    TransmitPreparationError, TransmitPreparationResult,
};
pub use envelope::ProtocolEnvelope;
pub use error::{ProtocolError, ProtocolResult};
pub use establishment::EstablishedProtocolContext;
pub use frame::{ProtocolFrame, MAX_FRAME_PAYLOAD_LEN};
pub use frame_transport::{
    FrameReceiver, FrameTransferError, FrameTransferResult, FrameTransmitter,
};
pub use handler::{HandlerAction, HandlerOutcome, ProtocolHandler};
pub use handshake::{
    CapabilityOfferPayload, CapabilityRejectionPayload, CapabilityRejectionReason,
    CapabilitySelectionPayload, DecodedCapabilityOffer, CAPABILITY_OFFER_MESSAGE_ID,
    CAPABILITY_REJECTION_MESSAGE_ID, CAPABILITY_SELECTION_MESSAGE_ID,
};
pub use handshake_state::{
    ClientCapabilityHandshake, ClientHandshakeError, ClientHandshakeState,
    ServerCapabilityHandshake, ServerHandshakeError, ServerHandshakeState,
};
pub use identifiers::{PolicyId, ProtocolVersion, SessionId};
pub use memory_transport::MemoryTransport;
pub use message::{MessageClass, MessageId};
pub use message_trait::ProtocolMessage;
pub use metadata::{CapabilityId, ProtocolDirection, ProtocolId};
pub use negotiation::{
    negotiate_decoded_policy_permitted_common, negotiate_policy_permitted_common,
    select_policy_permitted_common, select_preferred_common, validate_selected_capability,
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
