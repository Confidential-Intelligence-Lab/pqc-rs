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

mod aggregate_admissibility;
mod assurance;
mod capabilities;
mod codec;
mod configuration_identity;
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
mod integrated_transition_path;
mod memory_transport;
mod message;
mod message_trait;
mod metadata;
mod negotiation;
mod response;
mod role;
mod session;
mod state;
mod system_state;
mod system_transition_binding;
mod system_transition_path;
mod transition_admissibility;
mod transition_authorization;
mod transition_path;
mod transition_revalidation;
mod transport;
mod typestate;
mod wire;

pub use assurance::{
    evaluate_evidence, EvidenceApplicability, EvidenceId, EvidenceInput, EvidenceRecord,
    EvidenceScope, VerifiedEvidence,
};
pub use capabilities::{
    AUTH_ML_DSA_65, HPKE_ML_KEM_1024, HPKE_ML_KEM_768, HPKE_ML_KEM_768_CHACHA20,
    HPKE_ML_KEM_768_X25519, REGISTERED_CAPABILITIES,
};
pub use codec::{ProtocolDecode, ProtocolEncode};
pub use configuration_identity::{
    AlgorithmId, ConfigurationIdentity, ImplementationRevision, ParameterSetId, ProviderId,
};
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

/// Cryptographic system-state identity interfaces.
pub use system_state::{
    CryptographicSystemState, DeploymentStateIdentity, EvidenceStateIdentity, PolicyStateIdentity,
};

/// Advisory full-state transition-assessment binding interfaces.
pub use system_transition_binding::{
    evaluate_system_transition_binding, SystemBindingEvaluation, SystemTransitionBinding,
};
/// Advisory full-system-state transition-path evaluation interfaces.
pub use system_transition_path::{
    evaluate_system_transition_path, SystemPathEvaluation, SystemTransitionStep,
};

/// Diagnostic decomposition of transition admissibility.
pub use transition_admissibility::{
    evaluate_admissibility_components, AdmissibilityComponentEvaluation, AdmissibilityComponents,
};

/// Advisory integrated transition-trace evaluation interfaces.
pub use integrated_transition_path::{
    evaluate_integrated_transition_path, IntegratedPathEvaluation, IntegratedTransitionStep,
};

/// Advisory aggregation of bound transition admissibility.
pub use aggregate_admissibility::{
    combine_admissibility_components, evaluate_aggregate_admissibility,
    AggregateAdmissibilityEvaluation,
};

pub use transport::{TransportError, TransportReceive, TransportResult, TransportTransmit};
pub use typestate::{
    ClosedState, ClosingState, CreatedState, EstablishedState, EstablishingState, FailedState,
    SessionPhase, TypedProtocolSession,
};
pub use wire::{
    WireFlags, WireHeader, WireVersion, WIRE_HEADER_LEN, WIRE_MAGIC, WIRE_RESERVED_LEN,
};

/// Advisory cryptographic transition authorization interfaces.
pub use transition_authorization::{
    authorize_transition, AuthorizationDecision, CryptographicTransition, OperationalReadiness,
    PolicyAssessment, TransitionAssessments,
};

/// Advisory execution-context revalidation interfaces.
pub use transition_revalidation::{
    revalidate_transition, AssessedExecutionContext, ContextRevision, CurrentExecutionContext,
    ExecutionRevisions, RevalidationResult,
};

/// Advisory transition-path evaluation interfaces.
pub use transition_path::{
    evaluate_temporal_path, evaluate_transition_path, PathEvaluation, TemporalPathEvaluation,
    TransitionPathStep,
};
