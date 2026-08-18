# pqc-rs-protocol

`pqc-rs-protocol` is the transport-independent protocol layer of
**PQC-Forge**, the cryptographic-agility architecture built on PQC-rs.

It provides protocol roles, framing, capability negotiation, policy binding,
session state, and transport-independent execution machinery.

Cryptographic capability identifiers remain opaque at this layer. Concrete
KEM, KDF, and AEAD profiles are resolved by the PQC-Forge secure-channel
layer rather than selected directly by peers.

## Initial scope

The crate currently defines:

- client and server protocol roles;
- logical protocol directionality;
- protocol-family and capability identifiers;
- protocol-message identifiers and semantic classes;
- a transport-independent protocol-message trait;
- a generic message envelope with payload-type independence;
- non-allocating protocol encoding and prefix/exact decoding contracts;
- protocol-version identifiers;
- cryptographic-policy identifiers;
- opaque session identifiers;
- validated transport-independent session lifecycle states;
- a protocol-session metadata container with validated transitions;
- typestate session wrappers and bounded phase markers for compile-time lifecycle progression;
- fixed, independently versioned wire-header primitives and framing constants;
- zero-copy complete-frame composition, encoding, and payload slicing;
- transport-independent byte transmit and receive contracts;
- a fixed-capacity, allocation-free in-memory reference transport;
- resumable framed transmit and receive state machines;
- a transport-independent protocol execution context;
- protocol-specific frame-handler and semantic-action contracts;
- protocol-layer error types.

It defines the semantic model, fixed shape, big-endian byte encoding, and
validation rules of the initial wire header, together with zero-copy
complete-frame composition and decoding. Portable byte-transport contracts
and an allocation-free in-memory reference implementation are provided.
Resumable frame-transfer state machines connect canonical framing to byte
transports without selecting a networking or operating-system I/O backend.
`ProtocolDriver<T>` owns the transport and runtime `ProtocolSession` for one
execution context. It invokes externally supplied handlers over validated
inbound frames and applies requested lifecycle changes exclusively through
`ProtocolSession::transition_to`.
`ProtocolHandler` separates protocol-specific decisions from transport and
framing. `HandlerOutcome` carries a semantic `HandlerAction` and an optional
requested session transition without granting handlers mutable session
access or prescribing payload storage.
`ProtocolResponder` provides allocation-free outbound payload construction
into caller-owned storage. `OutboundResponse` borrows that payload while
carrying only protocol-specific message identity and class; session-bound
wire metadata remains framework-owned.

`ProtocolDriver::frame_response` converts an `OutboundResponse` into a
`ProtocolFrame` using authoritative runtime-session metadata. Protocol ID
and protocol version come from the bound `ProtocolSession`, while outbound
direction is derived from the local `ProtocolRole`. Wire version, flags,
and payload length remain framing-derived. Frame construction performs no
transport I/O and does not mutate session state.

`ProtocolDriver::build_response` completes allocation-free outbound response
orchestration. It invokes a `ProtocolResponder` with caller-owned payload
storage, preserves responder failures separately through `ResponseError`,
and converts the returned `OutboundResponse` into a session-bound
`ProtocolFrame`. Response construction performs no transport I/O and does
not mutate transport or session state.

`ProtocolDriver::advance_transmit` advances an externally owned
`FrameTransmitter` over the driver's owned transport. Encoded-frame scratch
storage and resumable transmission state remain caller-owned, so partial
progress, retryable transport conditions, and completion remain explicit
without hidden allocation or driver-internal buffering. Transmission does not
mutate protocol-session state.

`ProtocolDriver::prepare_response_transmit` composes response construction,
session-derived framing, and canonical frame encoding into a caller-owned
`FrameTransmitter`. Response payload storage is needed only during preparation;
the returned transmitter borrows only encoded frame storage. Preparation
performs no transport I/O and introduces no hidden allocation or transfer
state.

Outbound transfer semantics are exercised under adversarial transport behavior.
Maximally fragmented writes preserve canonical encoded bytes without omission
or duplication; retryable `Pending` and `Interrupted` failures preserve the
committed transmission offset and permit exact resumption; terminal closure
preserves already committed progress; invalid progress reports are rejected
without advancing state; and advancing an already completed transmitter is
idempotent and performs no further transport I/O.

`CapabilityOffer` introduces the first protocol-negotiation vocabulary. It is
an ordered, borrowed view over caller-owned `CapabilityId` values: lower
indices represent stronger advertised preference, empty offers are valid, and
duplicate capability identifiers are rejected. Offer construction performs no
allocation, transport I/O, policy evaluation, session mutation, cryptographic
selection, or wire encoding.

`select_preferred_common` performs deterministic capability intersection using
local offer ordering as preference precedence. It selects the first locally
preferred capability also present in the peer offer, or returns `None` when
there is no overlap. Selection can therefore return only a capability
explicitly present in both validated offers and performs no policy evaluation,
session mutation, transport I/O, cryptographic resolution, or wire processing.

`CapabilityPolicy` represents already-resolved local policy constraints without
interpreting `PolicyId` inside the protocol layer. Its borrowed allow-list
defines which capabilities are permitted but does not define preference.
`select_policy_permitted_common` preserves local-offer preference while
requiring the selected capability to be present in both offers and permitted
by local policy.

`NegotiatedCapability` records the capability selected by policy-constrained
negotiation together with the `PolicyId` under which it was permitted.
`negotiate_policy_permitted_common` produces this caller-owned evidence only
after successful common-capability and policy filtering. The negotiated value
is metadata rather than session state: negotiation performs no transport I/O,
does not mutate `ProtocolSession`, and does not itself establish a session.

`EstablishedProtocolContext` binds an established typed session to its
`NegotiatedCapability` without adding negotiation fields to `ProtocolSession`.
`TypedProtocolSession<EstablishingState>::establish_with_negotiation` produces
this stronger caller-owned context while the existing `establish` transition
remains available for generic lifecycle establishment. The context retains the
negotiated policy and capability as evidence and performs no transport I/O,
provider resolution, or cryptographic execution.

The capability handshake now has canonical non-allocating payload codecs.
`CapabilityOfferPayload` encodes ordered local capability offers, while
`DecodedCapabilityOffer` validates and borrows canonical wire bytes without
unsafe representation casts. `CapabilitySelectionPayload` and
`CapabilityRejectionPayload` encode the server selection or rejection result.
`PolicyId` remains local metadata and is never carried in these handshake
payloads.

The capability handshake now composes the canonical wire codec with explicit
client and server orchestration state. The client emits an ordered capability
offer and later validates an exact server-selected capability against its
original offer and local policy. The server decodes the offer, applies its own
local preference and policy, and emits either a canonical selection or
rejection.

Handshake processing deliberately does not establish the runtime session.
Successful negotiation produces endpoint-local `NegotiatedCapability` evidence;
the client and server must agree on the selected `CapabilityId`, while each may
retain a distinct local `PolicyId`. Establishment remains an explicit later
commit through `establish_with_negotiation`.

The complete exchange is exercised through resumable `FrameTransmitter`,
`MemoryTransport`, and `FrameReceiver` paths under deterministic fragmentation.

## Layering

```text
Application
    |
pqc-rs-protocol
    |
pqc-rs-hpke and future protocol compositions
    |
PQC-rs cryptographic primitives
```

## Status

This crate is experimental and is not currently published.
