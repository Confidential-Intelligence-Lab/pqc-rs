# PQC-rs Protocol Framework

## Purpose

The `pqc-rs-protocol` crate provides the transport-independent application
and protocol-orchestration layer for the PQC-rs ecosystem. It separates
protocol state, wire semantics, and application workflows from the
underlying cryptographic implementations.

The framework is experimental. Its first development stage defines only
participant roles, logical directionality, protocol and capability
identifiers, message identifiers and semantic classes, a transport-
independent protocol-message trait, a generic payload-independent message
envelope, protocol versions, cryptographic-policy identifiers, opaque
session identifiers, and protocol-layer errors.

## Architectural layering

```text
Applications and networked tools
              |
       pqc-rs-protocol
              |
Protocol implementations and profiles
   pqc-rs-hpke / future compositions
              |
Post-quantum cryptographic primitives
 ML-KEM / ML-DSA / SLH-DSA / hybrid
              |
          pqc-rs-core
```

## Design boundaries

### Protocol framework

`pqc-rs-protocol` owns concepts that describe a protocol exchange rather
than a cryptographic primitive. These include participant roles,
logical directionality, protocol and capability identifiers,
protocol versions, policy identifiers, session identifiers,
wire messages, framing, session state, and
transport-independent orchestration.

### Message identity

Message identifiers are scoped by protocol family or profile. Message
classes distinguish control, handshake, and application semantics without
defining payload representation, delivery guarantees, ordering, framing,
serialization, or cryptographic protection. Those concerns belong to later
protocol-framework stages.

The `ProtocolMessage` trait exposes semantic metadata only: protocol,
version, message identifier, message class, and logical direction. It does
not prescribe payload ownership or any wire representation.

`ProtocolEnvelope<P>` associates semantic message metadata with an
unconstrained payload type. The generic parameter permits borrowed,
fixed-size, allocated, or typed payloads without making allocation or
serialization part of the protocol-message abstraction.

### Codec contracts

`ProtocolEncode` writes canonical protocol values into caller-provided
storage and therefore does not require allocation. `ProtocolDecode`
distinguishes prefix decoding, which reports the number of bytes consumed,
from exact decoding, which rejects trailing input. These contracts define
buffer and consumption behavior but do not establish a concrete wire
format or message frame.

The protocol codec contracts complement rather than replace
`pqc-core::Encode` and `pqc-core::Decode`. The core traits remain suitable
for standalone canonical cryptographic objects; protocol framing requires
non-allocating writes and explicit input-consumption semantics.

### Session lifecycle

`SessionState` defines a transport-independent lifecycle consisting of
created, establishing, established, closing, closed, and failed states.
The common lifecycle validates broad state progression while leaving
protocol-specific handshake events and typestate wrappers to later stages.
Closed and failed sessions are terminal and reject further transitions.

`ProtocolSession` binds the session identifier, protocol identifier,
protocol version, local participant role, and current lifecycle state.
It applies the common transition rules transactionally: an invalid
transition returns an error and preserves the prior state. The container
does not own cryptographic context, transport state, message queues, or
protocol-specific handshake data.

`TypedProtocolSession<State>` wraps the runtime session with zero-sized
lifecycle markers bounded by the `SessionPhase` trait. The bound prevents
unrelated types from being used as lifecycle parameters. Legal transitions
consume one typed session and return
the next typed state, so skipped transitions and transitions out of
terminal states are unavailable through the typed API. The runtime session
remains available for dynamic dispatch, storage, and interoperability with
code that cannot represent lifecycle state statically.

### Wire-format primitives

The initial wire-format model uses a fixed 32-byte header. The header
identifies the binary wire version, protocol version, protocol and message
identifiers, flags, message class, logical direction, and payload length.
Magic bytes, encoded header length, and eight reserved bytes are framing
constants rather than mutable semantic fields.

`WireVersion` is independent from `ProtocolVersion`, allowing binary
representation and protocol semantics to evolve separately. `WireFlags`
preserves the raw 16-bit field while initially accepting only the empty
flag set. `WireHeader` describes payload extent without owning payload
storage and does not require sessions, transports, or allocation.

The concrete representation uses fixed offsets and big-endian integers.
`ProtocolEncode` writes exactly 32 bytes into caller-provided storage, and
`ProtocolDecode` supports both prefix and exact decoding. Decoding rejects
invalid magic, unsupported wire versions or flags, incorrect header
lengths, unknown enum discriminants, truncated input, and nonzero reserved
bytes.

`ProtocolFrame<'a>` composes a validated `WireHeader` with a borrowed
payload. Construction requires the declared and actual payload lengths to
agree. Prefix decoding borrows exactly the declared payload bytes and
reports the complete frame length, while exact decoding rejects trailing
input. Encoding concatenates the canonical header and payload into
caller-provided storage without allocation.

The frame decoder is an inherent lifetime-aware API rather than an
implementation of `ProtocolDecode`, because the generic decoding trait
cannot express a result that borrows from its input. Transport integration
and network I/O remain outside the framing layer.

### Transport contracts

`TransportTransmit` and `TransportReceive` define allocation-free byte
movement below the framing layer. They permit partial progress and require
retryable no-progress conditions to be reported explicitly rather than as
successful zero-byte operations on nonempty buffers.

`TransportError` classifies pending, closed, interrupted, invalid, and
implementation-specific transport failures independently from
`ProtocolError`. This keeps malformed protocol data separate from failures
to move otherwise valid bytes. The contracts do not depend on `std::io`,
an async runtime, operating-system handles, or any concrete transport.

`MemoryTransport<N>` is the allocation-free reference implementation. It
uses fixed caller-selected capacity, a deterministic transfer limit, and
a linear queue with compaction. Transmitted bytes loop back to the receive
side, making the type suitable for framing tests without introducing
networking or platform dependencies.

An open empty receive or full transmit reports `Pending`. Closing rejects
new transmission while preserving buffered bytes for draining; receives
report `Closed` only after the queue becomes empty.

### Framed transport integration

`FrameTransmitter` encodes one `ProtocolFrame` into caller-provided scratch
storage and preserves its byte offset across partial transport progress.
`FrameReceiver` receives exactly the fixed header first, validates it,
derives the complete frame length, and then receives exactly the declared
payload. It therefore does not consume bytes belonging to a subsequent
frame on stream-oriented transports.

`FrameTransferError` preserves the distinction between protocol-format
failures and transport failures. Both state machines are allocation-free,
resumable after `Pending` or partial progress, and independent of concrete
networking and asynchronous-runtime APIs.

### Protocol execution context

`ProtocolDriver<T>` owns the transport and runtime `ProtocolSession`
associated with one protocol execution context. It exposes controlled
immutable and mutable access to both components and returns their ownership
together through `into_parts`, while remaining generic over the transport
type.

The driver deliberately performs no message interpretation, state-machine
transition, cryptographic operation, frame-storage allocation, or retry
policy. Those responsibilities belong to future protocol handlers and
orchestration layers. Keeping the initial driver minimal prevents protocol
semantics from becoming coupled to byte movement or concrete transports.

The driver does not define an independent lifecycle representation.
`ProtocolSession` remains the single runtime source of truth, and mutable
session access continues to enforce transitions through
`ProtocolSession::transition_to`. Session-aware handler outcomes and
automatic transition orchestration remain later increments.

### Protocol handler contracts

`ProtocolHandler` is the protocol-specific decision boundary. It receives
a validated borrowed `ProtocolFrame`, may update handler-owned state, and
returns a `HandlerOutcome`. Each outcome contains a semantic
`HandlerAction` and may request a runtime-session transition.

Handlers do not own transports, perform I/O, allocate frame storage, or
construct outbound frames. The action model intentionally carries no
payload or buffer lifetime, leaving response construction and transfer to
later orchestration layers. Handler errors remain protocol-specific through
an associated error type.

A requested transition is declarative only from the handler's perspective.
The handler receives no mutable session reference and cannot apply or
validate lifecycle changes. `ProtocolDriver::handle_frame` applies the
request exclusively through `ProtocolSession::transition_to`; rejected
requests preserve the previous session state.

### Outbound response contracts

`ProtocolResponder` separates protocol-specific payload construction from
wire framing and transport. A responder writes bytes into caller-owned
storage and returns an `OutboundResponse` borrowing the initialized payload.

`OutboundResponse` contains only the protocol-scoped `MessageId`, semantic
`MessageClass`, and borrowed payload. It deliberately excludes protocol ID,
protocol version, logical direction, wire version, wire flags, and encoded
payload length. Those values remain framework-derived from authoritative
session and framing state.

`ProtocolDriver::handle_frame` forms the inbound orchestration seam between
the transport-owning execution context and an externally supplied handler.
It forwards one validated frame, preserves handler error provenance, and
applies any requested lifecycle transition exclusively through
`ProtocolSession::transition_to`. The operation performs no transport I/O,
response construction, or cryptographic processing.

`DriverError<E>` preserves error provenance by distinguishing handler
failures from protocol-layer lifecycle-validation failures. The driver
performs no compensating transition after rejection because
`ProtocolSession::transition_to` is atomic with respect to session state.

`ProtocolEnvelope<P>` associates the semantic message metadata with an
unconstrained payload type. The generic parameter permits borrowed,
fixed-size, allocated, or typed payloads without making allocation or
serialization part of the protocol-message abstraction.

`ProtocolDriver::frame_response` realizes this boundary. Given an
`OutboundResponse`, the driver derives protocol ID and protocol version
from its bound `ProtocolSession` and derives logical direction from the
local role: clients emit `ClientToServer` frames and servers emit
`ServerToClient` frames. `ProtocolFrame::current` supplies the current wire
version, empty wire flags, and payload length derived from the borrowed
payload. This construction step performs no transport I/O and leaves both
transport and session state unchanged.

`ProtocolDriver::build_response` composes the responder and framing
boundaries without introducing transport behavior. The driver supplies
caller-owned storage to `ProtocolResponder::write_response`, receives a
borrowed `OutboundResponse`, and passes it through `frame_response` to
produce the canonical session-bound `ProtocolFrame`. `ResponseError<E>`
keeps responder failures distinct from protocol-layer framing failures.
The operation performs no transport I/O and leaves both transport and
session state unchanged. Actual frame transmission remains a separate
orchestration concern.

`ProtocolDriver::advance_transmit` connects the transport-owning execution
context to the existing resumable `FrameTransmitter`. The caller retains
ownership of the transmitter, its encoded-frame scratch storage, and its
progress state; the driver contributes only mutable access to its owned
`TransportTransmit` implementation. Each call performs exactly one transmitter
advance operation, preserving partial progress and propagating existing
`FrameTransferError` semantics. No additional transfer state, hidden buffering,
allocation, or protocol-session mutation is introduced by the driver.

`ProtocolDriver::prepare_response_transmit` composes the outbound response and
resumable-transfer boundaries without performing transport I/O. The responder
writes protocol-specific bytes into caller-owned payload storage; the driver
derives canonical session-bound framing and `FrameTransmitter::new` immediately
encodes that frame into caller-owned frame storage. The returned transmitter
therefore retains only the encoded frame-storage lifetime, not the response
payload-storage lifetime. `TransmitPreparationError<E>` keeps responder
failures distinct from protocol framing or encoding failures, while actual
transport failures remain represented later by `FrameTransferError`.

The resumable outbound-transfer boundary is validated against adversarial
transport behavior. Successful partial writes advance the committed offset by
exactly the accepted byte count. `Pending` and `Interrupted` outcomes leave
that offset unchanged and permit subsequent resumption from the same encoded
position. Terminal transport failure preserves previously committed progress
without rollback. Invalid zero or oversized progress reports are rejected
without advancing transmitter state. Maximal one-byte fragmentation produces
the exact canonical encoded frame without duplication or omission, while
advancing an already completed transmitter is idempotent and performs no
additional transport I/O. None of these transfer outcomes mutate the bound
`ProtocolSession`.

### Protocol implementations

`pqc-rs-hpke` and future protocol crates own standards-defined cryptographic
protocol behavior. They expose operations that the protocol framework may
compose, but they do not own network transport or application framing.

### Cryptographic primitives

ML-KEM, ML-DSA, SLH-DSA, and hybrid-composition crates implement algorithms
and narrowly scoped cryptographic APIs. They do not depend on application or
transport semantics.

### Shared core

`pqc-rs-core` owns reusable cryptographic traits, typed byte containers,
secret containers, errors, constant-time helpers, and shared codec traits.
Protocol serialization will reuse these shared boundaries where appropriate.

## Current scope

The initial protocol crate contains no networking, wire-message encoding,
framing, cryptographic execution, or session state machine. These omissions
are deliberate: their semantics will be specified before implementation.

## Planned development sequence

1. Foundational roles, identifiers, errors, and crate boundaries.
2. Protocol architecture and binary wire-format specification.
3. Strict encoding, decoding, length validation, and fuzz testing.
4. In-process protocol simulation over serialized messages.
5. Independent client and server applications using blocking TCP.
6. Replay, ordering, truncation, corruption, and resource-bound tests.
7. Policy-driven cryptographic agility and provider interoperability.

### Capability negotiation vocabulary

`CapabilityId` remains the atomic identifier for an optional protocol
capability. `CapabilityOffer<'a>` adds negotiation semantics without changing
that identifier: an offer is an ordered, borrowed view over caller-owned
capability identifiers, where lower indices represent stronger advertised
preference.

Offers may be empty because structural capability representation is kept
separate from higher-level negotiation policy. Duplicate identifiers are
rejected by `CapabilityOffer::new`, preserving an unambiguous preference
ordering. The representation performs no allocation, transport I/O, policy
evaluation, session mutation, cryptographic selection, or wire encoding.

`PolicyId` remains distinct from peer-advertised capabilities. It identifies
local cryptographic policy and is intentionally not interpreted directly by
the negotiation vocabulary. Stage 12A.12 now provides deterministic capability
intersection, resolved policy constraints, negotiation evidence, and
negotiation-aware establishment while keeping concrete policy interpretation
and provider resolution outside the protocol layer.

`select_preferred_common` adds deterministic capability intersection without
introducing negotiation state. Local offer ordering defines preference
precedence: the resolver walks local capabilities from strongest to weakest
and returns the first identifier also present in the validated peer offer.
No common capability yields `None`.

The resolver cannot select a capability absent from either offer. This
intersection invariant forms the initial foundation for later downgrade-
resistance rules. The operation is pure with respect to both offers and
performs no policy interpretation, session transition, transport I/O,
cryptographic algorithm resolution, or wire processing.

`CapabilityPolicy<'a>` represents the output of policy resolution rather than
performing policy interpretation itself. `PolicyId` identifies the externally
defined policy, while the borrowed allow-list records the capabilities that an
external policy-resolution layer has determined are permitted. Allow-list
ordering has no preference semantics.

`select_policy_permitted_common` retains local-offer preference precedence
while adding the policy constraint. A selected capability must therefore be
present in the local offer, present in the peer offer, and permitted by the
resolved local policy. Policy filtering cannot reorder the remaining local
candidates. An empty allow-list or the absence of a capability satisfying all
three constraints produces no selection.

`NegotiatedCapability` is the validated output of policy-constrained
capability negotiation. It binds the selected `CapabilityId` to the
`PolicyId` under which that selection was permitted. Construction remains
internal to the negotiation operation rather than being exposed as an
unrestricted public constructor, so the value represents successful
negotiation rather than an arbitrary capability-policy pair.

The negotiated value remains caller-owned metadata. It is not stored in
`ProtocolSession`, `TypedProtocolSession`, `ProtocolDriver`, or
`HandlerOutcome`. Producing it performs no transport I/O, session mutation,
provider selection, cryptographic execution, or lifecycle transition.
In particular, successful capability negotiation does not itself transition
a session to `Established`. Establishment binding remains a separate
architectural boundary.

`EstablishedProtocolContext` is the negotiation-aware establishment boundary.
It owns both a `TypedProtocolSession<EstablishedState>` and the
`NegotiatedCapability` that justified the negotiated protocol choice.
Construction occurs through
`TypedProtocolSession<EstablishingState>::establish_with_negotiation`, so the
context records both successful lifecycle establishment and retained
negotiation evidence.

This composition deliberately leaves `ProtocolSession` unchanged. Negotiated
policy and capability metadata are not inserted into the generic runtime
session, typestate representation, driver, or handler outcome. The ordinary
`TypedProtocolSession<EstablishingState>::establish` transition also remains
available for protocol families whose lifecycle does not use this capability
negotiation mechanism.

The establishment context preserves session identity, protocol identity,
protocol version, role, policy identity, and selected capability. It may be
consumed with `into_parts` to recover the established typed session and
negotiation evidence without loss. This boundary performs no transport I/O,
provider resolution, cryptographic execution, or wire processing. Downstream
lifecycle behavior and concrete cryptographic/provider binding remain separate
architectural concerns.

This boundary keeps policy definition and provider resolution outside the
protocol-negotiation mechanism. The protocol layer does not infer cryptographic
semantics from `PolicyId`, map capabilities to concrete algorithms, perform
provider selection, mutate session state, or bind the result to establishment.

### Negotiation downgrade-resistance assurance

The complete capability-negotiation path is exercised against adversarial peer
ordering and capability injection. Peer offer ordering cannot override local
preference, and a peer cannot cause selection of a capability absent from the
local offer. Policy permission cannot create peer support or local support, and
policy filtering remains authoritative when it excludes a more-preferred
mutually supported capability.

Consequently, every successfully negotiated capability remains inside the
three-way intersection of local support, peer support, and resolved local
policy. If that intersection is empty, no `NegotiatedCapability` and therefore
no negotiation-aware `EstablishedProtocolContext` is produced.

End-to-end assurance also verifies that establishment preserves the exact
session identifier, protocol identifier, protocol version, participant role,
policy identifier, and selected capability produced by negotiation. These
properties are tested without introducing downgrade-specific mutable state or
a separate downgrade mechanism.

## Cryptographic agility

Applications should ultimately select security behavior through validated
policy identifiers rather than by directly hard-coding KEM, KDF, signature,
or AEAD implementations. The framework is intended to accommodate NIST,
IETF, ISO/IEC, Korean, European, and future standards ecosystems without
requiring application workflows to be rewritten.

## Future protocol families

The architecture may support additional standards and protocol families,
including hybrid HPKE profiles, secure-channel protocols, TLS or QUIC
integration, group messaging, COSE, JOSE, and provider-backed deployments.
These are roadmap directions, not claims of current implementation.

## Assurance model

Each protocol-framework stage must include documentation, negative testing,
fuzzing where parsers are introduced, API and architecture inventory updates,
and the workspace CI/CD assurance gates before integration into `main`.
