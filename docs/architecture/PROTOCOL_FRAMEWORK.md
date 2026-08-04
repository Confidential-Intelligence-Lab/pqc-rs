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

Concrete byte offsets, big-endian encoding, reserved-field validation, and
`ProtocolEncode` and `ProtocolDecode` implementations are deferred to the
next wire-format stage.

`ProtocolEnvelope<P>` associates the semantic message metadata with an
unconstrained payload type. The generic parameter permits borrowed,
fixed-size, allocated, or typed payloads without making allocation or
serialization part of the protocol-message abstraction.

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
