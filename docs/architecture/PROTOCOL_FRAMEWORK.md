# PQC-rs Protocol Framework

## Purpose

The `pqc-rs-protocol` crate provides the transport-independent application
and protocol-orchestration layer for the PQC-rs ecosystem. It separates
protocol state, wire semantics, and application workflows from the
underlying cryptographic implementations.

The framework is experimental. Its first development stage defines only
participant roles, protocol versions, cryptographic-policy identifiers,
opaque session identifiers, and protocol-layer errors.

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
than a cryptographic primitive. These include participant roles, protocol
versions, policy identifiers, session identifiers, wire messages, framing,
session state, and transport-independent orchestration.

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
