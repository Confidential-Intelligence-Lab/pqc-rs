# pqc-rs-protocol

`pqc-rs-protocol` provides transport-independent protocol-layer foundations
for the PQC-rs ecosystem.

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
`ProtocolDriver<T>` provides the initial transport-owning execution context.
`ProtocolHandler` separates protocol-specific decisions from transport and
framing, while `HandlerAction` reports semantic continuation, response, or
orderly-closure intent without prescribing payload storage.

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
