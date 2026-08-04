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
- protocol-layer error types.

It defines the semantic model and fixed shape of the initial wire header,
but does not yet define its concrete byte encoding, complete message
framing, transport integration, or networking. The codec contracts define
buffer and consumption semantics; concrete field offsets and validation
rules are introduced in the next wire-format stage.

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
