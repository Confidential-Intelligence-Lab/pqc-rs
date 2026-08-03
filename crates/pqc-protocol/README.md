# pqc-rs-protocol

`pqc-rs-protocol` provides transport-independent protocol-layer foundations
for the PQC-rs ecosystem.

## Initial scope

The crate currently defines:

- client and server protocol roles;
- protocol-version identifiers;
- cryptographic-policy identifiers;
- opaque session identifiers;
- protocol-layer error types.

It deliberately does not yet define wire messages, serialization, framing,
sessions, or networking. Those abstractions will be introduced after the
protocol architecture and binary wire format are specified.

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
