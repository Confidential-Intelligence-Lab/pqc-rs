# pqc-rs-secure-channel

`pqc-rs-secure-channel` is the **PQC-Forge** integration layer that turns
validated PQC-rs protocol negotiation evidence into policy-bound HPKE secure
channels.

It connects the transport-independent protocol machinery in
`pqc-rs-protocol` to concrete cryptographic profiles implemented by
`pqc-rs-hpke`. Peer-controlled capability identifiers remain separate from
KEM, KDF, and AEAD selection.

> **Status:** pre-1.0 and not independently audited. Version `0.4.0` is
> published on crates.io.

## Quick start

The `negotiated_tcp` example demonstrates an end-to-end negotiated
post-quantum secure channel between separate client and server roles connected
through a real loopback TCP socket.

Run it from the workspace root:

    cargo run -p pqc-rs-secure-channel --example negotiated_tcp

A successful run reports:

    negotiated secure channel over loopback TCP: pass
    selected capability: 0x0101
    request authenticated and decrypted: pass
    response authenticated and decrypted: pass

The example performs the following workflow:

    Client                                      Server
    ------                                      ------

    capability offer -------------------------->

                               validate offer against local policy
                               select registered capability

                        <---------------- capability selection

    validate selection
    retain negotiated evidence                  retain negotiated evidence
            |                                             |
            v                                             v
    resolve closed HPKE profile                  resolve closed HPKE profile
            |                                             |
            +---------- activate channels ----------------+
            |                                             |
    encrypted request -------------------------->

                        <--------------- encrypted response

The current example selects the registered ML-KEM-768 HPKE capability. The
same secure-channel resolution boundary also supports other registered
profiles without allowing the peer to directly select arbitrary KEM, KDF, or
AEAD identifiers.

## Architecture

The PQC-Forge secure-channel path is:

    capability offer
        ->
    capability negotiation
        ->
    validated negotiation evidence
        ->
    cryptographic profile resolution
        ->
    secure-channel binding
        ->
    sender / receiver activation
        ->
    protected application traffic

This separation is intentional.

`pqc-rs-protocol` handles protocol identifiers, capability negotiation,
framing, state transitions, and policy evidence without embedding concrete
cryptographic implementations.

`pqc-rs-secure-channel` resolves validated capabilities into a closed set of
implementation-defined HPKE profiles and binds the resulting cryptographic
state to the established protocol context.

`pqc-rs-hpke` performs the underlying HPKE and KEM operations.

Consequently, a peer-provided capability identifier is not interpreted as a
raw KEM, KDF, or AEAD identifier.

## Registered profiles

The current secure-channel registry includes profiles using:

- ML-KEM-768;
- ML-KEM-1024;
- ML-KEM-768 with ChaCha20-Poly1305;
- the ML-KEM-768 + X25519 hybrid KEM.

The concrete KDF and AEAD combinations are defined by the secure-channel
profile registry rather than supplied independently by a peer.

## Transport model

The `negotiated_tcp` example uses simple length-prefixed records over loopback
TCP so that the application-facing cryptographic workflow remains easy to
follow.

The evaluation suite exercises the transport layer more aggressively. It
includes framed byte-stream transport, partial progress, loopback TCP, and
deterministic retryable `Pending` and `Interrupted` schedules.

Transport behavior and cryptographic profile resolution are separate
concerns: the secure-channel binding and activation model does not depend on
TCP specifically.

## Runtime expectations

The current secure-channel integration is `std`-oriented. This crate should
not be interpreted as providing a workspace-wide `no_std` guarantee.

## Security

The secure-channel API is designed around validated negotiation evidence and
closed cryptographic profiles. Applications should not treat unvalidated
peer-controlled identifiers as cryptographic configuration.

PQC-rs and PQC-Forge are pre-1.0 and have not undergone an independent
security audit. The repository's conformance, interoperability, negative-test,
fuzzing, timing, zeroization, and reproducibility results are engineering
evidence rather than a formal proof or certification.

See the repository evaluation and assurance documentation for the tested
scope, limitations, and reproducibility material.

## License

MIT
