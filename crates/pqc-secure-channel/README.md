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

## HPKE authorization and continued use

This development branch adds guarded HPKE activation and continued-use
wrappers. The protocol crate maintains revision-aware authorization state;
the secure-channel layer checks that state before selected HPKE operations.
The guarded APIs support denying activation, `seal`, or `open` when current
assessments do not authorize the requested operation. Unauthorized message
attempts are tested to ensure they do not advance the corresponding HPKE
message sequence state.

Using an *unguarded* HPKE context does **not** implicitly enable this policy
check. Evidence and policy changes must be provided through the application
integration; the code does not independently authenticate those updates or
automatically migrate or rekey a channel.

### Sources and integration tests

| Component | File | What it exercises |
|---|---|---|
| Activation wrapper | [`guarded_activation.rs`](src/guarded_activation.rs) | Authorization before HPKE setup |
| Continued-use wrapper | [`continued_use.rs`](src/continued_use.rs) | Authorization before message processing |
| Activation tests | [`tests/guarded_activation.rs`](tests/guarded_activation.rs) | Denial before encapsulation/decapsulation and a permitted round trip |
| Continued-use tests | [`tests/continued_use.rs`](tests/continued_use.rs) | Withdrawal, sender/receiver blocking, sequence preservation, and recovery |
| State-change tests | [`tests/continued_use_evaluation.rs`](tests/continued_use_evaluation.rs) | Simultaneous updates, concurrent evidence changes, and guarded-vs-baseline behavior |
| Comparative tests | [`tests/transition_comparison.rs`](tests/transition_comparison.rs) | State-change comparison and profile mismatch |
| Local benchmarks | [`continued_use_cost.rs`](benches/continued_use_cost.rs), [`transition_gate_cost.rs`](benches/transition_gate_cost.rs) | Optional guarded-operation and activation overhead measurements |

Run the relevant integration tests from the workspace root:

```bash
cargo test -p pqc-rs-secure-channel
cargo test -p pqc-rs-secure-channel --test guarded_activation
cargo test -p pqc-rs-secure-channel --test continued_use
cargo test -p pqc-rs-secure-channel --test continued_use_evaluation
cargo test -p pqc-rs-secure-channel --test transition_comparison

# Optional local performance measurements.
cargo bench -p pqc-rs-secure-channel --bench transition_gate_cost
cargo bench -p pqc-rs-secure-channel --bench continued_use_cost
```

The tests establish behavior for the supplied state-change schedules and
conditions; they do not establish that all possible concurrent interleavings
or malicious environments have been covered.

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
