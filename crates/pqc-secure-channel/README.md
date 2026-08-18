# pqc-rs-secure-channel

`pqc-rs-secure-channel` is the PQC-Forge integration layer that turns validated
PQC-rs protocol negotiation evidence into policy-bound HPKE secure channels.

It connects the generic protocol layer to concrete cryptographic profiles while
keeping peer-controlled capability identifiers separate from KEM, KDF, and
AEAD selection.

The current registered profile set includes pure post-quantum and hybrid
configurations built from ML-KEM, HPKE, X25519, AES-GCM, and
ChaCha20-Poly1305 components supported by PQC-rs.

## Secure-channel path

The integration path is:

```text
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
The evaluated PQC-Forge workflow also exercises client and server roles in
separate threads connected through real loopback TCP sockets. Framed transport
supports partial byte-stream progress, and the evaluation covers deterministic
retryable Pending and Interrupted transport conditions.

The TCP and adverse-schedule machinery are integration and evaluation
mechanisms. Cryptographic profile resolution and secure-channel activation
remain independent of the underlying transport.

Runtime expectations

The current secure-channel integration is std-oriented. It should not be
interpreted as a workspace-wide no_std guarantee.

Security

Capability identifiers select closed implementation-defined cryptographic
profiles. A peer does not directly provide arbitrary KEM, KDF, or AEAD
identifiers through the secure-channel API.

See the repository evaluation and assurance documentation for the tested threat
model, interoperability evidence, limitations, and reproducibility material.

License

MIT
