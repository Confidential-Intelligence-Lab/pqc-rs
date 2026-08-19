# pqc-rs-authentication

`pqc-rs-authentication` is a **PQC-Forge** integration layer for negotiated
post-quantum challenge-response authentication.

It consumes established `pqc-rs-protocol` context containing validated
capability-negotiation evidence and resolves registered authentication
capabilities into closed local cryptographic profiles. The initial realization
uses ML-DSA-65.

> **Status:** pre-1.0, experimental, and not independently audited. The crate
> is currently workspace-only while its integration API is evaluated.

## Architecture

```text
pqc-rs-protocol
      |
      | validated negotiation evidence
      v
pqc-rs-authentication
      |
      | local authentication profile
      | challenge and context binding
      | proof generation / verification
      v
pqc-rs-ml-dsa
```

The protocol layer owns capability identity, negotiation, policy, and
established protocol state. The authentication layer owns local profile
resolution, canonical transcript construction, challenge binding, ML-DSA proof
generation and verification, and the verifier-side single-use challenge
workflow.

It does not depend on `pqc-rs-secure-channel`, `pqc-rs-hpke`, or
`pqc-rs-ml-kem`.

## Quick start

From the workspace root:

```bash
cargo run -p pqc-rs-authentication --example challenge_response
```

The example performs:

```text
capability negotiation
        |
        v
validated protocol context
        |
        v
ML-DSA-65 profile resolution
        |
        v
fresh verifier challenge
        |
        v
context-bound authentication proof
        |
        v
single-use verification
```

A successful run includes:

```text
negotiated capability: 0x0201
resolved authentication profile: MlDsa65
verifier issued fresh challenge
prover generated ML-DSA-65 authentication proof
authentication succeeded
```

## Binding model

The canonical authentication transcript binds:

- the protocol session;
- protocol identifier and version;
- negotiated policy;
- negotiated authentication capability;
- verifier challenge;
- application context.

Changing any bound value invalidates the proof.

The verifier consumes a pending challenge on a verification attempt, providing
a single-use challenge lifecycle within one verifier instance. Distributed
deployments require an application-level shared challenge-consumption
mechanism.

## Identity boundary

Successful verification demonstrates possession of the private key
corresponding to the public key configured by the verifier. Mapping that key
to a human, device, account, service, certificate, or other identity remains
application policy; this crate defines neither a credential format nor a
public-key infrastructure.

## Security

PQC-rs and PQC-Forge are pre-1.0 and have not undergone an independent
security audit. Repository conformance, interoperability, negative testing,
fuzzing, timing, zeroization, and reproducibility results are engineering
evidence rather than formal proof or certification.

## License

MIT
