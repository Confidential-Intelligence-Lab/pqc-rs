# pqc-rs-authentication

`pqc-rs-authentication` is the PQC-Forge authentication integration layer.

It consumes established protocol context containing validated capability
negotiation evidence and resolves authentication capabilities into closed local
cryptographic profiles.

The initial profile is ML-DSA-65 challenge-response authentication.

## Architectural role

```text
pqc-rs-protocol
      |
      | validated negotiation evidence
      v
pqc-rs-authentication
      |
      | local authentication profile
      v
pqc-rs-ml-dsa
The protocol layer owns capability identity, negotiation, policy, and
established protocol state. This crate owns authentication-profile resolution
and, in later stages, authentication-specific challenge binding and proof
verification.

It does not depend on pqc-rs-secure-channel or pqc-rs-hpke.

The authentication work is experimental while its public API and application
model are being developed.
