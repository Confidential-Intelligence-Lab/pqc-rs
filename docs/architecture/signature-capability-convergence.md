# Signature Capability Convergence

## Finding

During evaluation of cryptographic agility, PQC-rs was found to expose
`pqc_core::SignatureScheme` without concrete implementations for either
ML-DSA or SLH-DSA.

The original trait also modeled key generation, signing, and verification as
static operations, whereas the publication-facing ML-DSA and SLH-DSA APIs
bind an implementation instance to a selected parameter set.

This was an architectural integration inconsistency, not a defect in the
FIPS 204 or FIPS 205 cryptographic computations.

## Existing capabilities

Before the repair, both standardized signature implementations already
provided:

- parameter-bound public keys;
- parameter-bound private keys;
- parameter-bound signatures;
- caller-supplied RNG key generation;
- deterministic signing;
- hedged signing;
- context-bound signature verification;
- deterministic provisioning interfaces.

The missing element was convergence on the workspace-wide signature
capability.

## Resolution

`SignatureScheme` was changed from a static interface to an
instance-oriented interface by adding `&self` receivers.

This matches the parameter-bound object model used by `MlDsa` and `SlhDsa`
and allows both implementations to satisfy the same application-facing
capability without discarding their concrete parameter-set state.

Both `MlDsa` and `SlhDsa` now implement `SignatureScheme`.

The trait uses the RNG-backed operational path:

- key generation maps to the concrete `keygen` operation;
- signing maps to the concrete hedged-signing operation;
- verification maps a valid signature to `Ok(())` and an invalid signature
  to `PqcError::VerificationFailed`.

Deterministic provisioning and deterministic signing remain explicit
algorithm APIs. They are intentionally not hidden behind the generic
operational interface.

## Error boundary

The convergence exercise also exposed insufficient precision in the common
error taxonomy.

The workspace-wide `PqcError` taxonomy was therefore extended with:

- `ParameterSetMismatch`;
- `InvalidInput`;
- `InternalError`.

This avoids incorrectly classifying a well-formed object for the wrong
parameter set as malformed encoding and avoids using protocol-specific
failure categories for internal primitive failures.

Concrete algorithm APIs continue to expose their richer algorithm-specific
error types. The common signature capability maps those errors into stable
cross-algorithm failure classes.

## Assurance implications

This repair changes the composition and API boundary, not the underlying
ML-DSA or SLH-DSA cryptographic computations.

The relevant formatting, compilation, Clippy, API, unit, integration,
feature, architectural, and performance checks must therefore be repeated
after the repair.

The evaluation should subsequently exercise the same generic
`SignatureScheme` application workflow with both standardized signature
families.

## Engineering lesson

Declaring an algorithm-independent abstraction does not itself establish
cryptographic agility. The abstraction must be implemented by multiple
concrete algorithms and exercised through application-level workflows.

In this case, architectural evaluation exposed a latent mismatch that
algorithm-level conformance testing could not detect.
