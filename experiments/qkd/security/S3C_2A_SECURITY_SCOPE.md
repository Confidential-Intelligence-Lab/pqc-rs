# S3.C-2a: authenticated H2 transport integration (unqualified)

S3.C-2a routes the **actual public wire messages** emitted by the existing H2
basis announcement, quota, X selection, Z disclosure and estimation procedure
through a paired, globally ordered S3.C authenticated transcript. The receiver
must verify the S3.C frame before the original H2 receiver processes the
original public bytes and legacy MAC. The transport uses an explicit success or
quota-abort schedule bound to the frame context. An entire H2 transcript must
close with identical Alice/Bob transcript digests to proceed.

This is a **transitional double-authentication envelope**: existing H2
authentication is retained for compatibility while S3.C adds independently
maintained sender and receiver states and authenticates delivery of the bytes
that the real H2 implementation consumes. It does not yet provide a fully
unified transcript across reconciliation, confirmation and privacy amplification.
Those are S3.C-2b/2c tasks. The quota schedule is selected from the simulator's
locally held Alice and Bob measurement records; this is a trusted simulation
orchestrator, not a distributed network endpoint.

S3.C-2a does NOT attest the authentication root, prove a composable MAC bound,
prove the quantum source model, establish conditional min-entropy, qualify QKD
keys, or implement a production QKD key provider. The strict wrapper preserves
single-host persistent ID burn and refuses simulation-derived HPKE export.

Required flags remain false: `security_model_validated`,
`security_qualified`, `hpke_export_authorized`.

Evidence: run `test_s3c2a_h2_integration.py`, then the existing S3.A, S3.B,
S3.C-1 and H2/M2.A suites; record head SHA and exact results. CI must be green
before describing the increment as integrated.
