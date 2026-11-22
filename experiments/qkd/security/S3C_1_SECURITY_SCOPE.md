# S3.C-1: authenticated transcript reference model (unqualified)

QST-1 baseline: PR #60 merge commit `7b3a6d74ccbbff9472657e67cc6bebcb4f93c296`.

This increment adds an **additive**, CPU-only reference authenticated session with a single
monotonically advancing global transcript digest and a frozen two-party event schedule.
Each frame binds protocol, profile, version, endpoint identities, key identifier,
session identifier, stage, direction, sequence, preceding transcript digest and
canonical public payload. Frames are HMAC-SHA256 authenticated under a session-
and context-derived key. Any incoming invalid frame terminates its receiver.

The 14-event schedule is a **minimal conformance fixture**, not the complete
production-like H2/S2.A2 dialogue. The actual interactive reconciliation and
parameter-estimation exchanges have not been wired to this implementation.
Callers must provide only public protocol payloads: this model does not
recognize or prevent raw-key bytes embedded in arbitrary payloads.

## Explicit limitations and blockers

- No independently verified credential provisioning, shared persistent session
  registry integration, root provenance, quantified MAC advantage, source proof,
  quantum min-entropy, or verified key-distribution theorem.
- No claimed protection against dropped network frames beyond nonprogress and
  fail-closed local timeout/abort managed by the caller. Neither timeout nor
  authenticated abort messages are implemented in this first increment.
- The schedule is fixed at one public frame per role per stage. S3.C-2 must
  freeze actual application message types and counts, then replace this fixture
  with a formally reviewed transcript state machine for real H2/S2.A2/M2.A.
- A local process restart creates a new model session. No durable replay defense
  is claimed here; the existing S3.B registry remains a separate feature.
- Python bytearray overwrite does not establish secure erasure.
- A passing test suite demonstrates model conformance only, not QKD security.

`security_model_validated=false`, `security_qualified=false`, and
`hpke_export_authorized=false` remain mandatory.

## Next step

Derive a concrete per-message stage schedule from H2 and S2.A2; connect the
S3.B provisioned credential/registry boundary to a single transcript state
machine; add transcript alignment checks to real M2.A run results; preserve
fail-closed production handoff. Add keyed adversarial/role-direction mutation
tests and unqualified evidence markers; then run complete repository CI.
