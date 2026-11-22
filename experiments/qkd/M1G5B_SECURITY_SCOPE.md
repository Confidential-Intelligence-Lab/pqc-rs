# M1.G5.B — Authenticated public discussion (experimental primitive)

This increment adds a **synthetic**, session-bound authenticated BB84 classical-message state machine. It does not yet bind the actual G5.A CUDA-Q measurement record to authenticated basis announcements. The existing quota simulator returns aggregate counts only, so this module cannot truthfully assert `basis_announcement_authenticated=true` for G5.A.

## Implemented

- Domain-separated HMAC-SHA256 tags over canonical JSON messages.
- Per-message sender role, session identifier, global sequence, and chained transcript digest.
- Ordered public messages for Alice/Bob basis lists, quota summary, X-sample selection, error statistics, and final decision.
- Authenticated abort messages and state-machine termination.
- Rejection tests for tampering, replay, reordered messages, cross-session attempts, wrong keys, inconsistently sized bases, malformed sample selection, and incomplete protocol state.
- No raw secret bits are transmitted; no key material is printed or exported.

## Explicit limitations

- Synthetic example uses fixed demonstrative MAC key and session ID: NOT independently secret/provisioned.
- HMAC authentication protects message integrity only if a secret MAC key is independently established and roles/session IDs are provisioned correctly. A full key-management and composable authentication analysis is not supplied.
- A message chain and local phase tracking cannot make an absent peer or missing network messages arrive. Application timeout/termination, bidirectional final transcript-hash confirmation, and reliable abort delivery require separate design.
- The message schema does not yet provide real raw-basis provenance, random authenticated X-sample selection, secure randomness, quantum device assumptions, or phase-error theorem conformance.
- No security-qualified QKD key is produced. `SECURITY_MODEL_VALIDATED=false`, `SECURITY_QUALIFIED=false`, and `HPKE_EXPORT_AUTHORIZED=false`.
- Confirmed delivered messages alone do not prove that a public announcement corresponds to what the sender actually measured; active malicious participants and device compromise are out of scope.

## Next integration

G5.C should preserve per-transmission basis metadata from the CUDA-Q simulation in a private session record; generate public authenticated basis announcements from each party's record; compute matched-basis quotas from received announcements; derive public parameter-estimation evidence and independently verify error counts. An independently seeded selection procedure, secret randomness assumptions, and the chosen finite-key theorem's precise sampling/stopping rules remain necessary.
