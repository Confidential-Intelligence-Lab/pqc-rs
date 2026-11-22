# S3.C-2b: reconciled-key confirmation in the shared authenticated transcript

**Status: experimental, not security qualified.** This increment binds the
actual S2.A2 syndrome frames and S2.A1 public universal-hash confirmation
message to the same globally ordered S3.C hash chain used by H2. It appends a
Bob acknowledgement and Alice commit before declaring the transcript closed.
The S3.C MAC is checked in an independently instantiated receiver state before
the original, still authenticated S2.A2/S2.A1 decoder consumes the delivered
public bytes. The old MACs remain temporarily for backwards compatibility.

The schedule is fixed and context-bound at session creation using the raw X-key
quota and 128-bit reconciliation block size. Unexpected extra, missing, stale,
reordered, cross-session or modified messages fail closed. The simulator's
orchestrator still holds both endpoints' private records and chooses the
schedule; no independent distributed implementation is asserted.

The confirmation seed is independently sampled after the reconciliation inputs
are fixed, and its frame is carried via S3.C. The acknowledgement reports
confirmation success, not cryptographic evidence of secrecy. Distinct endpoint
transcript digests must agree before diagnostic finite-key calculation proceeds.
The implementation's existing single-host session burn remains mandatory.

Not covered: privacy-amplification messages and final PA transcript closure
(S3.C-2c), source-model verification, authenticated credential provenance,
composable MAC accounting, entropy proof, independent implementation review,
secure hardware key custody, or authorized QKD-derived HPKE key export.

All QKD qualifications and production HPKE export flags remain **false**.
Do not substitute public status records or SHA-256 fingerprints for verified
quantum entropy or a trusted provider attestation.

Test evidence: `test_s3c2b_ec_integration.py` plus S3.A, S3.B, S3.C-1,
S3.C-2a, H2, S2.A2, S2.A3 regression suites. Record the target host, commit
SHA, exact counts, and command outputs before declaring this milestone done.
