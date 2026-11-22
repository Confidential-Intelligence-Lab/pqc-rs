# S5.D-4 — Bounded adaptive Cascade under the S3.C transcript

**Disposition: research-only engineering correspondence; conditional security NOT proved.**

## What is integrated

- S3.C recognizes `s5d4-cascade-v1` with an independently instantiated Alice state and Bob state, bound to the same authenticated profile fingerprint, key ID, session ID and maximum parity-pair count.
- A signed profile proposal and acknowledgment precede parity queries. Each parity query uses two S3.C role-specific frames, followed by an explicit authenticated finish, finish acknowledgment and commit.
- Each direction verifies MAC, profile/session binding, ordered sequence, transcript digest and sender role. The receiver aborts on forged, replayed, skipped or out-of-order messages.
- An adaptive S3.C schedule enforces at most 4,800 parity pairs and **9,605 outer frames** (2 profile messages, 9,600 parity messages, 3 completion messages). S3.C's existing fixed schedules remain unchanged.
- The worst-case **parity disclosure** charged by the experimental profile is 9,600 bits (two parity bits per pair). A 64-bit independent legacy confirmation tag is reported separately.
- The numerical TLGR 2012 Eq. (2) candidate is approximately 457 bits, for a requested 256-bit experimental extraction, **assuming theorem applicability and the declared disclosure model**. No key material leaves this interface.

## Known limitations to be addressed before security approval

1. Although S3.C maintains two authenticated endpoints, the Cascade engine still runs inside a **single-process reference orchestrator**. Its Bob parity input comes from the algorithm's internal corrected Bob state; the S3.C adapter does *not* yet run a genuinely independent Bob-side correction engine. Both execution and peer-isolation claims must remain false.
2. Independent key confirmation occurs within the existing local S5.D-2 routine and not through an S3.C confirmation exchange. The signed finish states its outcome; it does not establish an end-to-end standalone two-party confirmation proof.
3. S3.D's existing 1,024-outer-frame budget and durable single-use-root registry are **not integrated** with the new adaptive schedule. The new protocol counts up to 9,605 frames but does not provide or claim a complete computational HMAC advantage reduction.
4. The full public transcript (query choices, ordering, branch paths, abort behavior, authentication tags and timing) must be considered when proving a composable leakage bound; merely charging two parity bits per query is a conservative *candidate*, not a complete quantum-security argument.
5. The TLGR theorem's supplementary hypotheses, generalized-Eve quantum coupling under a public transmission cap, and the relationship to adaptive Cascade leakage remain unresolved.
6. The public permutation seed is precommitted but the use of Python `random.Random` to expand it does not establish a proven cryptographic public-uniform permutation family.
7. The externally provisioned shared root is assumed. No source attestation, distributed transport, rollback resistance, production key derivation or HPKE export is provided.

## Required next work

- Implement independently executed Bob-side Cascade correction and a message transport that never combines both peers' private states.
- Bind the final universal-hash confirmation to authenticated S3.C messages and integrate S3.D single-use-root provisioning with a rigorously justified extended frame budget.
- Prove the complete leakage bound and exact theorem hypotheses or adopt a published proof-matched reconciliation protocol.
- Obtain independent security review and record any conditional research-security disposition under the ETSI GS QKD 005 methodology; never imply production certification.

**Security gates:** `conditional_security_supported=false`; `security_model_validated=false`; `security_qualified=false`; `qkd_psk_available=false`; `hpke_export_authorized=false`.
