# M1.G4 — Independent arithmetic oracle and protocol-assumption audit

Reference: Tomamichel, Lim, Gisin, Renner, *Tight finite-key analysis for quantum cryptography*, Nature Communications 3, 634 (2012), DOI 10.1038/ncomms1631.

The independent `decimal` oracle is a **numerical cross-check** for the finite-size deviation and key-length arithmetic in Equation (2). It does not establish that the simulator implements protocol Phi or that its sources are secret. The two observed G3 mu values (0.4407711738132392 and 0.05108180401213586) match the oracle using epsilon_sec=1e-10 and the supplied block sizes. Complete cross-comparison of the key-length output requires the *exact* Q_tol, q, leak_EC, epsilon_cor inputs used by G3.

## Known blockers to theorem-specific protocol validation

- G2 runs a **fixed transmission count** rather than continuing until both matched-basis quotas are achieved.
- G2 basis announcements are **not authenticated**; the experiment retains aggregate basis counts, not an authenticated transcript.
- G2 and M1.F use **publicly reproducible Python PRNG seeds**, not private source bits/basis choices.
- The preparation-quality parameter q=1 describes ideal BB84 qubit states only; it must be a documented, enforced device-model assumption.
- E1 uses a pedagogical single-error-per-block reconciler and a truncated SHA-256 confirmation check. Confirm correctness accounting against the theorem's universal-hash correctness construction and avoid leakage double counting.
- G2 has no theorem-specific accept/abort threshold nor quota-based X/Z sample selection.
- G3 evaluates a published bound but **does not yet bind that bound to a validated protocol transcript**.
- The toolchain currently supports neither a proof of physical QKD device security nor qualified key export.

## Qualification status

`QKD_M1G4_NUMERICAL_ORACLE_STATUS` can become PASS without implying `SECURITY_MODEL_VALIDATED=true`. Maintain `SECURITY_MODEL_VALIDATED=false`, `SECURITY_QUALIFIED=false` and `HPKE_EXPORT_AUTHORIZED=false` until a separately reviewed M1.G5 gate.

The paper's exact protocol definition and supporting supplementary proof must be reviewed against the implemented state machine before that gate is considered.
