# M1.H2 — Authenticated theorem-oriented selection and parameter estimation

This experimental Python module binds X-basis key index selection and Z-basis test index selection to the authenticated G5.B basis transcript. It uses actual per-party BB84 simulation records from G5.C1 and authenticates each party's Z test-bit disclosures. Both peers' disclosed Z bits are checked and the observed error count is independently recalculated. No X key bit value is transmitted by these messages.

The existing G5.B message state machine only supports X-oriented `sample_selection`; H2 therefore uses an explicitly domain-separated, HMAC-authenticated, sequence-numbered, transcript-hash-chained extension after the first three genuine G5.B basis/quota messages, without falsely completing G5.B's original synthetic workflow. Peer identity and the basis transcript hash are bound to these extension frames. This is a simulation of authenticated public communication, not validated real-world key provisioning or formal transport security.

## Explicit limitations

- The CUDA-Q source bits and bases are generated from a publicly reproducible PRNG. A caller-selected deterministic sampling seed is likewise **not secret**. A `None` seed selects system randomness for demonstration but does not validate the complete protocol randomness model.
- G5.C1 collects matched-basis populations until quotas are filled. H2 randomly selects from these available populations but the quota/stopping process and the resulting selection distribution have **not** been proven equivalent to the cited Box 1 protocol.
- This H2 test uses the published X-key/Z-test orientation, but is **not** a complete theorem-conforming implementation.
- Authentication key provisioning, independent physical source assumptions, reconciliation, composable correctness/PA proof, and QKD-to-HPKE composition remain unvalidated.
- The numerical Tomamichel bound uses an explicitly configured tolerance and **provisional** reconciliation leakage. It is not self-certifying evidence; a positive result is never a security claim.
- Z test sample bit values are intentionally public and therefore included in the transcript; no X raw-key bit values are transmitted. No key bytes are printed or exported.
- All security, physical-qualification, and HPKE export flags remain false. Bibliography and related-work notes are maintained in the research chat, **not committed to this repository**.
