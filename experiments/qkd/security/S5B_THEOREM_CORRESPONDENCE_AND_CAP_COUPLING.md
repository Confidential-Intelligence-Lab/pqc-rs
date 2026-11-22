# S5.B: TLGR finite-key theorem correspondence and accepted-branch coupling

**Project:** PQC-rs goes Quantum
**Status:** SOURCE-GROUNDED ASSESSMENT; SECURITY THEOREM NOT ESTABLISHED
**Code baseline:** `94d687501797858ccf2ca0038e3da37df6f10378` (`research/qkd-security-qst1`)
**Reference:** M. Tomamichel, C. C. W. Lim, N. Gisin, R. Renner, *Tight finite-key analysis for quantum cryptography*, Nature Communications 3, 634 (2012), DOI 10.1038/ncomms1631. Main text: https://pmc.ncbi.nlm.nih.gov/articles/PMC3274703/
**Supplement identified:** `ncomms1631-s1.pdf` (Supplementary Notes S1–S2), at https://pmc.ncbi.nlm.nih.gov/articles/instance/3274703/bin/ncomms1631-s1.pdf . This PDF was **not retrievable during this increment** (PMC returned a browser verification barrier). It has therefore **not** been reviewed line by line, and we must not claim the theorem assumptions are completely audited.

## 1. The first substantive finding

In the published main text, Box 1 specifies a protocol family `Phi[n,k,ell,Q_tol,epsilon_cor,leak_EC]`: independent basis choices, matched-basis X and Z sets, **repetition until both X and Z quotas are met**, random selection of `n` X bits, and an error test across the **full matched Z set**. This is substantially closer to the present H2/S2.B2 behavior than an ordinary fixed-transmission, fixed-test-size BB84 design. However, the published security theorem's precise hypotheses, variables, conditioning and smoothing conventions still require an audit of the supplementary proof.

References: main text, section “Protocol definition”, Box 1; section “Security analysis”; supplementary Notes S1–S2 as yet unreviewed.

## 2. Implementation correspondence matrix

| TLGR Box 1 requirement | Current implementation path | Status |
|---|---|---|
| Prepared ideal BB84 states | `bb84_cudaq.prepare_and_measure`; S4.F structural audit; S4.G measured results | Simulation evidence only, no device certification |
| Alice/Bob basis probability | `m1h3a_randomness._basis`, fed by S4.F `ProofProfile` | OS-backed choice; finite 53-bit threshold discretization; no information-theoretic independence proof |
| Both matched-basis quotas required | `m1h3a_randomness.simulate_records` and `s2b2_strict_theorem_reference.assess_prefix` | Classical first-hit correspondence checked |
| Random X subset size `n` | `m1h2_authenticated_sampling.run_records`, `SystemRandom().sample` | Source-level implementation; no general-Eve sampling proof |
| Full matched Z sample, not random subset | `chosen_z=list(az)` in H2 | Source-level correspondence checked |
| Error-rate abort at precommitted tolerance | H2 `checked_errors/actual_z_test_size <= q_tolerance` | Source-level correspondence; subtle accepted-branch conditioning |
| Bounded error correction | `s2a2_syndrome_reconciliation`, 32 syndrome bits/128-bit block | Finite public-disclosure ledger; scheme-specific proof outstanding |
| Universal-2 correctness test | `s2a1_universal_confirmation` | Correctness reduction and seed assumptions outstanding |
| Universal-2 privacy amplification | `m1e2_privacy_amplification` and authenticated PA proposal | Toeplitz-family/quantum leftover-hash proof outstanding; no qualified extraction |
| Authenticated channel | S3.C/S3.D HMAC and assumed root | Computational assumption; complete multi-frame reduction outstanding |

## 3. Public cap as an abort-filter reduction: a conditional lemma, NOT proved for this code

Consider an *uncapped* ideal authenticated-channel protocol U that is precisely the TLGR modeled protocol, with the first hitting time `tau` when both quota conditions hold. Construct a capped protocol C with publicly committed limit `M_max`. For a history that reaches quotas by `M_max`, C should have precisely the same quantum interactions and public transcript as U up to `tau`; for other histories, C emits public abort and never outputs key. If there exists a joint quantum/classical coupling in which:

1. Both executions have identical source inputs, Eve side-information evolution, basis randomness, and causal announcements until `min(tau,M_max)`;
2. Accepted histories are identical (including *all* public messages) whenever `tau <= M_max`;
3. The cap is a public precommitted policy and is not allowed to change Eve's attack in the comparator in a manner unaccounted for by the proof;
4. Aborted histories produce no private output, with the same public accept/abort bit in real and ideal worlds;
5. The selected theorem already bounds the original *subnormalized* accepted branch under the relevant quantum adversary;

then applying the **same public abort filter** `F=1[tau <= M_max]` in the real and ideal states cannot increase their subnormalized trace-distance difference (contractivity). This is a proof *template*. The finite-prefix source checker only shows the **classical record-prefix property**, not conditions 1, 3, 4, or 5. In particular, an active adversary can learn of the public cap and alter its quantum attack, and causal scheduling/basis announcement timing must match the theorem's adversary model.

Do **not** divide an unnormalized distance by the acceptance probability without an explicit conversion. A successful public abort filter preserves a subnormalized security bound; it does not certify a small secrecy distance *conditioned on acceptance*.

## 4. `k_min` vs. observed matched-Z count `k_actual`

The protocol precommits `k_min`, while all eligible matched Z observations are disclosed. If the X quota is met last, matched-Z can significantly exceed `k_min`. The H2 source currently has two numerical `BoundInput` call sites: the initial one validates `k_test`, while the *final* call uses `actual_z_test_size` in the Eq. (2) numerical diagnostic.

This is **not by itself** a violation of the implemented protocol: Box 1 tests the complete matched-Z set. But it creates an inference gap. The published equation is parameterized by predeclared `k`; increasing `k` to a stopping-dependent `k_actual` changes the numerical bound. The program should not interpret the improved diagnostic as theorem-validated without a proof of the random-size substitution, or a conservative precommitted-`k_min` convention backed by a valid theorem argument.

**Decision:** Keep the existing H2 diagnostic untouched and unqualified for S5.B. Record both sizes explicitly with the checker. S5.C should evaluate proof-valid bounds after supplementary review; do not silently change formula inputs in this milestone.

## 5. Distinguish three different levels of evidence

**(A) Source and finite-trace evidence:** exact gates, random-subset API use, all matched Z disclosed, prefix check, cap enforcement, authenticated transcript. These can be supported by implementation and tests.

**(B) Mathematical correspondence:** exact quantum source/measurement/detection model, independent private basis randomness, delayed-measurement/memoryless assumptions, adversarial stopping/causality, seeded universality and correctness confirmation. These require source-specific definitions and proof.

**(C) Composable secrecy:** a lower bound on the appropriate smooth conditional min-entropy for the accepted classical-quantum state, with the *whole* public transcript and Eve included, followed by correctly parameterized privacy amplification and authentication reduction. This is not established by A or by eight-state CUDA-Q statistics.

## 6. S5.B acceptance decision and S5.C handoff

- **Completed:** published Box 1 main-text comparison; classical first-hit/cap witness; source guard for observed-Z numerical sample input; explicit nonauthorization and open-obligation ledger.
- **Not completed:** Supplementary Notes S1-S2 line-by-line audit (source unavailable); formal quantum coupling; a theorem-valid treatment of random `k_actual`; positive smooth conditional min-entropy; security-qualified key-length bound; real HMAC computational composition.
- **Recommended S5.C order:** (1) obtain and render supplement, (2) extract every theorem/lemma hypothesis with page/line locations, (3) write protocol trace correspondence including quantum channel attack timing and first-hit coupling, (4) settle `k_min`/`k_actual`, (5) instantiate min-entropy/leakage/extractor equations under exactly those assumptions, (6) independent expert review.

**Mandatory state:** `security_model_validated=false`, `security_qualified=false`, `hpke_export_authorized=false`, `qkd_psk_available=false`. No experimental or numerical output is QKD key-certification evidence.
