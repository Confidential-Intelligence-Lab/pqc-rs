# S5.E — QKD research-security disposition

**Decision date:** 2026-11-21
**Repository:** `Confidential-Intelligence-Lab/pqc-rs`
**Branch:** `research/qkd-security-qst1`
**Assessed revision:** `5cf8de321d705c5422e1cd39966abdeef55586f3`
**Disposition:** **RESEARCH_IMPLEMENTATION_VALIDATED; CONDITIONAL_SECURITY_NOT_SUPPORTED**
**Scope:** Idealized BB84/CUDA-Q and classical postprocessing research simulation, not a physical QKD product or distributed deployment.

## Executive decision

The functional security-engineering baseline is validated at the level demonstrated by its tests and code reviews: 504/504 QKD unit tests reportedly passed on EdgeExpert; S5.D-5 implements a bounded, authenticated **single-process** two-role simulation with a single-use credential registry, adaptive Cascade-style parity exchange and authenticated confirmation. These are engineering observations only.

**Do not approve conditional composable QKD secrecy, assign an achieved total security epsilon, classify the extracted output as a quantum-secure key, authorize HPKE export, or issue a hardware/product certification.** There are unresolved theorem-to-protocol and computational-authentication obligations. Successful numerical evaluation is not a proof of those obligations.

## Verified source evidence

- GitHub commit: https://github.com/Confidential-Intelligence-Lab/pqc-rs/commit/5cf8de321d705c5422e1cd39966abdeef55586f3
- `experiments/qkd/s5c_research_profile.py`: frozen numerical profile and explicit nonqualification flags.
- `experiments/qkd/s5d2_cascade_reconciliation.py`: adaptive single-process Cascade correction and inner local confirmation; parity exchanges are generated using both parties' local state.
- `experiments/qkd/s5d3_bounded_cascade.py`: 4,800-query local cap and frozen research profile.
- `experiments/qkd/s3c_authenticated_transcript.py`: authenticated session-bound sequencing, role checks, and adaptive S5.D-5 schedule.
- `experiments/qkd/s5d4_s3c_cascade.py`: S3.C parity exchanges, peer confirmation; Bob's correction remains with the single-process reference engine.
- `experiments/qkd/s5d5_peer_confirmation.py`: local one-use credential marker, explicit max frame contract, no key export.
- `experiments/qkd/security/S5D5_AUTHENTICATED_CONFIRMATION.md`: self-disclosed trust boundaries and accounting limits.
- Test evidence: user-provided EdgeExpert output reports 504 tests in 2.804 s, OK, exit code 0, `git diff --check` clean; test output has not been independently re-executed on EdgeExpert in this review.

## Finite-key numerical result — not a security statement

| Parameter | Frozen value / treatment |
|---|---|
| Matched X key bits, n | 16,384 |
| Minimum matched Z test bits, k | 16,384 |
| Maximum transmissions | 100,000; abort on unmet quotas |
| Nominal basis choice | 50% X / 50% Z |
| Z test tolerance | 2% |
| Secrecy epsilon target | 1e-10; not proved for actual adaptive protocol |
| Correctness epsilon target | 1e-10; requires full-protocol proof |
| Authentication epsilon target | 1e-12; no proved HMAC advantage |
| Total epsilon target | 1e-9; not achieved/established |
| Max parity query pairs | 4,800 |
| Max outer S3.C frames | 9,607 |
| Maximum parity answer disclosures charged | 9,600 bits (2 per pair) |
| Confirmation tags charged | 128 bits (legacy local + peer) |
| Numerical `leak_EC` input used in S5.D-5 | 9,728 bits |
| Equation-derived candidate | approximately 329 bits |
| Requested output | 256 bits; **not an approved secret key length** |

**Critical caveat:** 9,728 is a count of charged answer/tag bits, not a verified upper bound on the information revealed by the *complete adaptive public transcript*. Public index sets, selection, adaptive control flow, stopping length, abort behavior, and other public content require a formal chain-rule or protocol-specific argument. S3.C MACs authenticate messages; they do not prove secrecy or eliminate information leakage.

## Standards and theorem correspondence

**Primary methodology — ETSI GS QKD 005 V1.1.1, clauses 4.3 and 4.7.** A QKD security statement needs both a scientific security proof for the device/protocol model and verification that the implementation conforms to that model. Clause 4.7.7 expressly cautions against citing a one-way error-correction proof for a two-way protocol such as Cascade without a proof applying to the implementation; it also highlights unaccounted public locations and additional information leakage. This is a **review obligation**, not a categorical claim that all finite-key analyses prohibit Cascade.

**Theorem candidate — Tomamichel, Lim, Gisin, Renner (2012), Box 1, Eq. (2).** Published reference protocol selects matched X raw-key bits, tests matched Z outcomes, performs bounded-leakage correction and universal-hash confirmation, then applies privacy amplification. Numerical equality to Eq. (2) does not establish the hypotheses of that theorem for the implemented adaptive dialogue. The paper's supplementary proof has **not been reviewed in full** in this assessment. No line-by-line correspondence to its accepted/aborted classical-quantum state has been established.

**Secondary evaluation reference — ETSI GS QKD 016 V2.1.1, FCS_QKD.1.** Expects a composed security proof for the protocol, including abort semantics and random/shared/confidential output conditions; this experiment has no physical module being certified.

## Findings and decision register

| ID | Finding | Assessment | Blocking conditional security? |
|---|---|---|---|
| S5E-01 | Functional tests, limits, authenticated sequencing and tamper failures | Supported by reported regression and inspected code | No, for *research engineering* only |
| S5E-02 | Ideal-device/source correspondence under a general quantum adversary | Model assumed, not independently demonstrated | **Yes** |
| S5E-03 | TLGR source, stopping rule, overshooting Z test, hard 100,000-transmission cap, abort-conditioned state | Precise proof correspondence not established | **Yes** |
| S5E-04 | Cascade two-way adaptive transcript and all public leakage, including index/length/control information | Upper bound not proven by 2 bits per parity pair alone | **Yes** |
| S5E-05 | Confirmation correctness and double-tag treatment | Authenticated peer confirmation tested; complete correctness/security reduction not established | **Yes** |
| S5E-06 | Quantum-proof Toeplitz privacy amplification integrated with the actual final postprocessed state | Primitive exists; end-to-end leftover-hash theorem instantiation unproved | **Yes** |
| S5E-07 | Computational HMAC KDF/MAC advantage for up to 9,607 outer frames plus inner authenticated frames and all sessions | Frame count is a resource limit, not an epsilon_auth bound | **Yes** |
| S5E-08 | External root provisioning, anti-rollback, genuinely independent parties and transports | Explicitly simulated or assumed; no deployment verification | **Yes** for deployment claims |
| S5E-09 | QKD-derived HPKE key release | Explicitly disabled; no security evidence to permit | **Yes** |

## Essential separation of claims

1. **Engineering conformance supported:** bounded and authenticated *local simulated* dialogue, reported tests, explicit failures, no key exposure in public reports.
2. **Research profile numerically aligned:** published-style finite-key parameters and candidate margin *under stated numerical assumptions*.
3. **Conditional secrecy not supported:** a formal reduction to a theorem covering the full actual protocol is outstanding.
4. **Product/physical certification and HPKE export excluded:** a quantum circuit simulator, even with idealized source checks, cannot certify an implemented quantum channel or authenticated distributed QKD equipment.

## Release gate / continuation criterion

Do **not** add more engineering phases merely to increase test counts. Reconsider the blocked research-security claim only when these independent deliverables exist:

1. **Proof selection and instantiation:** cite an actual composable finite-key statement accepting the precise two-way reconciliation, or write an independent theorem/proof showing that the classical transcript's *entire* leakage can be conservatively bounded and inserted into a suitable quantum min-entropy chain rule. Review TLGR supplementary proof and reconcile public caps/abort conditioning and sample-size treatment.
2. **Authenticated protocol reduction:** specify MAC adversary (including quantum-query assumptions as applicable), multi-message KDF/HMAC model, independent root provisioning and session freshness; bound all outer and inner message forgery probabilities and composition. Do not present `1e-12` as achieved absent that evidence.
3. **End-to-end specification:** provide Alice/Bob-local algorithm/state transitions, complete publicly revealed transcript, universal-hash seed independence, postprocessing leakage, correctness failure and accepted/aborted key states; independent review of the proof-to-source mapping.

Only after those criteria are met should `conditional_security_supported` be reconsidered. `security_qualified`, `qkd_psk_available`, `hpke_export_authorized`, and `production_handoff_permitted` remain `false` regardless, unless separately authorized by an appropriate production-evaluation process.

## Decision record

- `research_implementation_validated`: **true** (limited to observed research tests / source audit)
- `research_profile_numerical_fitness`: **true** (candidate only)
- `research_profile_cryptographic_security_proven`: **false**
- `complete_postprocessing_leakage_proven`: **false**
- `quantum_abort_cap_theorem_correspondence_proven`: **false**
- `authentication_advantage_proven`: **false**
- `conditional_security_supported`: **false**
- `security_model_validated`: **false**
- `security_qualified`: **false**
- `qkd_psk_available`: **false**
- `hpke_export_authorized`: **false**
- `production_handoff_permitted`: **false**

## References

1. M. Tomamichel et al., *Tight finite-key analysis for quantum cryptography*, Nature Communications 3, 634 (2012), https://doi.org/10.1038/ncomms1631 — Box 1, Eq. (2), and proof sketch. Supplementary Notes S1–S2 **not fully reviewed**.
2. ETSI GS QKD 005 V1.1.1 (2010-12), *Quantum Key Distribution (QKD); Security Proofs*, clauses 4.3, 4.7 and especially 4.7.7: https://www.etsi.org/deliver/etsi_gs/QKD/001_099/005/01.01.01_60/gs_QKD005v010101p.pdf
3. ETSI GS QKD 016 V2.1.1 (2024-01), *Common Criteria Protection Profile — Pair of Prepare and Measure QKD Modules*, FCS_QKD.1: https://www.etsi.org/deliver/etsi_gs/QKD/001_099/016/02.01.01_60/gs_QKD016v020101p.pdf
