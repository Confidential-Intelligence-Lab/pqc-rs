# S4.B — TLGR-2012 theorem-to-implementation correspondence

**Project:** PQC-rs goes Quantum
**Status:** RESEARCH REVIEW / UNQUALIFIED — no theorem instantiated
**Version:** 0.1 (2026-11-21)
**Implementation baseline:** `research/qkd-security-qst1`, `43ed32407ce5b3dd5b73cfd35e98046aa075e391`
**Parent:** `experiments/qkd/security/S4A_QUANTUM_SOURCE_ADVERSARY_MODEL.md`
**Candidate reference:** Tomamichel, Lim, Gisin, Renner (TLGR), *Tight finite-key analysis for quantum cryptography*, *Nature Communications* **3**, 634 (2012), Box 1, Methods, Supplementary Notes S1–S2. https://doi.org/10.1038/ncomms1631

## 1. Decision

**Do not instantiate TLGR finite-key theorem yet.** Box 1 shares a material protocol structure with the research implementation, but the proof's hypotheses and all proof-relevant public communication are not yet matched. In particular, the current program has a hard acquisition limit and quota-dependent selection, a lossless measurement model, an independently chosen authenticated-communication construction, and a finite-key evaluator that explicitly requires external min-entropy evidence. The overall source/model, leakage and smooth-entropy argument remain OPEN.

The *published Box 1* specifies repeated preparation/measurement/sifting until both matched-basis quotas are reached, a uniformly selected key-basis subset of size `n`, and error estimation over the matched test-basis set. These observations are structural alignment, **not** proof equivalence. The exact supplementary proof, and specifically the random sampling and acceptance-conditioned entropy lemmas, still require line-by-line review. The present document does **not** claim such a review has occurred.

## 2. Role and variable dictionary

| Paper object | Implemented object | Review note |
|---|---|---|
| `Phi[n,k,ell,Q_tol,epsilon_cor,leak_EC]` | `n_key`, `k_test`, `requested_key_bits`, `q_tolerance`, `confirmation_tag_bits`, S2.A2 leakage | Must account for theorem's full parameter meanings, not variable-name similarity |
| Key basis | matched `basis == 1` (X) | Validate circuit and paper's basis assignment; a basis relabeling requires explicit argument |
| Test basis | matched `basis == 0` (Z) | All eligible Z bits disclosed by H2 |
| `n` | selected `n_key` matched X events | Exact fixed-size X subset |
| `k` | observed `k_actual = len(all matched Z)` versus configured minimum `k_test` | `k_actual` can exceed `k_test` at stop; do not silently substitute |
| `M` | observed prefix length with cap `max_transmissions` | First hitting time and cap interaction are proof-relevant |
| QBER estimate | `z_test_errors / z_test_bits` | Diagnostic until finite-sampling theorem established |
| `leak_EC` | S2.A2 syndrome disclosure + proof-relevant additional public metadata | Need explicit ledger and correct classification of confirmation bits |
| Preparation overlap `q` | candidate ideal qubit model | Unmeasured/uncertified; must verify state-preparation gates and theorem definition |
| `epsilon_sec`, `epsilon_cor` | proposed S4/S5 budgets; `epsilon_pa`, `tag_bits` in code | Definitions and budgets not interchangeable |

## 3. Protocol correspondence matrix

Status codes: **STRUCTURAL** = directly visible in source and Box 1 at high level, **PARTIAL** = functionally present but proof assumptions differ or are missing, **OPEN** = cannot claim correspondence, **DEVIATION** = known protocol/model difference requiring explicit justification.

| ID | TLGR-2012 / proof requirement | Source evidence at baseline | Status | Proof or implementation action |
|---|---|---|---|---|
| T01 | Trusted quantum source with stated preparation-quality/overlap | `bb84_cudaq.py`, S4.A A-SRC-01 | OPEN | Audit exact circuit and formalize qubit states/overlap parameter |
| T02 | Trusted receiver and admissible detection/no-click policy | `m1h3a_randomness.py` produces a binary Bob result | PARTIAL | Prove lossless/no-erasure submodel admissible; separate from physical hardware |
| T03 | Private bit and basis choices with correct distribution | `m1h3a_randomness.py` OS and explicit deterministic fixtures | PARTIAL | Prove/assume independence, exclude fixtures, audit role-specific randomness |
| T04 | Both matched-basis quotas reached before accepted postprocessing | `s2b2_strict_theorem_reference.assess_prefix`; H2 | STRUCTURAL | Review basis-announcement timing and Eve's causal information |
| T05 | Stop on first jointly fulfilled quota | S2.B2 detects and rejects late post-stop events | PARTIAL | Confirm *strict production entry* enforces the same prefix rather than only reference wrapper |
| T06 | Finite `M_max` cap and abort if quotas unmet | `m1h3a_randomness.py`, S3.B/H2 | DEVIATION / OPEN | Prove that additional cap abort does not alter accepted-branch secrecy or postselection reduction; otherwise revise protocol |
| T07 | Uniform selection of exactly `n` matched key-basis positions | H2 `SystemRandom().sample` / separated sampling stream | STRUCTURAL | Prove random selection under source model; test without-replacement membership |
| T08 | Parameter estimation uses matched test-basis events | H2 `chosen_z = list(az)` | STRUCTURAL | Establish whether theorem `k` is quota or realized `k_actual`, including overshoot |
| T09 | Public test bits determine threshold abort | H2 authenticated disclosures and error summary | STRUCTURAL | Compare threshold inequality and accepted-event convention exactly |
| T10 | Authentication of full classical protocol with quantified failure | S3.C-2a/2b/2c MAC/digest chain | PARTIAL | Credential bootstrap; computational authentication bound; replay and aggregate-message accounting |
| T11 | Error correction achieves specified leakage budget | S2.A2 128-bit block syndromes; public matrix seeds | PARTIAL | Count public *key-dependent* leakage, test exact per-block budget and metadata |
| T12 | Independent universal-hash confirmation, with correctness bound | S2.A1; S2.A2 integration; `confirmation_tag_bits` | PARTIAL | Match `epsilon_cor` and public tag/seed accounting to theorem and smooth entropy definition |
| T13 | Independent universal-2 privacy amplification | `m1e2_privacy_amplification.py` Toeplitz; S3.C-2c public seed binding | PARTIAL | Prove exact family universality, seed independence, secrecy penalty and bit layout |
| T14 | General/coherent quantum Eve and quantum side information `E` | S4.A model; simulator only intercept/resend example | OPEN | Apply correct TLGR supplementary security proof; simulations cannot establish this |
| T15 | Finite-sampling bound on phase error / smooth max entropy | `m1g3_tomamichel_bound.py` numerical diagnostic | OPEN | Audit original Eq. (2), deviation `mu`, smoothing and postselection assumptions |
| T16 | Sound smooth conditional min-entropy lower bound | `m1e3_finite_key.py` requires external input | OPEN / BLOCKER | Produce reviewed theorem-to-protocol bound; never derive from QBER alone |
| T17 | Correctness/secrecy composition on accepted subnormalized branch | S4.A and QST-1 target definitions | OPEN | Define full joint state, acceptance, length register, epsilon budget |
| T18 | Non-export of unqualified simulation material | S3.B, M2.A, Rust HPKE handoff | IMPLEMENTED NEGATIVE GATE | Retain unconditional false flags and independent Rust regression |

## 4. Proof obligations in recommended order

**P1 — Quantum model.** Formalize the emitted BB84 density operators, the detector projectors, detection/loss assumptions and general Eve CPTP maps under the theorem's causal order. State idealized independence assumptions; *do not* cite CUDA-Q simulation as secrecy evidence.

**P2 — Stopping and conditioning.** Prove the accepted protocol's `tau = min{i : N_X(i)>=n and N_Z(i)>=k_min}` plus `tau<=M_max` has the required exchangeability and sampling properties. The theorem's Box 1 already stops by quota, but the hard cap and the conditioning it introduces need an explicit argument. Assess partial sequences and adversarial delays.

**P3 — Test sampling.** Fix whether the proof parameter `k` equals `k_actual`, is lower bounded by `k_min`, or requires an alternate worst-case inequality. Evaluate quota overshoot and randomly selected X subset. The correct proof parameter cannot be chosen after viewing a favorable result without a justification.

**P4 — Exact entropy bound.** Transcribe the final published theorem with epsilon and overlap conventions; verify all supplementary assumptions and independent numerical evaluation. Prove a statement of the form `H_min^{eps_s}(X|E,T_preEC,accept) >= h_lower(n,k_actual,Q_tol,q,eps_params)` with correct subnormalization and publicly revealed information. This is a *goal*, not an established inequality.

**P5 — Leakage and confirmation ledger.** Record syndrome bits, matrix seed, row/block index, public choices, confirmation seed/tag, public decisions and PA-seed information. Decide which information is independent of X and which contributes to conditional entropy chain rules; budget leakage conservatively until proved otherwise. Keep confirmation collision, smoothing, authentication forgery, and estimation failure distinct.

**P6 — Privacy amplification and composable output.** Check the actual Toeplitz hash is universal-2, with fresh independent public seed. Apply a quantum-proof leftover-hash lemma consistent with P4/P5. Derive an output-length inequality with an explicit `epsilon_sec`, `epsilon_cor`, and `epsilon_auth`, then document real/ideal resource behavior on abort.

**P7 — Composition type.** The current HMAC-SHA256 authentication is computational, not an information-theoretic authentication construction. A theorem assuming an ideal authenticated classical channel is not a proof of unconditional real-system QKD. State and quantify a hybrid/computational security claim or change authentication construction; independently assess key provisioning and multi-session reuse.

## 5. Concrete implementation observations

- `m1h3a_randomness.simulate_records` stops when *quota counters* reach their targets, but increments only while below quota. It may therefore hide additional matched events after one quota is filled from its counters. H2 separately collects all matched Z positions from the complete prefix. Distinguish the acquisition counter from actual `k_actual` in every report.
- `s2b2_strict_theorem_reference.assess_prefix` enforces first-hit conformance when invoked but is not proof that every S3.B entry point invokes that wrapper. Confirm strict call-graph enforcement explicitly.
- In `m1e3_finite_key.evaluate`, `pre_leak_min_entropy_bits` and `entropy_evidence_id` are mandatory for conditional length; the code subtracts syndrome/confirmation leakages and applies a leftover-hash numerical penalty. Its success result is explicitly **length-only conditional**, not a theorem or export authorization.
- Current dual-view simulator access to Alice's and Bob's private records is a **testing architecture**. It does not establish security of separated endpoint implementations.
- The complete S3.C authenticated transcript is a functional protocol invariant; an authenticated SHA-256 digest is not a quantum security or source-entropy attestation.

## 6. Machine-checkable conformance evidence (not a security proof)

`test_s4b_protocol_correspondence.py` checks first-hit/late-prefix behavior, cap-abort classification, mismatched bases, zero and positive Z overshoot, excluded deterministic randomness fixtures, observed sampling membership/disjointness, rejection of nonexistent min-entropy evidence, and non-authorization flags. It uses ordinary Python test fixtures and never calls quantum hardware. These tests only assert *implemented observable invariants*; they cannot prove independence, collective/coherent attack security, or sampling lemmas.

**Acceptance for S4.B documentation:** baseline SHA recorded, reference/source matrix completed, tests passing, unresolved theorem assumptions listed and assigned to S4.C/S5, `git diff --check` passing. No security-qualification transition is permitted.

## 7. Decision gate before S4.C

A positive model-based key length or security claim requires an independently reviewed **theorem applicability statement** identifying source-model preparation quality, precise stop/cap and transcript, all random variables, precise EC/confirmation disclosure, and epsilon definitions, with a formal conditional entropy bound. If any part differs from TLGR's assumptions, either modify protocol and rerun evidence or write and review an amended theorem. No `pre_leak_min_entropy_bits` value should be promoted on the basis of model simulation or regression tests.

## 8. Research notebook — S4-002

- **Snapshot:** `43ed32407ce5b3dd5b73cfd35e98046aa075e391` (S4.A formatting follow-up), `research/qkd-security-qst1`.
- **Primary structural match:** TLGR Box 1 quota-based stopping, fixed-size randomly chosen key positions, complete matched test-basis error estimation.
- **Primary differences/uncertainties:** hard `M_max` cap; basis reveal timing and causal order; `k_min` versus `k_actual`; lossless/no-detection specialization; conditional entropy and leakage; computational MAC composition.
- **Permitted description:** *Functional conformance evidence and open theorem correspondence; no composable quantum secrecy established.*
- **Security invariants:** `security_model_validated=false`, `security_qualified=false`, `hpke_export_authorized=false`, `qkd_psk_available=false`.
- **Next:** S4.C lemma audit, source/circuit audit, leakage ledger, and conditional proof prototype under exact matched assumptions.

## 9. References

1. M. Tomamichel, C. C. W. Lim, N. Gisin, R. Renner, *Tight finite-key analysis for quantum cryptography*, Nat. Commun. 3, 634 (2012). Box 1, Methods; Supplementary Notes S1–S2 still to be audited. https://www.nature.com/articles/ncomms1631
2. M. Tomamichel, R. Renner, *Uncertainty Relation for Smooth Entropies*, Phys. Rev. Lett. 106, 110506 (2011). https://doi.org/10.1103/PhysRevLett.106.110506
3. S4.A and QST-1, same repository; `bb84_cudaq.py`, `m1h3a_randomness.py`, `m1h2_authenticated_sampling.py`, `s2b2_strict_theorem_reference.py`, `m1e3_finite_key.py`, S2.A2/S2.A1, and S3.C source/test modules at baseline SHA.
