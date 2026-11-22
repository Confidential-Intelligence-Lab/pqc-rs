# S4.A — Quantum source, measurement, and adversary model

**Project:** PQC-rs goes Quantum  
**Status:** PROPOSED / UNQUALIFIED — normative research model, not a security proof  
**Version:** 0.1  
**Date:** 2026-11-21 (America/Los_Angeles)  
**Implementation baseline:** `Confidential-Intelligence-Lab/pqc-rs`, `research/qkd-security-qst1`, commit `44cd86e0d7fab9ffb67f0be07f8d06868f114703`  
**Parent security target:** `experiments/qkd/security/QST-1.md`  
**Scope:** QST-1 research goals A (prototype) and B (conditional security under a specified idealized quantum model). No hardware or deployment certification.

## 1. Decision and security claim boundary

S4.A freezes a **candidate idealized prepare-and-measure BB84 model** and a list of proof obligations. The security theorem, parameter-estimation reduction, smooth conditional min-entropy, composable authentication, and qualified provenance have **not** been established. Passing any existing CUDA-Q simulation or Python/Rust test does not upgrade this status.

**Candidate theorem:** Tomamichel, Lim, Gisin, and Renner (2012), *Tight finite-key analysis for quantum cryptography*, Nature Communications 3, 634, DOI `10.1038/ncomms1631`. Its Box 1 explicitly specifies repeated transmission until both matched-basis quotas are reached, random selection of `n` key-basis positions, and testing all matched test-basis positions. This is **closely aligned at the observable-protocol level** with H2/S2.B2. This observation corrects the overly broad suggestion that any quota-stopping rule necessarily contradicts the paper. **Applicability remains OPEN** pending an exact side-by-side comparison of all hypotheses, including abort on a predeclared transmission cap and the theorem's treatment of non-detections, losses, and conditioning on acceptance.

The implementation's intended security bits remain unconditionally false:

- `security_model_validated=false`
- `security_qualified=false`
- `hpke_export_authorized=false`
- `qkd_psk_available=false`

There is no authorization to export a simulator-derived key as an HPKE PSK.

## 2. Model identifiers and terminology

- `model_id`: `pqc-rs/qkd/s4a/ideal-bb84/v0.1`
- `protocol_profile`: `qst1-research-v1`
- `theorem_candidate`: `TLGR-2012-Phi`
- `n`: number of retained X-basis raw-key bits (`n_key`)
- `k_min`: minimum number of eligible matched Z-basis test bits (`k_test`)
- `k_actual`: **all** eligible matched Z events in the accepted acquisition prefix, including quota overshoot
- `M_max`: predeclared maximum transmissions (`max_transmissions`)
- `tau`: first transmission index at which both matched X and Z quotas hold, or the abort boundary `M_max`
- `T`: complete public classical transcript, including bases, selected indices, test disclosures, syndromes, confirmation, public PA seed, final protocol state, and abort/accept information
- `E`: Eve's arbitrary quantum side information plus all accessible public data
- `X`, `X_B`: Alice's and Bob's selected raw X-basis key strings before reconciliation
- `K_A`, `K_B`: outputs after privacy amplification, or an abort symbol

`n` and `k_actual` are NOT the number of transmitted qubits. `k_actual` must not silently be replaced by `k_min` in a proof or finite-key formula.

## 3. Proposed idealized physical model (ASSUMPTIONS, not validated facts)

**A-SRC-01 — Trusted qubit source.** Each transmission contains a single two-level quantum system, prepared according to Alice's private uniformly random bit and privately chosen BB84 basis. Ideal states are `|0>`, `|1>` in Z and `|+>`, `|->` in X, up to a *specified* basis/bit convention. There are no multiphoton pulses, side channels, spectral tags, timing leakage, or basis-dependent information outside the qubit. A preparation-quality/overlap parameter `q` must be defined using the selected theorem's own convention. `q=1` is a **candidate ideal complementarity value**, not a measured property.

**A-MEA-01 — Trusted receiver.** Bob privately chooses Z or X and performs the corresponding ideal projective qubit measurement. The model records clicks/detection events and their time ordering. If a no-click outcome is allowed, its probability and adversarial dependence must be in the theorem model. The current simulator produces a binary bit per attempted transmission; **lossless/no-erasure behavior** is therefore the narrowest initial model. No detection-efficiency loophole is deemed covered.

**A-RNG-01 — Independent secret randomness.** Alice's bits, Alice's bases, Bob's bases, and post-sifting random X-position selection are independent as required by the proof, and unpredictable to Eve until their scheduled public disclosure. The public PA Toeplitz seed is fresh and independent of the raw key and Eve's information at seed selection. Computational pseudorandomness alone is not a proof of these ideal randomness hypotheses. The documented deterministic fixture stream is expressly **excluded** from security model B.

**A-CHAN-01 — Untrusted quantum channel.** Eve may replace, block, delay, inject, store, entangle, and coherently interact with the quantum systems, subject only to the trusted source/receiver and causal/timing assumptions of the chosen proof. We do **not** restrict Eve to intercept-and-resend or independent identical attacks. A general/coherent attack result is desired and must be tied to the actual theorem.

**A-CLASS-01 — Authenticated public channel.** Eve reads the entire classical transcript and may delay, replay, suppress, reorder, or attempt to forge frames. A separate classical-authentication assumption or quantified security reduction is required. S3.C provides session-bound canonical MAC-framed communications with fail-closed tests; it does not prove credential origin, a composable MAC bound, or distributed endpoint independence. No private basis/bit material may be sent before the proof permits disclosure.

**A-HOST-01 — Honest endpoints.** Alice's and Bob's process state, local raw bits, private randomness, authentication roots, and session state are uncompromised. The single-host testing orchestrator sees both sides, and therefore does **not** instantiate two isolated confidential endpoints. Hardware side channels, malicious operators, storage rollback, or multi-host registry races remain out of scope.

## 4. Exact candidate protocol and visibility boundary

1. **Precommitment (OPEN).** Fix `n`, `k_min`, basis probabilities, QBER threshold, `M_max`, selected security parameters, reconciliation policy, and protocol/model IDs before acquisition. Authenticate any public configuration that affects acceptance. A report made after acquisition does not prove precommitment.
2. **Prepare and measure.** For each ordered attempt `i`, Alice chooses `x_i` and `a_i`, prepares the corresponding BB84 qubit, Eve acts on the untrusted channel, and Bob chooses `b_i` and measures. Private choices must not be leaked prematurely.
3. **Stopping.** Continue until first hitting time `tau` with at least `n` matched X and `k_min` matched Z detections. Abort if the predeclared `M_max` is reached without reaching both quotas. The impact of cap-triggered abort/accept conditioning on the theorem must be reviewed.
4. **Authenticated sifting.** Authenticate the basis announcements and indices; both endpoints independently compute eligible sets. The current H2 simulator performs its basis exchange after generation of the complete prefix; the proof must determine whether disclosure timing affects the applicable adversary/causality model.
5. **Parameter estimation.** Uniformly choose `n` positions from all eligible matched X positions, without replacement. Disclose **all** matched Z bits and compute `k_actual` and Z-basis errors. Abort if measured test QBER exceeds `Q_tol`. An accepted observation by itself is not an estimate of `H_min(X|E,T)`.
6. **Reconciliation.** Communicate bounded syndrome frames using the tested S2.A2 128-bit-block decoder. Account for **actual public error-correction leakage**, including any additional metadata that the proof needs to count. The decoder corrects up to two errors per block under its checked matrices; beyond that, correctness depends on confirmation.
7. **Key confirmation.** Authenticate a fresh public independent universal-hash confirmation seed and tag; independently verify on Bob's side. Carefully distinguish collision probability from authentication/quantum-secrecy failure.
8. **Privacy amplification.** Agree on the extractor family, exact input/output lengths, public seed, and complete session context through S3.C. The public seed is not a secret. Derive a non-exportable diagnostic only when the implementation's existing illustrative path explicitly allows it; a real key output requires a signed-off min-entropy proof and trusted provider architecture.
9. **Finalization.** Require matched transcript digests, successful confirmation, and a one-time session lifecycle. Both sides must agree on abort/accept status. Public acceptance of authenticated messages does not imply the final key is uniform.

**Open correspondence question:** In the theorem, transmission steps and basis announcements may be organized differently than in our simulator, which precomputes all records. A proof review must determine whether these views are equivalent under the chosen attack/causality model rather than assuming so.

## 5. Formal security quantities and proof obligations

**Correctness goal:** `Pr[accept and K_A != K_B] <= epsilon_cor`, subject to an agreed definition of whose acceptance is counted and termination/asynchrony handling.

**Secrecy goal:** Condition on the *subnormalized accepted branch*, with a length register if output lengths may vary. Bound `1/2 ||rho_{K_A E T,acc} - tau_{K_A} tensor rho_{E T,acc}||_1 <= epsilon_sec` under the selected convention; the exact ideal-resource construction, normalization, and smoothing convention must be recorded in S4.B/S5 before any claimed theorem.

**Required entropy statement:** Derive, for the selected pre-extraction raw key `X`, a lower bound on `H_min^epsilon_s(X | E,T_preEC,acc)` under the exact source and quantum-channel model. This must account for the X/Z sampling rule, public basis transcript, stopping rule and acceptance-conditioned statistics. The classical leakage chain rule, correctness confirmation disclosures, smoothing and privacy amplification must then be applied *once each*. Do not put an arbitrary QBER-derived number into `pre_leak_min_entropy_bits`.

**Authentication:** Develop a game/reduction for the chosen MAC and its provisioned-key model, including adversarial chosen-message access, total frame count, active sessions, key re-use, and transcript/hybrid domain separation. HMAC-SHA256 is computational authentication, not an unconditional Wegman–Carter proof; choose and state the resulting computational or information-theoretic security regime explicitly.

**Planning envelope:** `epsilon_total <= epsilon_sec + epsilon_cor + epsilon_auth` is a target to be justified by a precise composition argument, not an already-established result. The target `epsilon_total <= 1e-12` and candidate 256-bit extracted PSK are provisional feasibility requirements; they are not achieved by the current implementation. Robustness/abort probability is a separate metric.

**Finite-key machinery:** TLGR-2012 and its smooth-entropy uncertainty relation are **candidate inputs**, not automatically instantiated reductions. Specify theorem version/supplement, exact `q`, `n`, `k`, `Q_tol`, `leak_EC`, `epsilon_sec`, `epsilon_cor`, smoothing and statistical deviation terms; independently reproduce the published numerical expression; then prove the correspondence to the S3.C state machine.

## 6. Implementation-to-assumption traceability

| ID | Assumption or obligation | Current implementation evidence | Status / missing proof |
|---|---|---|---|
| S4-SRC | Ideal BB84 single-qubit state; preparation quality `q` | `bb84_cudaq.py`; `m1g5c1_measurement_transcript.py` | OPEN: inspect gates, source overlap and absence of side channels in *model*; not physical validation |
| S4-MEA | Ideal compatible-basis projective measurement; no-click policy | `bb84_cudaq.py`; `m1h3a_randomness.py` | OPEN: audit model, erasure/loss handling, measurement randomness |
| S4-RNG | Independent private bit/basis/selection RNG | `m1h3a_randomness.py`: separated OS/fixture streams; H2 uses `SystemRandom` or provided streams | OPEN: proof assumption; exclude fixed seeds, document source and sampling correlation |
| S4-STOP | First quota-crossing stop; max-transmission cap | `s2b2_strict_theorem_reference.py`; `m1h3a_randomness.py` | PARTIAL functional evidence; OPEN theorem applicability for cap and conditioning |
| S4-SAMPLE | Uniform X subset, entire matched Z population | `m1h2_authenticated_sampling.py` | PARTIAL functional evidence; OPEN comparison to theorem protocol and loss model |
| S4-AUTH | Global session/role/order/public-byte binding | `s3c_authenticated_transcript.py`, S3.C-2a/2b/2c tests | TESTED in simulator; OPEN credential bootstrap and quantitative MAC bound |
| S4-EC | Explicit reconciliation leakage | `s2a2_syndrome_reconciliation.py` | OPEN proof ledger, public metadata, worst-case/event-specific accounting |
| S4-COR | Fresh universal-hash correctness confirmation | `s2a1_universal_confirmation.py` | OPEN full protocol correctness including multi-party abort/accept semantics |
| S4-PA | Fresh independent public universal-hash seed and extractor | `m1e2_privacy_amplification.py`; S3.C-2c integration | PARTIAL functional evidence; OPEN seed independence, length proof and composable extraction |
| S4-ENT | Quantum conditional min-entropy vs Eve | `m1g3_tomamichel_bound.py`; `m1e3_finite_key.py` | BLOCKED: numerical formulas and caller-provided hypothetical values are not entropy proof |
| S4-HPKE | No simulated/unqualified production key export | `crates/pqc-hpke/src/qkd_m2b.rs`; Rust tests | IMPLEMENTED negative boundary; trusted qualified provider and composition OPEN |
| S4-ASSUR | Independent scientific review | QST-1, S3.C scope docs, integration tests | OPEN review, formal reduction, cross-implementation validation |

## 7. Specific protocol/theorem delta checklist (S4.B input)

| Delta ID | Question | Current assessment |
|---|---|---|
| D1 | Are the theorem's matched-X and matched-Z quota stopping semantics identical? | **Candidate match:** TLGR Box 1 itself uses quota stopping; must audit exact detection/stopping semantics |
| D2 | Does the theorem allow a hard `M_max` abort and what public conditioning does it induce? | OPEN |
| D3 | Is lossless binary-output modeling an admissible special case of theorem's no-detection model? | OPEN |
| D4 | Is basis revelation after simulating a complete prefix equivalent under the theorem's attack timing? | OPEN |
| D5 | Does uniformly sampling `n` X positions and using **all** Z bits match `Phi[n,k,...]`? | Candidate structural match; review role of actual `k_actual >= k_min` |
| D6 | Does the theorem's EC leakage budget cover 32-bit syndromes/block plus all other public disclosures? | OPEN |
| D7 | Do the implemented universal-hash confirmation, authentication and PA sequence satisfy proof assumptions? | OPEN |
| D8 | Is the ideal preparation quality `q` computed in the theorem's convention for actual CUDA-Q circuits? | OPEN |
| D9 | Are the theorem's epsilon allocations compatible with S2.A1 and `m1e3_finite_key.py`? | OPEN |
| D10 | Can a computational HMAC classical channel compose with information-theoretic quantum secrecy under an explicitly computational hybrid claim? | OPEN; must not call whole construction unconditional |
| D11 | Is session acceptance/abort consistently agreed in a distributed execution rather than only by a dual-view simulator? | OPEN |
| D12 | Can the cap and finite-block constraints support 256 output bits at target `1e-12`? | OPEN numerical feasibility; no qualified positive extraction |

**Priority recommendation for S4.B:** D1–D5 before running numerical entropy estimates. Fix the *exact theorem profile* first, then conduct sensitivity analyses.

## 8. Evidence acceptance criteria and tests

1. Check the source-preparation and Bob-measurement truth tables directly against the CUDA-Q circuit definition, including complementary-basis output distributions and post-Eve interference.
2. Show the simulator's stopping index is the first quota-crossing prefix; document cap-induced aborts and cases with one or both overshoots.
3. Show sampled X indices are a uniform without-replacement selection in the model (via code review/proof); tests may supplement but cannot establish true physical randomness.
4. Confirm all eligible Z positions are disclosed and accounted for, including overshoot.
5. Inventory actual authenticated transcript frames and leakage bits; compare to assumed theorem EC and confirmation leakage.
6. Record all randomness modes and prohibit a deterministic mode from any conditional theorem evidence or production qualification.
7. Build a separate proof ledger specifying every assumption, mathematical statement, tool-checked arithmetic step, and reviewer approval. Never promote a test result into a security theorem.
8. Verify all existing false qualification/HPKE flags remain false. Preserve Rust denial regardless of diagnostic outputs.

Suggested S4.A *documentation* acceptance: specification committed at an exact SHA, `git diff --check` passes, and the repository reference/test inventory is complete. There is **no new claim of quantum secrecy** at S4.A exit.

## 9. Exclusions, explicit research choices, and known risks

- The current model is **single-photon qubit, trusted source and receiver, no side channels**. Decoy states, photon-number splitting, optical apparatus, detector attacks, and hardware certification are outside this version.
- Eve's attack class is intended to be general under the theorem, not merely the intercept-and-resend simulator. A theoretical proof with an ideal trusted-device model is not a hardware certification.
- The simulator has both endpoints' data in one process, so its passing transcript tests are model conformance rather than distributed security evidence.
- Python key-byte handling does not establish reliable zeroization. Terminal and replay protection is single-host and vulnerable to privileged rollback.
- Independent authentication provisioning and a quantified key-use budget are absent. This must be resolved before calling the output an authenticated composable QKD key.
- All S4 assumptions and outcomes must remain revisioned and explicitly reviewer-signable. Changes to stopping logic, basis timing, leakage accounting, or extractor selection invalidate prior unreviewed applicability conclusions.

## 10. Research notebook — S4-001

- **Baseline:** commit `44cd86e0d7fab9ffb67f0be07f8d06868f114703`, branch `research/qkd-security-qst1`; S3.C-2c passed 109 selected tests on EdgeExpert before commit.
- **Finding:** TLGR-2012 Box 1 uses a quota-stopping BB84 protocol with random X subset and full matched-Z parameter estimation. The exact correspondence to the implementation is an open theorem obligation, not a binary mismatch assumed from quota stopping alone.
- **Decision:** Use ideal single-qubit prepare-and-measure BB84 with a trusted receiver and general quantum Eve as a **candidate** model B. No optical/hardware claims.
- **Main proof blockers:** cap/abort conditioning, measurement timing/losses, quantum min-entropy, precise EC/confirmation leakage, composable computational authentication, and distributed endpoint semantics.
- **Next:** S4.B side-by-side theorem/protocol correspondence and rigorous finite-key lemma audit. Decide whether to change the implementation or establish a theorem for its exact stopping/cap behavior.
- **Claims permitted:** authenticated BB84 simulation and fail-closed research integration; **not** secure QKD, certified entropy, or QKD-derived HPKE PSK.

## 11. References

1. M. Tomamichel, C. C. W. Lim, N. Gisin, and R. Renner, “Tight finite-key analysis for quantum cryptography,” *Nature Communications* **3**, 634 (2012). DOI: https://doi.org/10.1038/ncomms1631 ; open text: https://pmc.ncbi.nlm.nih.gov/articles/PMC3274703/ . See Box 1 and Supplementary Material for theorem hypotheses.
2. M. Tomamichel and R. Renner, “Uncertainty Relation for Smooth Entropies,” *Physical Review Letters* **106**, 110506 (2011). DOI: https://doi.org/10.1103/PhysRevLett.106.110506 .
3. `experiments/qkd/security/QST-1.md` in `Confidential-Intelligence-Lab/pqc-rs`, baseline above.
4. `experiments/qkd/security/S3C_2A_SECURITY_SCOPE.md`, `S3C_2B_SECURITY_SCOPE.md`, `S3C_2C_SECURITY_SCOPE.md` and corresponding code/tests in baseline above.
