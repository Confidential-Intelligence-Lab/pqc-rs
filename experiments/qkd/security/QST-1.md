# QST-1 — Quantum Security Target

**Project:** PQC-rs goes Quantum  
**Version:** 0.1 — proposed security contract, not a security certificate  
**Baseline:** `Confidential-Intelligence-Lab/pqc-rs`, `main`, merge commit `7b3a6d74ccbbff9472657e67cc6bebcb4f93c296` (PR #60)  
**Date:** 2026-11-21  
**Owner:** Confidential Intelligence Lab  
**Scope:** A — publishable research prototype; B — conditional security under an explicit idealized model. Physical/product qualification (C) is excluded.

## 1. Purpose and interpretation

QST-1 establishes the intended security claims, exact model assumptions, interfaces, numerical design goals, evidence needed for those claims, and a fail-closed qualification decision. This document **does not establish** that QKD secret keys, authentication credentials, or HPKE PSKs are secure. Every unfinished claim remains `OPEN`, and no caller-supplied Boolean may promote a claim to `PROVED`.

**Key distinction:** An idealized quantum simulation can demonstrate protocol conformance or model-dependent phenomena, but its execution cannot itself certify secret entropy against a quantum adversary. A proof must cover the modeled protocol and the actual classical transcript; source-model correspondence must be argued separately.

### Target outcomes

- **A / prototype:** Reproducible CUDA-Q BB84 simulation, authenticated classical distillation, finite-key diagnostics, fail-closed QKD/HPKE boundary, adversarial tests, and research-grade evaluation.
- **B / conditional:** A reviewable proof that the *specified* idealized prepare-and-measure protocol constructs an approximately ideal shared secret under explicit assumptions, plus a separately scoped argument for HPKE PSK composition.
- **Not targeted:** Optical devices, detectors, HSM/product certification, ETSI/Common Criteria/FIPS validation of a deployment, or claims of hardware-independent security.

## 2. System boundary

Alice and Bob execute prepare-and-measure BB84 in a CUDA-Q idealized source/channel/receiver model. Public classical interaction covers sifting, parameter estimation, authenticated reconciliation, correctness confirmation, privacy-amplification parameter agreement, and abort/commit. A local security evaluator checks evidence and parameters. The existing Rust `production_handoff` denies simulated provenance and all caller-forged positive flags. A separate non-secret, explicitly insecure fixture exercises ML-KEM-768 / RFC 9180 HPKE PSK functionality. **No production QKD-derived PSK export is authorized by QST-1.**

**Trust boundary:** A public report containing a transcript hash, numerical key length, or `security_qualified=true` is *not* a grant token. A future qualified provider requires trusted source identity, an internal enforcement decision, a one-time opaque key handle, authenticated policy context, and a separate security review.

## 3. Adversary and trusted assumptions

### 3.1 Adversary capabilities

The adversary may control, intercept, delay, drop, reorder, duplicate, and replace quantum transmissions and unauthenticated network traffic; retain quantum side information; attempt quantum-capable attacks; and observe the entire public transcript, accepted/aborted outcomes, public seeds, lengths, key identifiers, and classical error-correction disclosures. An active attacker may attempt session splicing, replay, role confusion, forged evidence, and cross-protocol key substitution.

The security theorem must explicitly state whether it handles coherent/general attacks or only a restricted adversary class. **Do not infer general-attack security from a simulator implementing intercept-and-resend.**

### 3.2 Assumptions required for conditional theorem (to be matched exactly)

- Alice's quantum-state preparation conforms to the defined idealized BB84 states and a documented preparation-quality parameter; Bob's measurement apparatus follows the chosen trusted model.
- Private basis and source randomness are independent, unpredictable to the adversary when required, and generated independently of adversarially controlled public information.
- Initial Alice/Bob classical authentication credentials are independently provisioned and not known to the attacker; the authentication construction and key-use budget are specified.
- Alice and Bob execute the *same* precisely defined stopping, selection, announcement, disclosure, reconciliation, confirmation, and privacy-amplification procedure as the mathematical security proof.
- All communication, losses, nondetections, aborts, quota overshoot, variable-length stopping, and allowed malicious scheduling are explicitly modeled. In particular, conditioning on reaching a stopping quota must not silently change a proof that assumed a fixed sample or fixed transmission window.
- Device imperfections, leakage outside the model, endpoint compromise, rollback attacks on the filesystem, and malicious local administrators are **outside B** unless separately modeled and proved.

**Proof blocker:** The applicability of Tomamichel–Lim–Gisin–Renner (2012), its exact protocol Phi, and its finite-key Equation (2) to the implemented quota-stop/full-Z-disclosure procedure is not currently established. Numerical agreement with the published equation is insufficient.

## 4. Security definitions and design targets

### 4.1 Correctness

For the protocol's complete output including abort, require a composable correctness definition such as

`Pr[accept and K_A != K_B] <= epsilon_cor`.

Confirmation collision tests establish only a *conditional ingredient* under their hashing/independence assumptions; they do not prove all-of-protocol correctness by themselves.

### 4.2 Secrecy

For the *subnormalized accepted branch* (so abort probability is correctly accounted for), require the final joint classical-quantum state of key, adversary, and public transcript to be within trace distance `epsilon_sec` of an ideal uniform, shared key independent of the adversary, under the selected proof's precise convention. Formally, state a trace-distance/ideal-resource definition with the accepted branch and length register spelled out in the proof appendix; do not replace it with empirical key randomness tests.

A sufficient extraction rule must follow from a **proved** smooth conditional min-entropy lower bound and the selected extractor/leftover-hash lemma, with public transcript, syndrome leakage, seeds, smoothing, and conditioning handled exactly once.

### 4.3 Authentication and composition

Bound classical authentication failure, including key exposure, chosen messages, multi-message forgery, and finite-session key consumption under its chosen construction. For an appropriately proven sequential/parallel composition:

`epsilon_qkd_total <= epsilon_sec + epsilon_cor + epsilon_auth`.

This is a **planning envelope**, not an established inequality for this implementation until the definitions and reduction are fixed. HPKE security additionally relies on its own KEM/KDF/AEAD assumptions, authenticated endpoint binding and application protocol context; it does not follow solely from the additive QKD bound.

### 4.4 Proposed numerical profile (subject to feasibility and proof)

| Setting | Provisional target | Status |
|---|---|---|
| Per-accepted-session QKD error budget | `epsilon_qkd_total <= 1e-12` | DESIGN TARGET |
| QKD-derived HPKE PSK | >= 256 justified bits of entropy (RFC 9180 requires >= 32 bytes entropy) | NOT AVAILABLE |
| HPKE KEM | ML-KEM-768 | IMPLEMENTED AS TESTED FIXTURE PATH |
| QKD output length | At most bound justified by actual protocol/theorem | NO CERTIFIED POSITIVE LENGTH |
| Auth root | Explicit externally supplied secret under B assumptions | PROVISIONING TRUST UNPROVED |
| Session anti-replay | Bound to authenticated session; fail closed on reuse | SINGLE-HOST PARTIAL |
| Export | No simulated/unqualified QKD-to-HPKE PSK export | REQUIRED INVARIANT |

**Practical feasibility:** `1e-12` is not an ISO/NIST mandated threshold. Run a sensitivity study for block size, tolerated QBER, number of accepted sessions, leakage, and abort rate before freezing the profile. A candidate length of 256 bits is an interoperability target, not a statement that 256 uniform bits can currently be extracted.

## 5. Normative modeled protocol (draft for S3.C / S4 alignment)

A single authenticated session must bind at least: `protocol_id`, `version`, `profile_id`, `alice_id`, `bob_id`, `authentication_key_id`, `session_id`, `stage`, `direction`, `sequence_number`, `previous_transcript_digest`, canonical public payload, and final transcript digest. All values influencing the final secret or the security decision must be committed to the authenticated transcript. Local private keys and raw unrevealed key bits are never serialized into public frames.

**Proposed stage machine** (not yet implemented as a single unit):

1. `NEW -> PROVISIONED`: externally supplied root under explicit bootstrap assumption; unique key ID and session ID; fail closed if absent.
2. `PROVISIONED -> ACQUIRING`: authenticated role, protocol, and parameter agreement; commit quota policy before acquisition.
3. `ACQUIRING -> SIFTED`: authenticated basis announcements, acquisition stopping decision, quota counts and accepted detection-event index set.
4. `SIFTED -> ESTIMATED`: authenticated X selection, **all eligible Z** disclosure as implemented, error tally, threshold decision, and abort status.
5. `ESTIMATED -> RECONCILED`: authenticated syndrome messages, leakage accounting, bounded-distance decoding outcome; no raw-key comparison as a protocol acceptance oracle.
6. `RECONCILED -> CONFIRMED`: authenticated universal-hash confirmation and correctness budget.
7. `CONFIRMED -> EXTRACTED`: agreed extractor/seed/output length; **only a hypothetical non-exportable local result** until the entropy theorem applies.
8. `EXTRACTED -> CLOSED` or `ANY -> ABORTED`: final digest, result status, one-time consumption and no restart/reopening of that session.

Any out-of-order stage, inconsistent role, stale sequence, transcript mismatch, duplicated/dropped frame, role reversal, malformed canonical encoding, downgraded version/profile, or key-ID/session-ID substitution must abort. Terminal states cannot transition to a key-producing state. Authenticated abortion is preferred when feasible; network silence still terminates safely. The exact role-dependent message order must be frozen in the S3.C specification.

**Conformance warning:** S2.B2's quota-stop/full-Z-disclosure rule is implementation evidence, *not yet* proof that a fixed-n/fixed-k theorem applies. Either (a) derive and review a theorem for this stopping model, or (b) change the protocol to a theorem-matched design and rerun all evidence. This is an explicit research decision, not a hidden implementation tweak.

## 6. Security requirements and gates

| ID | Requirement | Evidence for acceptance | Current disposition |
|---|---|---|---|
| QST-AUTH-01 | No unauthenticated production classical path | Exact session API wiring + negative tests | OPEN — S3.C |
| QST-AUTH-02 | Provisioned credential security and MAC bound | Bootstrap assumption, MAC reduction, key-use budget | OPEN — S3.D/S5 |
| QST-STATE-01 | Complete unique transcript and abort-on-replay | State-machine model, mutation/property tests, replay tests | OPEN — S3.C |
| QST-RNG-01 | Private independent randomness matches proof | RNG model, seeded fixture separation, adversarial tests | OPEN — S4 |
| QST-QKD-01 | Protocol matches selected theorem including stopping rule | Side-by-side protocol specification, proof applicability review | OPEN — S4 |
| QST-ENT-01 | Conditional min-entropy is justified | Reviewable theorem, adversary model, source assumptions | OPEN — S4 |
| QST-EC-01 | Reconciliation and correctness leakage counted once | Leakage ledger, universal-hash confirmation proof | OPEN — S4/S5 |
| QST-COMP-01 | Composable QKD key bound within chosen budget | End-to-end reduction, epsilon ledger, independent check | OPEN — S5 |
| QST-HPKE-01 | Trusted provider and hybrid PSK composition | Interface spec, one-time opaque handle, PSK requirements, reduction | OPEN — S6 |
| QST-FAIL-01 | Simulator and forged claims never authorize production export | Rust denial tests + negative cross-language tests | IMPLEMENTED; keep invariant |
| QST-ASSUR-01 | Reproducible and independent assurance | CI, cross-implementation oracle, adversarial and reviewer reports | PARTIAL — S7 |

**Gate A exit:** stable merged baseline; reproducible simulator and fixture-level HPKE demonstration; meaningful adversarial tests; security limitations published; all required CI green. Claims restricted to **experimental functional integration**.

**Gate B exit:** every proof-related requirement `QST-AUTH-01` through `QST-COMP-01` has a signed-off argument tied to exact source revision and configuration; a reviewer confirms proof/model correspondence; a positive extracted length is derived under the model; adversarial tests and independent numerical checks pass. An HPKE *compositional* claim additionally requires QST-HPKE-01. **Gate B is not equivalent to permission for production export.**

No amount of CI or empirical testing substitutes for a missing proof or a missing assumption. A fail-closed boundary is necessary even when Gate B is achieved.

## 7. S3.C implementation acceptance tests (mandatory first increment)

- Valid multi-stage Alice/Bob run agrees on final authenticated transcript hash and produces `EXPORT_AUTHORIZED=false`.
- Replay within a stage, replay after restart, duplicated frame and stale nonce/session ID are rejected.
- Drop, reordering, cross-stage substitution, stage-skipping, late message after terminal state, and forged abort/commit are rejected.
- Cross-session splice, wrong peer, role reflection, key-ID substitution, profile downgrade, transcript-hash fork and canonical-encoding ambiguity are rejected.
- Authentication failure must not expose raw key bits, reconciled material, authentication root, private randomness, or provider PSK in error/log output.
- Existing strict S3.B one-host registry remains active; concurrent processes cannot reserve the same session ID; limitations under snapshot rollback/multi-host remain documented.
- Independent non-CUDA-Q test path exercises the protocol state machine on ordinary CI runners; CUDA-Q device/simulation path is a separately labeled integration experiment.
- A negative test asserts that all positive public security booleans still cannot authorize Rust `production_handoff`.
- No existing security flag is set to true merely because these tests pass.

## 8. Experimental evidence plan

**A / functional:** record source revision, Python/Rust/CUDA-Q versions, host, simulator target, acquisition attempts, accepted X/Z quotas, QBER, reconciliation success/abort, public leakage, message counts, latency and memory, HPKE fixture round-trip outcome. Compare ideal/noise/intercept-and-resend scenarios; label intercept-and-resend as **one example**, not the full adversarial security analysis.

**B / conditional:** record proof identifier and exact hypotheses, conditional-entropy bound, parameter-estimation confidence term, correctness bound, authentication budget, security/robustness budget distinction, final extracted length, abort rate, and sensitivity against sample size/QBER/epsilon. Audit whole finite-key expression with an independent arithmetic implementation and review the exact theorem protocol, including stopping and announcements.

**Must not report:** measured 'bits of quantum security', a positive *certified* QKD key size, hardware security, or QKD-backed production HPKE security until the relevant obligations are discharged.

## 9. Research notebook / manuscript handoff record

### Entry QST-001 — 2026-11-21

- **Decision:** Target research prototype A and conditionally secure idealized protocol B; exclude operational/hardware certification C.
- **Baseline:** PR #60 merged as `7b3a6d74` into `main`; prior PR head `e59f0426`; 17/17 workflow successes at the validated head.
- **Working architecture:** CUDA-Q BB84 simulator; Python authenticated sampling/reconciliation/confirmation/finite-key diagnostics; Rust fail-closed handoff; separate insecure ML-KEM-768 HPKE PSK fixture.
- **Known limitations:** S3.A state machine not unified with actual H2/S2.A2; S3.B credential origin and multi-host rollback protection unproved; theorem-specific quota-stopping applicability unresolved; quantum min-entropy unproved; composable authentication budget not certified; qualified provider absent; no QKD export.
- **Security target:** provisional `epsilon_qkd_total <= 1e-12` per accepted session, 256-bit HPKE PSK interoperability target; feasibility and exact definitions to be reviewed.
- **Immediate implementation task:** S3.C unified transcript: design message schema, stage machine, negative tests, then integrate strict H2/S2.A2/M2.A.
- **Paper-facing claim today:** reproducible *experimental quantum-classical integration with explicit fail-closed separation*. Do not claim proven QKD secrecy.
- **Open research question:** Does the exact quota-stop/full-Z-disclosure protocol admit the selected finite-key proof unchanged? If not, adopt a theorem-matched protocol or develop a new security argument.

### Handoff instructions for a later paper-writing chat

Use the security target as a *requirements document*, not proof of attainment. Start the paper with precise contributions and distinguish experiments from conditional theorems. Include the proof-to-implementation gap as an explicit research problem; never imply CUDA-Q simulations certify physical QKD. Cite exact committed source files, benchmark commands, and signed-off evidence as milestones close. Retain the current fail-closed production boundary in all statements.

## 10. Source-of-truth implementation pointers

- `experiments/qkd/S3A_SECURITY_SCOPE.md` and `s3a_authentication_lifecycle.py` — authenticated session skeleton.
- `experiments/qkd/S3B_SECURITY_SCOPE.md` and `s3b_persistent_strict_path.py` — provisioned credential forwarding / single-host session registry.
- `experiments/qkd/m1h2_authenticated_sampling.py` — authenticated sampling and complete eligible-Z disclosure.
- `experiments/qkd/s2a2_syndrome_reconciliation.py` and `s2a1_universal_confirmation.py` — bounded-distance syndrome, independent confirmation.
- `experiments/qkd/s2b2_strict_theorem_reference.py` and `S2B2_SECURITY_SCOPE.md` — quota-stop observable-prefix check.
- `experiments/qkd/s2b3_composable_evidence.py` and `S2B3_SECURITY_SCOPE.md` — numerical/theorem/epsilon evidence diagnostics.
- `experiments/qkd/m2a_authenticated_distillation.py` — public distillation result; no exported key.
- `experiments/qkd/m2b_handoff_probe.py` and `crates/pqc-hpke/src/qkd_m2b.rs` — public-only evidence and Rust denial.
- `crates/pqc-hpke/tests/qkd_m2b_handoff.rs` — negative security tests and separate HPKE fixture.
- `https://github.com/Confidential-Intelligence-Lab/pqc-rs/pull/60` — integration PR and CI evidence.

## 11. Technical references

1. M. Tomamichel, C. C. W. Lim, N. Gisin, and R. Renner, *Tight finite-key analysis for quantum cryptography*, Nature Communications **3**, 634 (2012), DOI: 10.1038/ncomms1631. https://www.nature.com/articles/ncomms1631
2. RFC 9180, *Hybrid Public Key Encryption* (2022), Sections 5 and 9, especially 9.5 on PSK entropy. https://www.rfc-editor.org/rfc/rfc9180
3. ETSI GS QKD 016 V2.1.1, *Common Criteria Protection Profile — Pair of Prepare and Measure Quantum Key Distribution Modules* (2024). Used only as an assurance reference, not a certification target. https://www.etsi.org/deliver/etsi_gs/QKD/001_099/016/02.01.01_60/gs_QKD016v020101p.pdf

---

**Security disposition at QST-1 v0.1: A = demonstrated engineering prototype (scope-limited); B = OPEN; C = excluded. Production QKD-derived HPKE export = DENY.**
