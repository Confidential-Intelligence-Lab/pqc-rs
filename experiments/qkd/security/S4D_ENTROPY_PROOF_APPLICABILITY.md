# S4.D - Accepted-branch entropy and finite-key proof applicability

**Project:** PQC-rs goes Quantum
**Status:** RESEARCH ANALYSIS / NOT SECURITY QUALIFIED
**Version:** 0.1, 2026-11-21
**Baseline:** `research/qkd-security-qst1`, `79689dd8b253a10525cf2e193fcac50e293541d0`
**Parents:** `security/QST-1.md`, `security/S4A_QUANTUM_SOURCE_ADVERSARY_MODEL.md`, `security/S4B_THEOREM_IMPLEMENTATION_CORRESPONDENCE.md`, `security/S4C_FINITE_KEY_EQUATION_LEAKAGE_AUDIT.md`

## 1. Decision

**Theorem applicability: UNRESOLVED.** The published TLGR-2012 Box 1 has strong structural correspondence with the acquisition/selection/testing protocol, but an end-to-end conditional min-entropy statement for the current S3.C strict path is **not yet proved**. In particular, theorem-specific device and randomness assumptions, stopping-cap coupling, the `k_actual` versus `k_min` parameter, the complete leakage ledger, and composable computational authentication are unresolved. This assessment does not authorize any positive entropy claim or production key export.

**New analytic conclusion (conditional):** A hard public transmission cap is *not automatically incompatible* with the original proof. If the capped execution can be represented *exactly* as the original protocol followed by a completely public, transcript-measurable, final abort filter, then the subnormalized accepted-branch trace-distance secrecy bound cannot increase: the filter is a completely positive trace-nonincreasing map and trace distance is contractive under the associated flagged channel. This is a **conditional reduction**, not a proof that the current simulator meets the hypothesis. Postselection can increase the *normalized* distance conditional on acceptance; see Section 3 and accompanying tests.

## 2. Reference checked

Tomamichel, Lim, Gisin, Renner, *Tight finite-key analysis for quantum cryptography*, Nature Communications 3, 634 (2012), DOI: 10.1038/ncomms1631; published article pages 2-5, especially Box 1 on printed page 3 and Equation (2) on printed page 4. The reference explicitly uses (i) a stopping rule requiring matched-basis X and Z quotas, (ii) a random X subset of size `n`, (iii) testing all matched Z events, (iv) authenticated classical communication, (v) correctness via universal-2 hash, and (vi) privacy amplification via universal-2 hash. The published model also assumes basis-independent detection probabilities and a receiver measurement-delay/memorylessness property. The full Supplementary Notes S1-S2 have **not** been verified line-by-line for this S4.D increment; no claim of a complete supplementary lemma audit is made.

The published Eq. (2) (as visually checked in the journal PDF) is a *sufficient* length criterion under all stated hypotheses:

`ell <= n*(q - h2(Q_tol + mu)) - leak_EC - log2(2/(eps_sec^2 * eps_cor))`,

`mu = sqrt(((n+k)/(n*k))*((k+1)/k)*ln(2/eps_sec))`.

Existing `m1g3_tomamichel_bound.py` implements this numerical expression. Its output is a **numerical candidate only**, not a security proof. Check the exact supplemental conventions before using the numerical result as a certified entropy bound.

## 3. Public-abort filter: precise conditional lemma and counterexample

Let `rho_acc` be the original *subnormalized* classical-quantum key/adversary/public-transcript state on the accepted branch; let `sigma_acc` be its corresponding ideal uniform-key comparison state using the SAME public transcript register and compatible adversary marginal. Write `delta = (1/2)||rho_acc - sigma_acc||_1` and assume it is bounded by `eps_sec` in the chosen ideal-resource convention. Suppose `F` is a public predicate that (a) depends only on already available public transcript and public precommitted parameters; (b) has the same value in real and ideal experiments; and (c) introduces no different message, bit selection, causal quantum interaction, or partial key output. Retain only the accepted sectors for which `F=1`, while mapping all other outcomes to public abort. Then the (subnormalized) distance between the retained real and ideal sectors is at most `delta` by trace-distance contractivity of a flagged CPTP channel (or trace-norm contraction on the selected block). Thus a postprocessing-only abort restriction preserves an already established subnormalized secrecy upper bound.

**Not proved for current code:** The actual cap stops acquisition at `M_max` *before* the unlimited comparator protocol reaches its quotas. A coupling must establish that accepted capped histories coincide with precisely those first-hit histories of the unlimited protocol that satisfy `tau <= M_max`, with identical public announcements and no earlier disclosure or different Eve strategy. This may require specifying a virtual continuation after capped abort, a causal order, and an explicit public cap precommitment.

**Counterexample for normalized acceptance:** A classical accepted ensemble with accepted mass `0.1` and conditional total-variation secrecy distance `0.8` contributes only `0.08` to the subnormalized distance. Discarding the other `0.9` mass does not improve the `0.8` conditional distance of those retained sessions. Never infer `conditional_delta <= eps_sec` from `p_accept * conditional_delta <= eps_sec` without a lower bound on `p_accept` and an explicit conversion; use subnormalized security for composable aborting protocols.

## 4. k_actual versus k_min: no silent substitution

TLGR Box 1 specifies that acquisition stops once at least `k` matched-Z events exist, then computes error rate on the entire matched-Z set. At the final first-hit event, the overshoot is *at most one in a lossless per-transmission matched-event model* when Z is the last quota to fill; X might instead be last, in which case the Z set can have more than `k` events. Thus `k_actual` is a random variable >= `k_min` and may be substantially larger than `k_min`.

The paper's published Eq. (2) uses the protocol parameter `k`; any improvement obtained by plugging the *observed* `k_actual` into the bound needs an explicit theorem handling a random test-set size or a valid conditional/union-bound argument. The conservative engineering convention for unqualified numerical comparison is `k=k_min` with a predeclared `Q_tol`, *not* a claim that this substitution proves validity. A separate lemma must show that additional Z test outcomes and stopping/public disclosure preserve the required sampling assumptions. Use `k_actual` to report the observed error rate and disclosed bits.

## 5. Quantum entropy proof spine (unproved obligations)

- **L1 Source and complementarity:** specify ideal BB84 density operators (including encoding/basis labels) and establish preparation quality `q=1` only for the ideal mathematical model, not physical devices. Confirm the CUDA-Q circuit convention.
- **L2 Adversarial causality:** prove acceptable general quantum Eve interactions, source/basis independence, and receiver basis-independent detection and measurement-delay equivalence as required by the selected theorem.
- **L3 Stopping/sample coupling:** show the implemented first-hit/abort/cap/subset rules realize the relevant sampling experiment; include authenticated disclosure timing, `k_actual`, and any public stopping information.
- **L4 Smooth entropy bound:** instantiate the supplementary Serfling/uncertainty relation for the exact accepted, subnormalized state. Specify smoothing and acceptance conventions and derive `H_min^eps(X|E,T_preEC,acc)` with all public information included.
- **L5 Classical leakage chain rule:** debit 32 bits per S2.A2 syndrome block plus any *additional key-dependent* disclosures not already covered; separate independent public matrix seeds and message metadata only upon proving their independence conditions. Explicitly classify the confirmation tag and its failure contribution without double counting Eq. (2)'s `eps_cor`.
- **L6 Quantum-proof privacy amplification:** verify the actual MSB-first Toeplitz family, independent public seed, exact length, and a quantum leftover-hash lemma with matching smoothing/error conventions.
- **L7 Authenticated-channel reduction:** state HMAC-SHA256's computational security assumptions, multi-frame and multi-session query budget, provisioning and hybrid composition. An ideal authenticated channel theorem is not an unconditional QKD claim for the actual HMAC protocol.

No manuscript should describe any L1-L7 as discharged merely because the corresponding unit tests pass.

## 6. Explicit implementation decision and recommended changes

1. **Do not alter S3.C or the HPKE handoff in this increment.** Keep `security_model_validated=false`, `security_qualified=false`, `hpke_export_authorized=false`, `qkd_psk_available=false`.
2. Establish an explicit, authenticated **pre-acquisition parameter commitment**, covering `n_key`, `k_test`, basis probability, `M_max`, expected source mode, threshold, extractor profile, and ε budgets. Presently S3.C binds these only partially or later; this needs an audit before claiming proof correspondence.
3. Add a proof-profile acquisition wrapper that asserts first-hit conformance on the **actual strict entry point**, not only `s2b2_strict_theorem_reference.assess_prefix` used separately. This is a future code change; no current change to the strict path is authorized by S4.D.
4. Freeze one theorem profile with `k=k_min`, fixed externally declared `Q_tol`, lossless/no-erasure ideal qubit assumptions, and a public cap-abort filter, then seek an independent review of the coupling proof. Revisit `k_actual` improvements only after a valid random-size lemma.
5. Separate proof-quality evidence from numerical candidate output in public reports; retain a machine-readable *unproved-obligations* list and source revision IDs.

## 7. S4.D executable evidence

`test_s4d_entropy_applicability.py` checks arithmetic properties of the accepted-branch weighted distance, a classical counterexample to normalized postselection, monotonicity for purely public filtering, the cap/first-hit observable predicate, `k_actual` overshoot as distinct from `k_min`, numerical nonauthorization, and fixed false qualification flags. **Classical toy examples are illustrations of proof logic, not a quantum theorem, not a simulation of coherent attacks, and not an actual proof of L1-L7.**

## 8. Research notebook - S4-004

- Baseline: `79689dd8b253a10525cf2e193fcac50e293541d0`, `research/qkd-security-qst1`.
- Verified publication: TLGR (2012) main text Box 1, device assumptions, security definition, and Eq. (2) from journal PDF. Supplementary S1-S2 full lemma audit remains open.
- Decision: `UNRESOLVED`, with a plausible **conditional public-abort-filter reduction** for the cap, subject to formal coupling and no extra information release.
- Explicit warning: normalized accepted-only secrecy can be higher than subnormalized secrecy; do not remove abort probability weighting.
- Next phase: S4.E proof-profile precommitment and reference implementation coupling, followed by independent supplementary lemma and composability review.
- Export/qualification: permanently false pending distinct trusted provider and full proof gates.

## 9. References

1. Tomamichel et al., *Tight finite-key analysis for quantum cryptography*, Nat. Commun. 3:634 (2012), https://www.nature.com/articles/ncomms1631, PDF https://www.nature.com/articles/ncomms1631.pdf (visually checked main text).
2. Tomamichel and Renner, *Uncertainty Relation for Smooth Entropies*, Phys. Rev. Lett. 106, 110506 (2011), https://doi.org/10.1103/PhysRevLett.106.110506.
3. Tomamichel, Schaffner, Smith, Renner, *Leftover Hashing Against Quantum Side Information*, IEEE Trans. Inf. Theory 57, 5524-5535 (2011), https://doi.org/10.1109/TIT.2011.2158473.
4. Internal QST-1/S4.A/S4.B/S4.C research artifacts at the pinned baseline above.
