# S5.A — Real/ideal security contract and assumption ledger

**State:** OPEN RESEARCH OBLIGATIONS; NOT A QKD SECURITY THEOREM.
**Baseline:** `8919cfb1a0fafe453f29cf46280f8e34020df0be` (S3.D).
**Scope:** QST-1 target B (conditional idealized model), separate from production authorization.

## 1. Security experiment

Let `T` be the full authenticated **public** transcript, including the pre-acquisition proof profile, all basis announcements, first-hit/quota/cap and accept/abort information, X-subset indices, Z test disclosures, EC syndromes, matrix seeds, confirmation tag and seeds, public PA seed/output length, and terminal transcript binding. Let `E` be Eve's final quantum system, including any quantum memory and information derived from the public interaction. Alice and Bob output either abort or keys `K_A`, `K_B` of agreed length `ell`. For composability, the public abort/accept flag and output length belong to the distinguishing experiment.

**Correctness obligation:** `Pr[accept and K_A != K_B] <= epsilon_cor`. A passing confirmation-tag unit test does not imply that full-protocol inequality.

**Secrecy obligation:** Define the subnormalized accepted-branch cq-state `rho_acc(K_A,E,T,ell)` and ideal `sigma_acc = U_ell(K_A) tensor rho_acc(E,T,ell)`, with the same public-transcript/length marginal and the same acceptance weight. Require `1/2 ||rho_acc - sigma_acc||_1 <= epsilon_sec` (or explicitly document a different ideal-resource convention and any conversion). For variable `ell`, use a classical length register and blockwise ideal uniform keys conditioned on public length. The abort branch contains no key. The full real/ideal resource must also cover correctness, authenticated communication, and arbitrary external distinguishers. **This is a required definition, not a bound demonstrated by this code.**

Authenticated-channel idealization incurs a **computational** reduction for actual HMAC-SHA256 frames. A future hybrid argument may produce a total distinguishing-advantage upper bound from separately proved component bounds; merely adding desired epsilon numbers is not a proof. Quantum secrecy and correctness terms must share coherent accepted/abort and smoothing conventions.

## 2. Frozen research boundary

The S4.E authenticated `ProofProfile` precedes acquisition. S4.F forces OS-mode simulated acquisition with declared quotas and basis probability; S4.G empirically checks BB84 circuit statistics and one intercept-resend attack. S3.D reserves one public root identity on a trusted single-host, no-rollback filesystem and accepts a caller-*asserted* externally provisioned secret. It does not attest credential origin, prove quantum randomness independence, or prove that distinct remote peers own isolated secrets.

The current S3.C outer frame chain has 2 proof frames, 9 H2 frames, `ceil(n_key/128)` EC syndrome frames, 3 EC confirmation/ack/commit frames and 3 PA agreement frames. **S3.D's `17+ceil(n_key/128)` cap is a resource cap, not an authentication-forgery bound.** Account for legacy/inner H2 and EC MACs, KDF derived keys, chosen-message/verification queries, shared-root assumptions, and total key uses in an eventual authentication reduction.

## 3. Finite-key ledger: keep two routes distinct

Route A (`m1g3_tomamichel_bound.py`): TLGR-2012 Eq. (2) gives an unqualified **numerical candidate**, contingent on the exact theorem hypotheses and exact protocol correspondence. The current quota-first-hit plus public hard cap and `k_actual >= k_min` require a proof of correspondence; the S4.D public-filter argument is *conditional*, not a validated reduction. Never treat a positive computed length as a certified entropy statement.

Route B (`m1e3_finite_key.py`): externally justified pre-EC conditional min-entropy is required before any extraction calculation. The code currently has no independently authenticated proof of that input. For this route, subtract separately accounted EC syndromes and confirmation tag, then apply the matching PA leftover-hash penalty; do not duplicate a confirmation debit already represented by `epsilon_cor` in Route A. Account for all public selection, stopping, disclosed Z bits and security-relevant tags in the chosen proof convention.

## 4. Obligations — all remain OPEN

| ID | Required mathematical/security deliverable | Review criterion |
|---|---|---|
| L1 | Ideal BB84 state/source and trusted receiver hypotheses | Explicit mathematical model matched to code; no physical attestation claim |
| L2 | General quantum Eve, causal interaction and basis-independent detection | Valid adversary experiment and source independence assumptions |
| L3 | Stop-first quotas, full matched-Z disclosure, random X subset, public cap | Exact coupling or alternate theorem with treatment of `k_actual` |
| L4 | Smooth `H_min^epsilon(X|E,T_preEC,accept)` | Reviewable accepted-branch sampling/uncertainty derivation |
| L5 | Full EC leakage/correctness accounting | All syndrome and key-dependent public disclosures charged once |
| L6 | Quantum-proof Toeplitz privacy amplification | Uniform seed, universality, parameter agreement, smoothing conversion |
| L7 | Actual HMAC/KDF/multiframe security | Cryptographic game, query ledger, credential assumptions and reduction |
| L8 | End-to-end composability / future HPKE interface | Real/ideal hybrid argument and separately reviewed export boundary |

The TLGR paper's published Box 1 does employ matched-basis quota stopping, a random X key subset and all matched Z test bits. This correspondence is promising but does **not** discharge the paper's supplementary assumptions, the bounded-cap coupling, or the application-level cryptographic composition. The Supplementary Notes have not been independently audited line by line here.

## 5. Planning epsilon ledger — not a theorem

`PlanningBudget` requires decimal-string secrecy/correctness/authentication budgets and a total target. It computes their exact decimal sum and flags whether the **planned** sum fits the target. It never reports a proved bound. For every invocation, `security_model_validated=false`, `security_qualified=false`, `hpke_export_authorized=false` and `qkd_psk_available=false`. A diagnostic report claiming positive qualification is rejected. No caller-supplied Boolean or numerical candidate can discharge L1-L8.

The current one-root S3.D profile is an experimental *operational assumption*, not a proved `epsilon_auth`. Avoid formulas like `frames/2^256` without a reduction. The `1e-12` per-session total and 256-bit HPKE PSK remain QST-1 design targets only.

## 6. Next proof increments

- **S5.B:** Independently review TLGR supplementary notes, freeze the exact accepted-branch protocol, and either prove quota/cap coupling or explicitly revise the protocol.
- **S5.C:** Establish smooth min-entropy and precise EC/correctness/PA composition; verify probability and sampling conventions.
- **S5.D:** Supply computational HMAC/KDF authentication bound and explicit hybrid composition, including multi-user/multisession assumptions.

Until these steps and independent review, no security qualification or production QKD-derived HPKE export can be enabled.

## References

- Tomamichel, Lim, Gisin, Renner, *Tight finite-key analysis for quantum cryptography*, Nature Communications 3:634 (2012), https://doi.org/10.1038/ncomms1631 (Box 1, Eq. 2; supplementary proof review outstanding).
- RFC 9180, *Hybrid Public Key Encryption*, https://www.rfc-editor.org/rfc/rfc9180 (PSK interface and entropy requirements; separate security argument necessary).
- Repository source: `security/QST-1.md`, `security/S4D_ENTROPY_PROOF_APPLICABILITY.md`, `security/S4C_FINITE_KEY_EQUATION_LEAKAGE_AUDIT.md`, `security/S3D_AUTHENTICATION_CONTRACT.md`.
