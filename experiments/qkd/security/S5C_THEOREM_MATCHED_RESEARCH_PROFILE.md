# S5.C: Frozen theorem-matched finite-key numerical research profile

**Repository baseline:** `ff2ba3c9d74220e01023b3ec35d9ae942953aa0d` (`research/qkd-security-qst1`)
**Disposition:** NUMERICAL CANDIDATE; QUANTUM SECURITY UNQUALIFIED
**Scope:** Idealized, lossless BB84/CUDA-Q source; no physical QKD module or HPKE key authorization.

## Sources and claim boundary

1. M. Tomamichel, C. C. W. Lim, N. Gisin, R. Renner, *Tight finite-key analysis for quantum cryptography*, Nature Communications 3:634 (2012), Box 1 and Eq. (2), https://pmc.ncbi.nlm.nih.gov/articles/PMC3274703/ .
2. ETSI GS QKD 005 V1.1.1 (2010), sections 4.3-4.7: scientific security proof versus implementation verification, https://www.etsi.org/deliver/etsi_gs/QKD/001_099/005/01.01.01_60/gs_QKD005v010101p.pdf .
3. TLGR Supplementary Notes S1-S2, `ncomms1631-s1.pdf` identified but not successfully reviewed in this increment. Formal theorem applicability remains open.

The published theorem binds secrecy to an exact quantum source, random preparation, receiver, adversary and classical postprocessing model. Matching its numerical equation does **not** establish that our implementation meets those hypotheses. The primary research output of S5.C is a frozen *candidate* profile suitable for theorem-mapping review.

## Frozen profile version 1

| Field | Value | Interpretation |
|---|---:|---|
| `n_key` | 16384 | Precommitted uniformly selected matched-X raw bits |
| `k_test_min` | 16384 | Precommitted minimum number of matched-Z test bits |
| `max_transmissions` | 100000 | Public abort cap; quantum coupling to TLGR remains unproved |
| `x_basis_probability_ppm` | 500000 | Alice/Bob nominal X selection probability 0.5 |
| `q_tolerance_ppm` | 20000 | Precommitted Z-QBER threshold 0.02 |
| `preparation_quality` | 1 | Idealized source assumption; not physical device evidence |
| `epsilon_secrecy` | 1e-10 | Desired TLGR finite-key secrecy parameter |
| `epsilon_correctness` | 1e-10 | Desired correctness parameter (requires implementation reduction) |
| `epsilon_authentication_target` | 1e-12 | Target only: HMAC advantage not proved |
| `epsilon_total_target` | 1e-9 | Desired aggregate bound, not achieved by the code |
| `block_size` | 128 | Syndrome-reconciliation block size |
| `syndrome_bits_per_block` | 32 | Explicit transmitted syndrome bits per block |
| `ec_leakage_upper_bits` | 4096 | 32 * ceil(16384 / 128); validate complete disclosures |
| `confirmation_tag_bits` | 64 | Separately tracked; TLGR Eq. (2) correctness penalty used |
| `requested_key_bits` | 256 | Candidate requested output length; never released by this stage |

The 100000-transmission cap is not a guarantee of reaching quotas for a given run; a run that does not reach quotas aborts. The profile is chosen for numerical feasibility, not to infer statistically measured robustness or hardware security. The source's 53-bit basis probability discretization and independence assumptions remain subject to review.

## Equation discipline

The TLGR Eq. (2) numerical evaluator is reused with the **predeclared** `k_test_min` rather than postselected `k_actual`. This is a conservative numerical choice, not a substitute for a proof of theorem applicability. Observed-Z overshoot is reported separately and is never allowed to change the numerical `k`. Other possible issues (quantum acceptance conditioning, source model, public leakage, true universal-2 families and computational authentication) are unchanged.

The candidate computes `mu = sqrt(((n+k)/(n*k))*((k+1)/k)*ln(2/eps_sec))` and the existing implementation's `n*(q-h2(Q_tol+mu)) - leak_EC - log2(2/(eps_sec^2*eps_cor))`. The expression includes an epsilon-correctness penalty; it does not justify subtracting the 64-bit confirmation tag a second time without checking the precise proof convention. The syndrome disclosure is explicitly 4096 bits, but the complete public transcript must still be audited before any theorem claim.

A positive `numerical_candidate_key_bits` or `requested_length_numerically_fits=true` is **not** proof of any number of secret bits. In particular, `epsilon_authentication_target` is a planned bound, not an achieved advantage. Do not assert the sum of these epsilon parameters is the proven composite security level.

## Approval checkpoints (S5.C -> S5.D/S5.E)

- Review TLGR Supplementary S1-S2 hypotheses and characterize the stopped, capped, general-Eve experiment. Prove a sound abort-filter coupling or revise acquisition to a theorem-compatible protocol.
- Reconcile the random/overshooting matched-Z sample and sampling correctness with a published theorem; inspect source preparation, measurement and basis independence assumptions.
- Check actual syndrome and confirmation disclosures, universal-2 hash families, and correctness failure probability; distinguish static leakage budget from full accepted transcript.
- Quantify authentication cost and provisioned-root consumption across all outer and inner authenticated messages. Match the computational/quantum composition definition.
- Independent review of the frozen source revision and theorem-to-implementation correspondence. Only then consider a conditional research-security disposition. A production QKD/HPKE authorization remains separate.

**Mandatory flags:** `security_model_validated=false`, `security_qualified=false`, `hpke_export_authorized=false`, `qkd_psk_available=false`.
