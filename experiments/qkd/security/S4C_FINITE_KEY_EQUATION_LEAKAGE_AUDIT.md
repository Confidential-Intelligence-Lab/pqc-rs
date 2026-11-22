# S4.C — Finite-key equation and public-leakage audit

**Project:** PQC-rs goes Quantum
**Status:** RESEARCH AUDIT / UNQUALIFIED — no theorem instantiated
**Version:** 0.1 (2026-11-21)
**Implementation baseline:** `research/qkd-security-qst1`, `b14eed5898e9f4618f5f89069ccf0f9ef9051551`
**Parents:** `security/QST-1.md`, `security/S4A_QUANTUM_SOURCE_ADVERSARY_MODEL.md`, `security/S4B_THEOREM_IMPLEMENTATION_CORRESPONDENCE.md`

## 1. Review outcome and principal caution

The TLGR-2012 article's main-text Equation (2) is represented numerically in `m1g3_tomamichel_bound.py`. The calculation is **only a theorem-shaped numerical candidate**. S4.B's outstanding source-model, cap, causal ordering, sampling/conditioning, and composable authentication proof obligations still block theorem application. This S4.C increment audits the published main-text formula and current source-level public disclosures; it does **not** certify positive conditional min-entropy, extracted keys, or production HPKE export.

The paper's Methods expressly identify `leak_EC + ceil(log2(1/epsilon_cor))` bits of key-dependent classical communication before privacy amplification (up to the stated rounding convention). Thus, when evaluating **the paper's Equation (2)**, do not subtract the confirmation tag **twice**. Conversely, the code's distinct `m1e3_finite_key.py` conditional min-entropy interface explicitly deducts both the syndrome disclosure and confirmation tag, and uses a separate leftover-hash penalty. These are **different security-accounting routes**; neither is automatically equivalent without checking smoothing/error conventions.

## 2. Exact main-text TLGR Equation (2) transcription

For the paper's protocol `Phi[n,k,ell,Q_tol,epsilon_cor,leak_EC]` and preparation quality `q`, its sufficient secret length condition is

```text
ell <= n [ q - h_2(Q_tol + mu) ] - leak_EC
       - log_2( 2 / (epsilon_sec^2 * epsilon_cor) )

mu = sqrt( ((n+k)/(n*k)) * ((k+1)/k) * ln(2/epsilon_sec) )

h_2(x) = -x log_2(x) - (1-x) log_2(1-x)
```

Here `k` is the theorem's test-sample parameter, not automatically the configured minimum quota `k_test`; the implementation reports all eligible matched Z observations as `k_actual`. `q` is *source preparation quality*, defined by the selected theorem—not the observed QBER. The argument `Q_tol + mu` must lie in the relevant domain of the entropy-bound reasoning. The current numerical code conservatively reports no useful candidate if it is `>= 1/2`; this is a numerical fail-closed policy, not a replacement for the proof. Calculations require `epsilon_sec`, `epsilon_cor` and all inputs to be interpreted exactly as in the published theorem and supplementary lemmas. Correctness and secrecy composability does not automatically include HMAC authentication failure.

**Source read:** TLGR *Nature Communications* **3**, 634 (2012), Box 1 and Methods, especially Equations (2), (6)–(9). https://pmc.ncbi.nlm.nih.gov/articles/PMC3274703/ ; DOI https://doi.org/10.1038/ncomms1631 . **Supplementary Notes S1–S2 are an explicit unresolved line-by-line proof-review task**, not certified by reproducing the main-text equation.

## 3. Source-level disclosure ledger

| Message or data | Current module | Key-dependent disclosure accounting | Interpretation / unresolved condition |
|---|---|---|---|
| Alice/Bob basis vectors and eligible index sets | `m1h2_authenticated_sampling.py` | Condition on transcript; do not naively call all public bits extra EC leakage | Random-choice/acceptance conditioning must be included in sampling/entropy theorem |
| All matched Z test bits, per role | `m1h2_authenticated_sampling.py` | Condition on exposed test strings and selection | Test bits are not retained X bits; security reduction must treat sample selection correctly |
| Chosen X positions and public quota/abort status | H2 / S3.C | Condition on transcript and accepted branch | Selection independence and stop/cap proof still open |
| S2.A2 syndrome per 128-bit block | `s2a2_syndrome_reconciliation.py` | **32 bits per block**, at most `32 * ceil(n_key/128)` announced parity bits | This is a raw announced-bit upper bound; no claim of tight information-theoretic leakage |
| S2.A2 matrix seed and block indexing | `s2a2_syndrome_reconciliation.py` | Public 128-bit seed per block; indices, widths, and matrix selection metadata | Seed independence must be justified. Public randomness does not automatically imply raw-key leakage equal to seed length; remain conditioned on full transcript |
| S2.A1 Toeplitz confirmation seed | `s2a1_universal_confirmation.py` | `n_key + tag_bits - 1` **public seed** bits | Seed is intended independent of fixed raw keys; audit independence and any additional selection/acceptance effects |
| S2.A1 confirmation tag | `s2a1_universal_confirmation.py` | **tag_bits** public key-dependent bits (e.g. 40) | Under TLGR Eq. (2), correctness cost is inside `epsilon_cor`; do not subtract again. Under `m1e3`, subtract explicitly |
| S3.C EC acknowledgement/commit, status | `m2a_authenticated_distillation.py` | Contains acceptance, block count, confirmation digest, transcript digest | Acceptance conditioning must be included; hash of public message is not an independent secret |
| S3.C PA parameters, public Toeplitz seed | `m2a_authenticated_distillation.py` and `m1e2_privacy_amplification.py` | Public seed of `n_key + ell - 1` bits | Fresh independence needed. No key bytes should appear on the wire or public report |
| Authenticated MAC tags and frame metadata | `s3c_authenticated_transcript.py` and transitional legacy MACs | Tags derive from provisioned authentication key, not QKD raw key | Authenticate whole transcript; quantify MAC forgery under chosen computational assumption and key-use policy |

**Worst-case syndrome ledger:** For `n_key=128`, `256`, `257`, and `65536`, declared syndrome disclosure upper bounds are respectively `32`, `64`, `96`, and `16384` bits. A final partial block still consumes a complete 32-bit syndrome. A future report must bind the actual number of messages, matrix construction, and the precommitted block cap to the authenticated transcript.

**Important audit distinction:** The declared syndrome/tag disclosure sum is `32*ceil(n_key/128) + tag_bits`. In the TLGR Equation (2) route, use the syndrome contribution for `leak_EC` only if **all** proof-relevant EC disclosures are covered and the correctness term is the one justified by the actual confirmation procedure. In the `m1e3` route, the sum is subtracted from independently justified *pre-leak* conditional entropy. Do not mix the two routes or re-charge the same public confirmation tag.

## 4. Two noninterchangeable numerical routes

**Route A — TLGR-2012 theorem-shaped numerical formula.** `m1g3_tomamichel_bound.evaluate` takes `n_key`, `k_test`, `q_tolerance`, syndrome `leakage_ec_bits`, `epsilon_secrecy`, `epsilon_correctness`, `preparation_quality`. Its output is `NUMERICAL_CANDIDATE` or `NO_KEY`, with `protocol_assumptions_verified=false`; it **must not be used as authenticated entropy evidence or key-export authorization**. The `k_test` argument requires independent review for exact `k_actual` correspondence.

**Route B — externally justified entropy plus quantum leftover-hash length.** `m1e3_finite_key.evaluate` takes an *externally proved* `H_min` estimate for the pre-EC retained key, requires an `entropy_evidence_id`, subtracts explicitly specified reconciliation and confirmation bits, then applies `2 log2(1/(2 epsilon_pa))` as a numerical extraction penalty. A test-supplied identifier is only a string, **not a cryptographic certificate**. Even `CONDITIONAL_PASS` returns `security_qualified=false`, `hpke_export_authorized=false`. The precise smoothing penalty, entropy-convention provenance and acceptance conditioning need proof review before Route B could instantiate a theorem.

## 5. Outstanding proof obligations, classified

| Priority | Obligation | Completion condition |
|---|---|---|
| P0 | Read and audit TLGR Supplementary Notes S1–S2 | Line-referenced sampling/uncertainty/smoothing assumptions and exact theorem definitions |
| P0 | Stop/quota/cap applicability | Signed-off accepted-branch argument for `tau<=M_max`, or theorem-matched protocol change |
| P0 | `k_min` versus `k_actual` | Sound use of actual matched test count, including overshoot and public stopping history |
| P0 | Pre-EC `H_min^epsilon(X | E,T_preEC,accept)` | Formal derivation under general Eve and declared ideal model; not a QBER substitution |
| P1 | Correctness confirmation | Show `epsilon_cor` from fresh-seed universal hashing and precisely defined abort/agreement |
| P1 | Reconciliation leakage | Prove complete accounting of key-dependent disclosure, including any adaptive choices |
| P1 | PA universality and independent seed | Prove Toeplitz mapping and seed distribution under exact encoding and transcript |
| P1 | Authentication and composition | HMAC reduction and per-key/per-frame budget, explicit computational-versus-IT claim |
| P1 | Numerical independent reproduction | Cross-check main-text formula, edge cases and exact rounding, without overclaiming |
| P2 | Sensitivity and robustness | Quantify hypothetical lengths, abort rates and sample-size dependence only after model correspondence |

**Potentially consequential design issue:** the current `s2a2_syndrome_reconciliation.py` derives public parity-check matrices via Python's `random.Random` seeded with SHA-256 of a public seed. This is not, by itself, proof of a statistically independent information-theoretic matrix ensemble. Treat it as a deterministic public experimental construction; count its syndrome bits conservatively and examine whether the security argument requires anything beyond publicly selected parity-check matrices.

## 6. Executable arithmetic checks (S4.C increment)

`test_s4c_finite_key_ledger.py` contains eight tests: an independent high-precision `decimal` reconstruction of main-text Equation (2) versus `m1g3_tomamichel_bound.py`; no-key large-deviation behavior; 128-bit-block ceiling ledger; explicit separation of 32-bit syndrome and confirmation tag; QBER not serving as entropy evidence; hypothetical positive length staying unqualified; `epsilon_cor` term versus confirmation-tag double counting; and preservation of negative security/export flags.

These tests check **arithmetic and source-level bookkeeping only**, not TLGR theorem applicability, quantum min-entropy, or composable secrecy. Any numerical candidate remains non-exportable.

## 7. Research notebook — S4-003

- **Baseline:** `b14eed5898e9f4618f5f89069ccf0f9ef9051551`, branch `research/qkd-security-qst1`.
- **Finding:** TLGR Eq. (2) incorporates correctness through its `epsilon_cor` term; `m1e3` is a separate min-entropy-conditioned extraction calculation that explicitly subtracts confirmation leakage. Their intermediate quantities cannot be conflated.
- **Code audit:** S2.A2 transmits `32 * ceil(n/128)` syndrome bits; S2.A1 exposes a `tag_bits` confirmation digest and a fresh `n+tag_bits-1` public seed. All claims about the independence, security of sampling, and authenticated transcript remain conditional.
- **Evidence pending:** Eight S4.C tests on EdgeExpert; supplementary line-by-line review; independent mathematical security review.
- **Required invariant:** `security_model_validated=false`, `security_qualified=false`, `hpke_export_authorized=false`, `qkd_psk_available=false`.
- **Next:** S4.D proof-condition closure or protocol revisions; do not enable QKD-derived production HPKE export.
