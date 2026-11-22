# S5.D-2: Cascade-style QKD reconciliation research experiment

**Status:** RESEARCH-ONLY ALTERNATIVE; not installed into S3.C/S4.E; no secrecy or HPKE-export qualification.

The previous 128-bit/32-row syndrome scheme guarantees at most two errors corrected per block. Under independent Bernoulli X-key errors with p=0.02, a 16,384-bit key has 128 blocks; the probability *all* blocks lie within the guarantee is approximately 2.516e-36, although this is not the actual acceptance rate.

This increment implements a randomized-permutation, multi-pass Cascade-style iterative parity and backtracking method, inspired by the QKD reconciliation literature. It explicitly exposes both Alice and Bob parity bits per query, authenticates each local-model frame with HMAC-SHA256, caps parity query count and aborts on failure. Fresh independent Toeplitz key confirmation runs after reconciliation. The seed is public and independent; deterministic test fixtures use a fixed seed. Both endpoints are simulated in the **same process**; authenticity is **not independently established on a distributed wire**.

The public-parity disclosure budget is conservatively **2 bits per parity pair**, plus the public confirmation tag. Query subsets are reconstructible from public seeds and previous parity outcomes; this is a structural *research accounting* argument, not a composable proof. HMAC tags are keyed with independently provisioned secret in a real design; the actual multiframe computational reduction remains OPEN. The complete implementation transcript (including its framing, public seed, selection timing, and assumptions about Eve and reconciliation feedback) is not yet covered by the TLGR finite-key theorem. Never substitute this variable-length disclosure into TLGR Eq. (2) as a certified key bound without proving the relevant leakage treatment and acceptance behavior.

Algorithmic performance and leakage must be evaluated on reproducible X-basis error traces. A 2% i.i.d. X-basis bit-error model is a robustness benchmark only, **not** a bound inferred from Z-basis parameter estimation or an attack against general quantum Eve.

No production HPKE key is exported; `security_qualified=false` and `hpke_export_authorized=false` must stay false. This is an independent experiment, not yet the default reconciliation path.

References:
- Brassard and Salvail, *Secret-key reconciliation by public discussion*, EUROCRYPT 1993 / LNCS 765 (1994).
- https://www.nature.com/articles/ncomms3363 (experimental finite-key QKD with Winnow error reconciliation)
- https://link.springer.com/article/10.1007/s11128-024-04395-w (public parity leakage and Cascade design).

The frozen-profile benchmark is `s5d2_cascade_benchmark.py`; it reports only input error counts, reconciliation acceptance, and public disclosures for eight default 16,384-bit iid trials. No secret material appears in its JSON report. A 2%% iid trial is only a robustness experiment. The 4,096-bit S5.C syndrome parameter is not valid for this alternative; the *observed* parity leakage must replace it in noncertifying candidate calculations and a deterministic maximum must be established for any theorem-supported claim.
