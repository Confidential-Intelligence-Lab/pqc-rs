# M1.H1 — Experimental Box-1-oriented sampling

This experimental component changes the **candidate** raw key to the X basis and the
parameter-estimation sample to the Z basis, matching the labeling in Tomamichel,
Lim, Gisin, and Renner, *Nature Communications* 3, 634 (2012), Box 1.

It samples without replacement from matched-basis populations. The existing
G5.C1 record generator still uses public deterministic randomness and aggregate
quota acquisition; this program does **not** authenticate the sample-selection
announcement or establish that stopping and postselection reproduce the exact
security theorem. The reported seed is explicitly a reproducible simulation fixture.

## Gaps blocking security-model validation

- Independently provisioned authentication key and authenticated sample choice.
- Exact Box 1 stopping/selection analysis, including detection/no-click behavior.
- Private independent preparation and basis randomness (or explicit ideal model).
- Correctness check, explicit reconciliation leakage, universal hashing, complete
  security-parameter budget, and independent protocol review.
- No QKD-to-HPKE export in this milestone.

This file is **implementation security-scope documentation**, not a paper bibliography.
The related-work ledger and references are maintained in the research chat only.

`SECURITY_MODEL_VALIDATED=false` and `HPKE_EXPORT_AUTHORIZED=false` unconditionally.
