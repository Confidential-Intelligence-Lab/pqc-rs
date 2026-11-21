# S2.B3 — composable evidence and numeric-budget audit (unqualified)

This additive module **does not derive certified quantum min-entropy** and
**cannot authorize a QKD-derived PSK**. It inspects the SHA-256 fingerprints of
the existing source chain, checks public sizes and syndrome disclosures, and
computes a *diagnostic* finite-key Equation (2) result under **assumed** source
preparation quality and security parameters.

The module distinguishes two distinct accounting perspectives:

1. **Reference Equation (2):** `leak_EC` is the syndrome disclosure. The
   correctness-hash expense enters the theorem formula through `epsilon_cor`.
   Its 40-bit tag is not subtracted a second time. The calculated upper
   length is not a security-qualified lower min-entropy bound.
2. **Alternative proof-work allocation:** the sums for parameter-estimation,
   smoothing, and privacy-amplification budgets are checked against a top-level
   secrecy target. These are planning allocations, not independently proven
   guarantees and not additional subtractions to Equation (2).

A conservative top-level *planning envelope* checks
`epsilon_sec + epsilon_cor + epsilon_auth <= epsilon_total`. This does not
establish any authentication bound because the current channel key provenance
is not qualified. No external evidence document, ID, boolean flag, or user
assertion is treated as proof. Source hashes establish code identity only.

Outstanding work: exact quantum sampling and preparation-quality hypotheses;
independent proof review; authenticated-channel key provisioning and MAC
security bound; reconciliation transcript and privacy-amplification proof
mapping; and secure-provider/HPKE composition. In particular, an observed
classical QBER and an idealized CUDA-Q simulator do not establish Eve's
conditional min-entropy.

The generated diagnostic contains public parameters and source hashes only.
No raw key bits, authentication secrets, or device secrets are accepted.

All security and export flags remain permanently false in this milestone.
