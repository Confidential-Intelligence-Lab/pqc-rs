# M1.H3.B: integrated randomness and authenticated BB84 sampling

This diagnostic connects H3.A's domain-separated randomness provider to H2's authenticated public-discussion path without claiming QKD secrecy.

- `fixture` uses deterministic, publicly reproducible PRNG streams for tests. `os` uses OS-backed CSPRNG choices for simulated Alice/Bob bits/bases and subset selection. Neither qualifies physical quantum measurement randomness.
- Quota acquisition uses oversampling to permit nontrivial random selection without replacement. This is **not** a proof that the stopping/sampling distribution matches Tomamichel et al. 2012, Box 1.
- H2 authenticates basis announcements, selected positions, Z-test disclosures, and the error decision. The authentication key is generated locally for the experiment; independent authenticated-channel provisioning and its security budget are **not** established.
- All outputs remain unqualified. `security_model_validated`, `security_qualified`, and `hpke_export_authorized` are false.
- No raw key bits or secret seeds are printed, saved, or exported. The test-basis values are public by design; their public disclosure must be treated appropriately in any eventual theorem-specific proof.
- Distribution smoke tests check statistical behavior for selected cases, not an information-theoretic guarantee.

## Subsequent work

Compare the *exact* stop-and-sample procedure against the pinned BB84 protocol theorem, including the conditional distribution of accepted matched-basis events and aborted runs; then integrate correct authenticated provisioning, error correction and composable leakage/security accounting.
