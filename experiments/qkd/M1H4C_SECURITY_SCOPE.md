# M1.H4.C - Structural conformance-gap audit

This module does **not** prove QKD security or theorem conformance. It checks current
H2/H3.A/H3.B source patterns (fail-closed on unexpected revision) and enumerates
short public-basis traces to demonstrate a precise parameter-estimation mismatch.

The current acquisition stops when X and Z matched-basis quotas have been reached.
Matched Z positions may continue to accumulate after the Z quota is filled while
waiting for the X quota. The authenticated H2 protocol then discloses a random
subset of size `k_test` from the entire eligible Z set. The selected finite-key
protocol instead uses all matched Z observations for its parameter-estimation
statistic. Even `oversample=1` does not eliminate that discrepancy. An extra
transmission-limit abort and any oversampling require independent justification.

The three-frame public-basis witness `ZZX` with quotas (1,1) finishes at frame 3,
with two eligible Z positions, while H2 discloses only one. This is a structural
counterexample to *exact protocol equivalence*, not a demonstrated attack.

The audit validates neither a quantum-device model nor authentication-key
provisioning, reconciliation, privacy amplification, or composable secrecy.
No raw bit values or keys are exported. Security-model and HPKE-export flags
are intentionally always false. Research literature is maintained separately.
