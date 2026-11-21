# M1.G5.A — Quota-based BB84 sifting diagnostics

This additive experiment keeps collecting until both requested matched-basis
quotas (Z and X) are reached or a strict transmission limit triggers abort.
Matched-basis observations beyond their quota are discarded; the report
accounts for those discards separately from basis mismatches.

**Security status:** Not security-qualified. Source bits and basis choices use
reproducible `random.Random` seeded from an experiment identifier. Classical
basis announcements are not authenticated; only aggregate counts are retained;
no final key is generated or exported. This does not implement all sampling,
randomness, sifting, or correctness conditions of Tomamichel et al. (2012).
Quota fulfillment is *not* protocol conformance or a finite-key proof.

The test `test_attacked_channel_has_errors` injects deterministic measurement
corruption as a unit-test fixture; it does not establish a specific QKD attack
model. CUDA-Q intercept-and-resend remains available via the experiment CLI.

Acceptance markers:
- `QKD_M1G5A_QUOTA_SIFTING_STATUS=PASS` — executable completed its diagnostics
- `QKD_M1G5A_SECURITY_MODEL_VALIDATED=false` — protocol proof remains pending
- `hpke_export_authorized=false` — never generate/export keys from this module

Required follow-up: authenticated sifting and sample selection; a matching
published theorem's sampling and stopping protocol; secure-randomness
assumptions; correct finite-key and leakage/composable budgets; independent
protocol-level conformance checks.
