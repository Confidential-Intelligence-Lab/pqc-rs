# M1.H3.A — Randomness abstraction for idealized BB84 experiments

This module separates deterministic, publicly reproducible **fixtures** from
OS-backed cryptographic randomness. It introduces independently domain-separated
Alice source-bit, Alice basis, Bob basis, Eve diagnostic and sampling streams.
It does not establish independent physical quantum entropy or certify a QKD key.

- `fixture` requires an explicit nonnegative integer seed and uses deterministic
  domain-separated SHA-256 derivation followed by `random.Random`. This mode is
  NEVER secret, even if the seed is not printed.
- `os` (the default) forbids deterministic seeds and draws from Python's
  `secrets.randbelow`, which relies on OS-backed cryptographic randomness.
  This is a source-code/API statement, not a device-entropy certification.
- Alice and Bob have separate source/basis choice streams. This code is an
  orchestration harness with access to both peers' records; peer separation and
  authenticated announcements are exercised elsewhere in M1.G5.C1/M1.H2.
- An optional sample-index API performs uniform sampling without replacement,
  *conditional on the underlying generator being uniform*. It does not prove
  the overall stopping/sampling distribution of the theorem in M1.H3.B.
- The quantum measurement outcome is supplied by CUDA-Q or an injected mock.
  Its security-relevant stochastic properties are NOT validated here.
- No raw secret, source bit, basis vector, fixture seed, or extracted key is
  included in the experiment report. No QKD→HPKE export is authorized.
- The OS mode **does not** make `security_model_validated`, `security_qualified`,
  or `hpke_export_authorized` true. The complete theorem and classical-channel
  assumptions, correctness, and error budgets remain outstanding.

Both modes are simulation-only. Never use outputs as production QKD PSKs.
