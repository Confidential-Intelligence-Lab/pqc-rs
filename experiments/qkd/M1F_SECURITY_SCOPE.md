# M1.F — Experimental CUDA-Q BB84 distillation lifecycle

This is an **experimental workflow integration**, not a composably secure QKD protocol. It combines the existing M1.C BB84 simulator, M1.E1 authenticated *reconciliation* routine, M1.E2 Toeplitz hash, and M1.E3 conditional budget calculator.

## Workflow

1. Run the existing CUDA-Q BB84 simulator and collect *sifted* Alice/Bob bits in the same process. The current simulator does not expose preparation/measurement basis logs and does **not authenticate basis sifting**.
2. Select and discard a reproducible pseudorandom subset of sifted bits for diagnostic error estimation. This is **not** a security-proven BB84 phase-error sampling protocol.
3. Reconcile the remaining bits under a locally generated ephemeral MAC key; count explicitly disclosed parity and 128 confirmation-digest bits. This does not authenticate the original sifting operation or validate out-of-band initial MAC-key provisioning.
4. Execute the M1.E3 fail-closed budget evaluator. With no entropy proof (default), reject, and never perform Toeplitz extraction.
5. An opt-in `--demo-pre-leak-min-entropy-bits` option allows **hypothetical** assumptions to illustrate arithmetic and extraction. A `CONDITIONAL_PASS` means solely that the requested output length fits the *caller-supplied hypothetical* entropy bound. Neither correctness, security, nor completeness of the protocol follows from this setting. Do not use the result for HPKE.
6. Report metadata and timings; never print, save, or authorize export of any key bytes. No physical-QKD claims.

`security_model_validated=false`, `security_qualified=false`, `hpke_export_authorized=false` remain unconditionally false even with demonstration-only extraction.

## Scientific and security caveats

- The CUDA-Q BB84 simulator uses reproducible `random.Random` values for source bits and bases. These are **not private cryptographic randomness**, so no min-entropy or secrecy can be assumed against an observer knowing the seed.
- The source currently discards basis metadata. The random sample of sifted bits used here is useful for demonstration but **cannot** be substituted for a basis-aware phase-error estimator valid against general quantum attacks.
- The E1 code's confirmation is a truncated SHA-256 digest; the declared 128-bit leakage is counted, but a rigorous, composable correctness proof and authentication budget are not implemented here.
- Reconciliation is a single-error-per-block pedagogical algorithm, not a complete high-QBER error-correction protocol. Some error patterns escape parity detection; confirmation catches mismatches with a residual collision risk.
- Toeplitz hashing is a reference implementation, not constant time. A publicly chosen random seed can be safe in the properly proven universal-hashing framework, but it does not compensate for missing entropy.
- Timing is a reproducible measurement procedure, not a performance guarantee; nondeterministic scheduling and quantum simulation can affect runtime.
- No qualified QKD PSK is supplied to Rust/HPKE.

## Reproducible commands

From the repository root, in the CUDA-Q virtual environment:

```bash
PY=~/research/cudaq-experiments/.venv/bin/python
"$PY" experiments/qkd/m1f_distillation.py --bits 2048 --seed 20261120 --intercept-percent 0
"$PY" experiments/qkd/m1f_distillation.py --bits 2048 --seed 20261120 --intercept-percent 100
# Optional arithmetic and agreement demonstration: NEVER security evidence
"$PY" experiments/qkd/m1f_distillation.py --bits 2048 --seed 20261120 --requested-key-bits 128 --demo-pre-leak-min-entropy-bits 650
```

Do not store experiment logs that contain key material; the runner deliberately never emits keys.

## Requirements before a security-model-validation claim

1. Select the precise ideal BB84 protocol model and a **peer-reviewed composable finite-key theorem**, including preparation quality, basis probabilities, sample sizes, abort conditions and all epsilon parameters. One candidate is Tomamichel, Lim, Gisin, Renner (2012), *Tight finite-key analysis for quantum cryptography*, https://doi.org/10.1038/ncomms1631. That theorem is **not implemented in M1.F**.
2. Extend the CUDA-Q simulator to preserve distinct X/Z matched-basis observations and execute exactly the theorem's parameter-estimation and phase-error sampling protocol (not the same-pool test/error heuristic). Secure randomness and an authenticated classical transcript must be accounted for or idealized under explicit, justified assumptions.
3. Implement the exact finite-sample deviation formula and derive a lower bound on conditional **smooth** min-entropy, including composability of smoothing, privacy-amplification, correctness, and authentication errors; check basis-dependent attacks and channel losses within the model.
4. Account conservatively for **all** public leakage, including reconciliation and confirmation, without double counting; use an explicitly proven correctness-check collision bound.
5. Verify at least three independent oracle test vectors against the theorem's equations, monotonicity, pathological/boundary inputs, attack sweeps, and abort cases; validate against an independently coded reference and review assumptions and proofs.
6. Allow `security_model_validated=true` **only for a named, formally stated simulated BB84 model** when the implementation matches the theorem, all prerequisites are mechanically checked, and the theorem and tests have passed review. This must **not** imply physical-device certification or that a reproducible seeded simulation creates secret keys.

A future security-validity badge must be separate from security-qualified key export, which requires separate security assessment of the entire QKD→HPKE construction.
