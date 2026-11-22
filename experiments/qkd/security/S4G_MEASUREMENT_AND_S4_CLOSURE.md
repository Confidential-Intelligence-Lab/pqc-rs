# S4.G - Quantum measurement evidence and S4 engineering closure review

**Project:** PQC-rs goes Quantum
**Status:** Experimental engineering evaluation - UNQUALIFIED
**Source baseline:** `research/qkd-security-qst1`, following S4.F
**Security decision:** Model/conditional theorem applicability OPEN; simulated QKD-to-HPKE export DENIED.

## 1. Scope and decision

S4.A-S4.F established an idealized source specification, theorem correspondence review, finite-key numerical audit, public-abort reasoning, authenticated proof-profile precommitment, and profile-to-acquisition mapping. S4.G adds actual measurement-distribution evidence from the CUDA-Q kernel and one diagnostic intercept/resend channel. **This can close the specified S4 engineering experimental checklist, but NOT the S4 quantum entropy/security proof requirement.** Completion of tests has no bearing on whether idealized BB84 is secure against general quantum attacks under the precise implemented protocol.

## 2. Exact idealized BB84 experiment

The audited kernel prepares `H^a X^x |0>` and measures in basis `b` by applying `H^b` before Z measurement, with `a,b` in {0,1}; Z=0, X=1. Ideal behavior is:

| Alice bit x | Preparation basis | Bob basis | Pr[Bob=1] |
|---|---|---|---|
| 0 | Z | Z | 0 |
| 1 | Z | Z | 1 |
| 0 | X | X | 0 |
| 1 | X | X | 1 |
| 0 or 1 | Z | X | 1/2 |
| 0 or 1 | X | Z | 1/2 |

All eight distinct `(bit, preparation_basis, measurement_basis)` inputs are exercised with a predeclared shot count. For an ideal Bernoulli parameter p, the empirical fraction should lie within the union-bounded Hoeffding radius `sqrt(ln(2m/alpha)/(2N))`, with m=8 simultaneous tests. This is a **statistical diagnostic**, not a hypothesis-based quantum-security proof. A finite number of simulations cannot verify exact probabilities, distributional independence, or source fidelity outside the simulator.

## 3. Intercept/resend experiment and interpretation

For **full** intercept/resend with Eve choosing Z or X uniformly, idealized lossless BB84 with independently chosen uniform Alice/Bob bases has 1/4 sifted-key QBER: when Eve chooses the wrong basis (probability 1/2), her replacement yields a wrong Bob bit with probability 1/2. The simulator test conditions on Alice and Bob having matching bases. The intercept/resend test uses a deterministic *diagnostic* `random.Random` stream for classical choices and makes two calls to the measurement oracle per trial; the injected reference oracle used by unit tests is not CUDA-Q.

The CLI's default backend calls the actual CUDA-Q `measured_bit()` per shot and reports a SHA-256 fingerprint of the source kernel. It **does not** generate secret keys, derive min entropy, attest devices, or model coherent Eve. One intercept/resend test is not evidence of security against general attacks.

## 4. S4 gate disposition

| Increment | Engineering evidence | Formal security disposition |
|---|---|---|
| S4.A | Ideal source/adversary assumptions recorded | Unverified assumptions |
| S4.B | Observable correspondence matrix and tests | Full TLGR applicability OPEN |
| S4.C | Equation (2) arithmetic and explicit disclosure ledger | No proved min entropy |
| S4.D | Abort-filter contraction model and first-hit tests | Capped protocol coupling OPEN |
| S4.E | Authenticated pre-acquisition profile and replay denial | Computational authentication model/provisioning OPEN |
| S4.F | Source AST guard, constrained acquisition and numerical parameter forwarding | Device attestation/independence OPEN |
| S4.G | Eight-case quantum measurement diagnostics and full-intercept sample | Statistical model conformance only |

**Engineering S4 gate:** Eligible for closure only after S4.G CPU unit tests, actual EdgeExpert CUDA-Q experiment, full QKD regression, artifact capture, and code review all PASS. If the actual CUDA-Q experiment fails, keep S4.G open and investigate.

**Security S4 gate:** Remains OPEN. Specifically, prove correspondence for quantum source/receiver assumptions; stopping and quota/cap coupling; general quantum Eve; parameter estimation with realized `k_actual`; full public transcript conditioning; smooth conditional min entropy on accepted branches; leakage and security parameter allocation; extractor theorem. Independent review is required. Do not mark `QST-ENT-01` or `QST-QKD-01` satisfied just because all tests pass.

## 5. Reproducible evidence collection

Use EdgeExpert's CUDA-Q environment (normally the configured `.venv`). Record the CUDA-Q version, Python version, Git SHA, CLI arguments, machine architecture, target/simulator configuration and resulting JSON. The CPU test oracle is deterministic and labelled not CUDA-Q. The actual CUDA-Q sample is stochastic, so repeated trials and statistical summaries matter; avoid reporting one run as a precision calibration.

Commands after installing files:

```bash
python3 -m unittest discover -s experiments/qkd -p 'test_s4g_measurement_evidence.py' -v
python3 -m unittest discover -s experiments/qkd -p 'test_*.py' -v > /tmp/qkd_s4g_full.log 2>&1
python3 experiments/qkd/s4g_measurement_evidence.py --shots 256 --attack-trials 1024 --output /tmp/qkd_s4g_cudaq.json
```

No output of this module is a credential or authorization. No positive security flags should be added to its report. The final manuscript should use phrases such as *'idealized CUDA-Q measurement and intercept-resend behavior agrees with theoretical expectations at the tested sample sizes'* rather than *'QKD security validated.'*

## 6. S4 closure decision / research notebook - S4-007

- Engineering status: **PENDING EDGEEXPERT S4.G AND REGRESSION EVIDENCE**.
- Quantum-security theorem: **NOT PROVED**.
- Authenticated cryptographic-security composition: **S3.D and S5 OPEN**.
- Trusted QKD-derived HPKE PSK provider: **S6 OPEN**.
- Production export: **DENIED**, regardless of experimental results.
- Suggested next research step after experiments: targeted S4 proof workshop/independent review, followed by S5 composition. Implement source/model changes only when needed to discharge a specific theorem obligation.
