# Stage 11A — Existing Harness Wiring

Stage 11A enables manifests for the timing and generated-code evidence developed
in Stages 9F and 10B. A compatibility adapter discovers historical scripts or
Cargo targets and normalizes their output.

Enabled experiments:

- Stage 9F-2A fixed-challenge negative control
- Stage 9F-2A matched-distribution test
- Stage 9F-2A varying-challenge positive control
- Stage 9F-3A conditioned residual timing
- Stage 9F-3A within-attempt timing
- Stage 10B-2 constant-time byte comparison
- Stage 9F-4 generated machine-code audit
- Stage 10B-4 zeroization audit

A missing historical target produces `inconclusive`, never a false pass.
The varying-challenge experiment is intentionally a positive control and uses a
minimum absolute t-statistic threshold of 4.5. Negative-control and leakage
regression experiments use a maximum absolute threshold of 4.5.

Run:

```bash
./scripts/run-stage11a.sh
```

Reports:

```text
target/stage11a/report.json
target/stage11a/report.md
```
