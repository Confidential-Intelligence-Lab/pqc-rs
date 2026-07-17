# Stage 11 — Systematic Side-Channel Evaluation Framework

Stage 11 introduces a reusable, manifest-driven framework for timing and other
side-channel regression experiments.

The framework does **not** claim that a passing threshold proves constant-time
behavior. It provides repeatable evidence, environment capture, regression
policy, and reviewable raw output.

## Design goals

- Experiments are declarative JSON manifests.
- Every run records the platform, toolchain, Git commit, duration, return code,
  output digest, and raw output.
- Each experiment is repeated independently.
- A parser extracts the last matching metric from each run.
- A policy converts measurements into `pass`, `fail`, or `inconclusive`.
- JSON and Markdown reports are generated together.
- No external Python packages are required.

## Initial scope

This increment establishes the framework and validates it with a synthetic
self-test. Existing Stage 9F and Stage 10B timing harnesses must be wired into
individual manifests before real evidence is collected.

## Experiment manifest

```json
{
  "schema_version": 1,
  "id": "ml-kem-decapsulation-validity",
  "description": "Compare valid and invalid ciphertext decapsulation timing.",
  "command": ["cargo", "test", "...", "--", "--nocapture"],
  "working_directory": ".",
  "repetitions": 5,
  "timeout_seconds": 600,
  "parser": {
    "type": "regex",
    "pattern": "welch_t=(-?[0-9]+(?:\\.[0-9]+)?)",
    "metric": "welch_t",
    "absolute": true
  },
  "policy": {
    "maximum": 4.5,
    "minimum_successful_repetitions": 5
  },
  "tags": ["ml-kem", "decapsulation", "timing"],
  "enabled": true
}
```

## Commands

Validate the framework and the workspace:

```bash
./scripts/run-stage11.sh
```

List experiments:

```bash
python3 scripts/stage11_sidechannel.py --list
```

Run enabled experiments:

```bash
python3 scripts/stage11_sidechannel.py
```

Reports are written to:

```text
target/stage11/report.json
target/stage11/report.md
```

## Exit status

- `0`: all enabled experiments passed, or no enabled experiment failed.
- `1`: at least one experiment failed its policy.
- `2`: at least one experiment was inconclusive and none failed.

## Required next increment

Stage 11A should connect the existing tests and binaries to manifests for:

1. constant-time byte comparison;
2. ML-KEM decapsulation validity handling;
3. ML-DSA signing conditioned on attempt count;
4. challenge multiplication matched-distribution testing;
5. generated-code audit status.

Machine-specific baselines must not be shared blindly across architectures.
Apple ARM64, Linux ARM64, and x86-64 should retain separate evidence records.
