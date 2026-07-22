# Stage 12 — Comprehensive Side-Channel Validation

Stage 12 promotes the Stage 11 regression harness into a release-oriented validation campaign. It separates portable statistical gates from host-specific microarchitectural evidence and compiler-diversity checks.

## Profiles

`ci` runs the same enabled experiments as `portable`, but treats statistical
timing thresholds as evidence rather than hard gates. Deterministic,
zeroization, generated-code, and compiler failures remain gating. This profile
is intended for noisy, shared GitHub-hosted runners.

`portable` runs the enabled Stage 9F/10B experiments with three repetitions and the installed stable compiler gate. It is suitable for Apple ARM64 and ordinary developer hosts.

`full` uses five repetitions, requires a clean Git tree, checks every locally installed Rust channel, and attempts Linux `perf` collection. `soak` increases statistical repetitions to ten and is intended for controlled release runners.

## Security interpretation

A passing campaign means that the measured experiments stayed within their versioned thresholds on the recorded host and compiler. It does not prove constant-time execution. Unsupported tools are recorded explicitly. Linux perf observations are informational until per-architecture baselines, variance models, and review thresholds are established.

## Execution

```bash
./scripts/run-stage12.sh ci
./scripts/run-stage12.sh portable
./scripts/run-stage12.sh full
./scripts/run-stage12.sh soak
```

Evidence is written beneath `target/stage12/<profile>/` and bundled as `target/stage12-<profile>-evidence.tar.gz` with SHA-256 checksums.
