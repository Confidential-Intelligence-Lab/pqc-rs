# Stage 8 Production-Hardening Roadmap

## Stage 8A — Security hygiene baseline

- dependency advisory scanning;
- license and source policy;
- strict formatting, linting, tests, and documentation;
- negative HPKE protocol tests;
- CI enforcement.

## Stage 8B — Fuzzing

Initial targets: ML-KEM key checks and decapsulation, HPKE vector parsing,
receiver `Open`, and hybrid KEM parsing.

## Stage 8C — Interpreter and sanitizer checks

Miri, AddressSanitizer, UndefinedBehaviorSanitizer where supported, and leak
checks for long-running harnesses.

## Stage 8D — Constant-time and secret-lifetime review

Secret-bearing type inventory, zeroization boundaries, accidental `Debug`
exposure, secret-dependent branches/indexing, and critical assembly review.

## Stage 8E — Performance and regression baselines

Criterion benchmarks, allocation counts, message expansion, latency, and CI
regression thresholds.
