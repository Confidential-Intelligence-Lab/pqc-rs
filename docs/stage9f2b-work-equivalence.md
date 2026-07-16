# Stage 9F-2B: Challenge-Multiplication Work Equivalence

This stage proves whether valid sparse challenge supports perform identical
algorithmic work.

For ML-DSA-44, `tau = 39` and `N = 256`. Every invocation must perform:

- 256 challenge-coefficient inspections;
- 39 nonzero challenge terms;
- 9,984 coefficient multiplications;
- 9,984 total accumulations;
- 256 final modular reductions.

The direct-versus-wrapped accumulation split varies with support positions,
while the total remains fixed.

The audit wrapper returns the production multiplication result and counts only
the work implied by the production loop. Tests verify result equivalence and
operation-count invariants across many support patterns.

Run:

```bash
python3 scripts/patch-stage9f2b-audit-module.py
./scripts/run-stage9f2b-work-equivalence.sh
```

If every invariant holds, Stage 9F-2A's remaining timing signal is consistent
with microarchitectural effects rather than differing arithmetic workload.
