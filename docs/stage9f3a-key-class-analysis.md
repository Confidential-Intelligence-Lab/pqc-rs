# Stage 9F-3A: Fixed-Key Versus Varying-Key Conditioned Analysis

Stage 9F-3 established that signing latency is dominated by rejection-loop
attempt count. Stage 9F-3A asks whether private-key class remains
distinguishable after accounting for that expected variability.

## Classes

- Class 0: one fixed ML-DSA-44 private key.
- Class 1: independently generated ML-DSA-44 private keys.
- Both classes use the same fixed message and context.
- Both classes use identically distributed deterministic signing randomness.
- Cases are interleaved through a deterministic pseudorandom class schedule.

## Measurements

Each case records:

- signing latency;
- attempt count;
- `z` rejection count;
- `r0` rejection count;
- `ct0` rejection count;
- hint rejection count.

The default campaign uses 10,000 signatures.

## Analysis

The analyzer reports:

1. whole-class timing and attempt-count Welch t-statistics;
2. attempt-distribution chi-square;
3. linear timing regression on attempt count;
4. residual timing Welch t-statistic after removing the attempt-count model;
5. timing comparisons within equally sized attempt-count buckets;
6. rejection-category mean comparisons.

## Interpretation

The security-relevant warning conditions are:

- attempt-count `|t| >= 4.5`;
- residual timing `|t| >= 4.5`;
- within-attempt timing `|t| >= 4.5` in well-populated buckets;
- rejection-category `|t| >= 4.5`.

Whole-class raw timing may differ merely because attempt distributions differ.
Residual and conditioned analyses are therefore more informative.

## Run

```bash
./scripts/run-stage9f3a-key-class-analysis.sh
```

This stage uses the trace instrumentation committed in Stage 9F-3 and does not
change signing semantics.
