# Stage 9F-3: Signing Rejection-Loop Characterization

This stage instruments the ML-DSA signing rejection loop without changing
signature outputs.

It records, for each signing operation:

- total latency;
- number of loop attempts;
- response-vector norm rejections;
- low-bits norm rejections;
- secret `t0` product norm rejections;
- hint-weight rejections;
- total rejected attempts.

The harness checks the invariant:

```text
attempts = total_rejections + 1
```

for every successful signature.

The default campaign executes 5,000 deterministic ML-DSA-44 signing cases with
a fixed key, message, and context and independently varying signing randomness.

The analyzer reports:

- mean and median signing latency;
- mean and maximum attempt count;
- Pearson correlation between latency and attempts;
- latency grouped by attempt count;
- aggregate rejection counts by category.

## Apply and run

```bash
python3 scripts/patch-stage9f3-signing-trace.py
./scripts/run-stage9f3-rejection-trace.sh
```

## Interpretation

A strong latency-versus-attempt correlation is expected because ML-DSA signing
uses rejection sampling. It establishes the dominant source of variable
signing latency, but does not by itself prove exploitable secret leakage.

Follow-on analysis should test whether, after conditioning on attempt count,
latency or rejection-category distributions remain distinguishable across
fixed and varying private keys.
