# Stage 9F-2: Per-Primitive Timing Localization

This stage separates fixed-schedule ML-DSA primitives from the full signing
path.

Screens:

- NTT;
- inverse NTT;
- eta sampling;
- `SampleInBall`;
- rounding (`HighBits` and `LowBits`);
- canonical `t1` encode/decode;
- sparse challenge multiplication.

Each screen compares a fixed all-zero class with a varying deterministic class
using 20,000 interleaved measurements and raw/trimmed Welch t-tests.

Interpretation:

- `|t| < 4.5`: no signal detected at this sample size;
- `|t| >= 4.5`: investigate;
- `|t| >= 10`: strong class separation.

A detected difference does not by itself prove secret leakage. Some input
classes intentionally differ in value distribution. The purpose is to identify
which primitive deserves deeper constant-time review.

Run:

```bash
./scripts/run-stage9f2-primitive-timing.sh
```

Stage 9F-3 will instrument the signing rejection loop and correlate execution
time with iteration count.
