# Stage 9F-1: ML-DSA Timing-Leakage Screening

This stage begins the side-channel review without changing cryptographic
behavior.

It provides:

- interleaved two-class timing acquisition;
- raw and 1% trimmed Welch t-tests;
- KeyGen screening across fixed and varying seeds;
- signing screening across fixed and varying private keys;
- a source-level inventory of branches, loops, indexing, division, and
  `unsafe` usage.

The common TVLA threshold `|t| >= 4.5` is treated as a signal requiring
investigation, not proof of exploitable leakage. A non-detection is not proof
of constant-time behavior.

ML-DSA signing contains rejection sampling. Signing must therefore be analyzed
separately from fixed-schedule primitives, and detected timing differences must
be localized before remediation.

This stage runs natively on Apple Silicon. ctgrind is deferred to a Linux CI or
virtual-machine stage because Valgrind is not a reliable Apple Silicon macOS
workflow.

Run:

```bash
./scripts/run-stage9f1-timing-screen.sh
```

For a longer campaign:

```bash
STAGE9F_SAMPLES=100000 STAGE9F_WARMUP=1000 \
  ./scripts/run-stage9f1-timing-screen.sh
```

Follow-on work:

1. per-primitive screens;
2. Linux ctgrind/memory-access analysis;
3. optimized assembly and LLVM inspection;
4. compiler/version matrices;
5. remediation and regression thresholds.
