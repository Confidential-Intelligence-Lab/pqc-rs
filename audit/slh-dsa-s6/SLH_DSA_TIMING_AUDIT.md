# SLH-DSA Fixed-vs-Varying Secret Timing Audit

## Scope

This S6.2e experiment screens the secret-bearing SLH-DSA PRF boundaries
for timing separation between fixed-secret and varying-secret input classes.

All public inputs, operation sizes, and parameter configurations are held fixed.
Secret values alone distinguish the two interleaved classes.

Each configuration uses:

- 20,000 observations;
- 500 warmup observations;
- 128 primitive executions per timed observation;
- raw and 1%-trimmed Welch t-statistics.

The repository investigation threshold is |t| >= 4.5.

## Results

| Operation | Hash path | Raw |t| | Trimmed |t| | Max |t| | Classification |
|---|---|---:|---:|---:|---|
| PRF | SHAKE256 | 1.1484 | 1.4629 | **1.4629** | No signal detected |
| PRF_msg | SHAKE256 | 0.1895 | 0.0189 | **0.1895** | No signal detected |
| PRF | SHA-2 | 0.8464 | 0.8400 | **0.8464** | No signal detected |
| PRF_msg | HMAC-SHA-512 (n=32) | 0.1974 | 0.3180 | **0.3180** | No signal detected |
| PRF_msg | HMAC-SHA-256 (n=16) | 0.0180 | 0.1087 | **0.1087** | No signal detected |

The maximum absolute Welch statistic observed across all raw and trimmed
comparisons is **1.4629**, below the |t| = 4.5 investigation threshold.

## Environment

```text
rustc 1.89.0 (29483883e 2025-08-04)
binary: rustc
commit-hash: 29483883eed69d5fb4db01964cdf2af4d86e9cb2
commit-date: 2025-08-04
host: aarch64-apple-darwin
release: 1.89.0
LLVM version: 20.1.7
cargo 1.89.0 (c24e10642 2025-06-23)
Darwin mac.lan 25.6.0 Darwin Kernel Version 25.6.0: Fri Jul 31 19:11:03 PDT 2026; root:xnu-12377.161.14~5/RELEASE_ARM64_T8132 arm64
Apple M4
```

## Claim Boundary

No fixed-vs-varying secret timing signal was detected at this sample size
and on this compiler/platform configuration.

Statistical non-detection is empirical leakage-screening evidence, not a
proof of constant-time execution. Results are architecture-, compiler-,
configuration-, and measurement-environment-specific.
