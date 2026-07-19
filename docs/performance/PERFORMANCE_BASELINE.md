# Performance Baseline

> Generated from `compliance/performance-policy.toml` by `scripts/performance_audit.py`. Do not edit manually.

## Scope and claim

Milestone: **B1.3.5**.

Claim boundary: **reproducible engineering baseline; not a cross-platform performance guarantee**.

This baseline measures release-mode cryptographic operations using Criterion. It records machine and toolchain provenance separately from correctness gates. Results are comparable only when the benchmark source, feature set, toolchain, target triple, power policy, and host conditions are controlled.

## Decision

**PASS** — 10 active benchmark groups; 0 blocking findings.

## Execution

```bash
cargo xtask performance-audit --check
./scripts/run-performance-baseline.sh
```

The runner writes provenance to `target/performance-baseline/environment.txt` and Criterion output beneath `target/criterion/`.

## Regression policy

A sustained median regression of **10% or more** requires investigation. A sustained regression of **20% or more** blocks release unless explicitly accepted with rationale. These thresholds apply only to controlled, like-for-like measurements and are not enforced in generic CI runners.

ML-DSA signing is rejection-sampled and therefore naturally variable. Review its distribution and signing trace together with median latency; do not interpret one timing sample as a constant-time claim.

## Required provenance

- CPU model, architecture, core count, and frequency policy
- operating system and kernel version
- Rust and Cargo versions plus target triple
- Git revision and dirty-tree status
- build profile and enabled features
- benchmark source revision, sample count, and Criterion confidence interval
- thermal, power, virtualization, and background-load conditions

## Coverage

| ID | Benchmark | Class | Parameter sets | Metrics |
|---|---|---|---|---|
| `PERF-MLKEM-KEYGEN` | `ml_kem/keygen` | `key-generation` | ML-KEM-512; ML-KEM-768; ML-KEM-1024 | median latency; confidence interval; throughput |
| `PERF-MLKEM-ENCAPS` | `ml_kem/encaps_decaps/encaps` | `encapsulation` | ML-KEM-512; ML-KEM-768; ML-KEM-1024 | median latency; confidence interval; throughput |
| `PERF-MLKEM-DECAPS` | `ml_kem/encaps_decaps/decaps` | `decapsulation` | ML-KEM-512; ML-KEM-768; ML-KEM-1024 | median latency; confidence interval; throughput |
| `PERF-MLDSA-KEYGEN` | `ml_dsa/keygen` | `key-generation` | ML-DSA-44; ML-DSA-65; ML-DSA-87 | median latency; confidence interval; throughput |
| `PERF-MLDSA-SIGN` | `ml_dsa/sign` | `signing` | ML-DSA-44; ML-DSA-65; ML-DSA-87 | median latency; confidence interval; rejection-loop variability |
| `PERF-MLDSA-VERIFY` | `ml_dsa/verify` | `verification` | ML-DSA-44; ML-DSA-65; ML-DSA-87 | median latency; confidence interval; throughput |
| `PERF-HPKE-SETUP` | `hpke/base/setup` | `protocol-setup` | ML-KEM-768/HKDF-SHA256/AES-128-GCM | sender setup latency; receiver setup latency |
| `PERF-HPKE-SEAL-OPEN` | `hpke/base/seal_open_1k` | `authenticated-encryption` | ML-KEM-768/HKDF-SHA256/AES-128-GCM | 1 KiB seal latency; 1 KiB open latency; throughput |
| `PERF-HPKE-EXPORT` | `hpke/base/export_32` | `exporter` | ML-KEM-768/HKDF-SHA256/AES-128-GCM | 32-byte export latency |
| `PERF-HYBRID-SETUP` | `hpke/hybrid/setup` | `protocol-setup` | MLKEM768-P256; MLKEM768-X25519; MLKEM1024-P384 | sender setup latency; receiver setup latency |

## Interpretation boundaries

- Criterion measurements are not evidence of constant-time execution or cryptographic security.
- CI smoke mode validates compilation and execution only; it does not establish stable performance numbers.
- Cross-machine comparisons are invalid unless hardware, firmware, compiler, target features, and operating conditions are normalized.
- Allocation and peak-memory measurements are not yet part of this baseline and remain future work.
