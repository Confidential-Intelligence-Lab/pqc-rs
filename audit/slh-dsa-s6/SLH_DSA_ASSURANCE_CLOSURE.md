# SLH-DSA S6 assurance closure

## Scope

This document consolidates the SLH-DSA assurance evidence produced during S6
and records the final claim boundaries, executable gates, CI enforcement, and
durable audit artifacts.

S6 assurance is evidence-based and layered. It does not claim formal
verification, proof of constant-time execution, proof of absence of all
memory-safety defects, or complete measurement of total runtime stack usage.

## Assurance matrix

| Assurance property | Policy / scope | Executable reproducer | CI enforcement | Durable evidence | Result |
| --- | --- | --- | --- | --- | --- |
| Secret lifetime / zeroization | `compliance/secret-policy.toml` | `cargo xtask zeroization-audit --check` | `constant-time-audit.yml`, `zeroization-audit.yml` | generated secret-lifetime / zeroization audit artifacts | PASS |
| Source-level secret dependency | secret-critical SLH-DSA paths | source review and classified dependency candidates | policy gate covers classified CT targets; source audit is durable evidence | `SLH_DSA_SECRET_DEPENDENCY_AUDIT.md`, `source-dependency-candidates.txt` | PASS within documented source-review claim |
| Optimized machine code | secret-critical PRF / PRF_msg paths | `build-slhdsa-s6-machine-code-audit.sh`, `analyze-slhdsa-s6-machine-code.py` | durable audit evidence; not claimed as a per-PR standalone workflow | `SLH_DSA_MACHINE_CODE_AUDIT.md` | PASS within documented machine-code claim |
| Timing screening | fixed-vs-varying secret timing screen | SLH-DSA timing audit harness | durable audit evidence; not claimed as proof of constant time | `SLH_DSA_TIMING_AUDIT.md` | PASS within documented statistical-screening claim |
| Dynamic secret taint | PRF / PRF_msg secret inputs | `run-slhdsa-s6-secret-taint.sh` | `slhdsa-s6-secret-taint.yml` | `SLH_DSA_SECRET_TAINT_AUDIT.md` plus CI artifacts | PASS |
| Miri | selected structural, bounds, malformed-input paths | `run-slhdsa-s6-miri.sh` | `dynamic-analysis.yml` | `SLH_DSA_MEMORY_SAFETY_AUDIT.md` | PASS within bounded scope |
| AddressSanitizer | selected SLH-DSA structural / malformed-input paths | `run-slhdsa-s6-asan.sh` | `dynamic-analysis.yml` | `SLH_DSA_MEMORY_SAFETY_AUDIT.md` | PASS within bounded scope |
| Structured fuzzing | SLH-DSA verification across all 12 parameter sets | `cargo fuzz`, `cargo xtask fuzz-audit --check` | `fuzz-smoke.yml` | `SLH_DSA_FUZZ_AUDIT.md` | PASS |
| Stack behavior | recursion bounds + compiler-emitted fixed frames | `run-slhdsa-s6-stack-audit.sh` | `dynamic-analysis.yml` | `SLH_DSA_STACK_AUDIT.md`, `SLH_DSA_MEMORY_BEHAVIOR_AUDIT.md` | PASS within fixed-frame claim |
| Heap behavior | 12 parameter sets × 5 public operations | `slhdsa-s6-heap-audit` | `dynamic-analysis.yml` | `SLH_DSA_MEMORY_BEHAVIOR_AUDIT.md` | PASS |
| Constant-time policy | classified CT targets | `cargo xtask constant-time-audit --check` | `constant-time-audit.yml` | generated policy artifacts and S6 audits | PASS — 19 classified targets |
| Fuzz policy | classified robustness targets | `cargo xtask fuzz-audit --check` | `fuzz-smoke.yml` | generated fuzz register and S6 fuzz audit | PASS — 8 classified targets |
| Zeroization policy | classified secret lifetimes | `cargo xtask zeroization-audit --check` | `zeroization-audit.yml` | generated inventory / audit artifacts | PASS — 16 classified lifetimes |

## Dynamic-analysis closure

Public Dynamic analysis run `35166990327` completed with all jobs green:

- repository Miri;
- bounded SLH-DSA Miri;
- broad workspace AddressSanitizer;
- bounded SLH-DSA AddressSanitizer;
- SLH-DSA stack-size audit;
- SLH-DSA heap audit;
- undefined-behavior compatibility gate.

The broad workspace ASan job excludes SLH-DSA's exhaustive suites because
SLH-DSA has a dedicated bounded ASan gate. This keeps the coverage boundary
explicit and avoids duplicate exhaustive execution that previously exceeded the
workflow budget.

## Local policy closure

The final local policy checks completed successfully:

```text
B1.3.2 zeroization audit: pass (16 classified lifetimes)
B1.3.3 constant-time audit: pass (19 classified targets)
B1.3.4 fuzz audit: pass (8 classified targets)
The SLH-DSA crate also completed cargo check both with the default feature
set and with internal-api.

Claim boundaries

The S6 assurance package supports the following bounded claims:

owned secret lifetimes are explicitly classified and audited for zeroization;
identified secret-critical control-flow and memory-access boundaries were
reviewed at source and optimized-machine-code levels;
dynamic secret-taint screening produced no findings in the evaluated PRF and
PRF_msg paths, with an effective positive control;
selected SLH-DSA paths complete cleanly under bounded Miri and ASan campaigns;
structured fuzzing exercises malformed SLH-DSA verification inputs across
all twelve parameter sets;
recursive tree depth and optimized fixed stack frames are bounded and
reproducibly measured;
heap allocation behavior is deterministically measured across all twelve
parameter sets for key generation, Pure signing / verification, and
representative HashSLH signing / verification.

These results do not establish:

formal verification;
universal constant-time behavior;
absence of all side channels;
exhaustive dynamic execution of every path under every sanitizer;
total peak runtime stack consumption;
exhaustive HashSLH memory measurements across all prehash algorithms.
Result

S6: PASS within the documented assurance boundaries.

The SLH-DSA implementation now has a coherent assurance chain from policy and
classified scope through executable reproducer, CI enforcement, durable
evidence, and explicit claim limitations.

The next work package is S7: performance and footprint characterization.
