# Stage 10B-5: Cross-Architecture Validation

Stage 10B-5 reinstates the deferred cross-architecture validation campaign on
public GitHub-hosted runners. It covers the release foundation on:

- Linux x86-64 using `ubuntu-24.04`;
- Linux ARM64 using `ubuntu-24.04-arm`; and
- Apple ARM64 using `macos-15`.

The workflow verifies the observed operating system, machine architecture, and
Rust host triple. A mislabeled or unexpectedly migrated runner fails rather
than being accepted as evidence for the intended target.

## Release gates

Each architecture must pass:

1. formatting, warning-free Clippy, and the complete workspace test suite;
2. optimized recovery of the Stage 10B-1.1, 10B-2, 10B-3, and 10B-4 audit
   wrappers;
3. versioned secret-dependency rules for branchless wrappers, including the
   absence of conditional branches and division instructions in the audited
   fixed-schedule entry points;
4. recovery of explicit stores from the zeroization function family; and
5. complete SHA-256 coverage and verification of the evidence tree.

The policy is maintained in `sidechannel/stage10b5/policy.json`. Changing a
wrapper, its control-flow classification, an architecture identity, or a
timing threshold is therefore a reviewable source change.

The machine-code checks are deliberately narrow. They validate specific audit
entry points and forbidden instruction classes; they do not prove that all
transitive machine code is constant time or free of microarchitectural
leakage.

## Timing boundary

The Stage 10B-2 mismatch-position timing screen runs on all three targets. Its
raw CSV, class statistics, and pairwise Welch t-statistics are preserved. A
threshold crossing is classified as `signal-detected` and must be reviewed,
but it does not fail a shared hosted runner. Hosted machines differ in CPU
generation, virtualization, load, frequency behavior, and timer properties,
so absolute timing is not compared across architectures.

Functional behavior, wrapper recovery, versioned secret-dependency rules, and
artifact integrity remain hard gates. Timing is architecture-specific
regression evidence, not proof of constant-time execution.

## Workflow behavior

The workflow is path-filtered to release-relevant code, audit harnesses,
policy, and its own implementation. Documentation-only changes do not launch
the architecture campaign. Stage 9F-4 Linux Valgrind evidence remains a
separate preserved experiment and is not rerun by Stage 10B-5.

Each matrix job uploads a target-specific evidence archive. The `aggregate`
job then requires exactly the three policy targets, verifies every checksum,
requires a common source commit, and produces a combined archive.

## Local run

Install stable Rust with `rustfmt`, `clippy`, and `llvm-tools-preview`, then run
the target identifier that matches the current host:

```bash
python3 scripts/validate-stage10b5.py
./scripts/run-stage10b5-cross-architecture.sh apple-aarch64
```

Valid identifiers are `linux-x86_64`, `linux-aarch64`, and `apple-aarch64`.
Local execution validates only the current host; completion requires the
combined GitHub Actions evidence from all three runners.

## Evidence layout

Per-target evidence is written below `target/stage10b5/<target-id>/` and
includes:

- `summary.json`;
- `SHA256SUMS`;
- compiler, Cargo, host, and runner-image metadata;
- functional-gate logs;
- complete disassembly and symbol inventories for each audit binary;
- machine-code JSON and Markdown reports; and
- raw and summarized timing evidence.

The aggregate archive contains all three target archives, target summaries, a
combined summary, and its own checksum manifest. Before release review begins,
the combined archive must be downloaded, independently verified, signed, and
attached to the fixed review candidate rather than relying only on expiring CI
artifact storage.

## Claim boundary

A passing Stage 10B-5 campaign supports the statement that the documented
functional and generated-code checks passed for the recorded compiler and
three target configurations. It is not a formal constant-time proof, FIPS or
CMVP validation, Common Criteria certification, hardware leakage evaluation,
or independent security audit.
