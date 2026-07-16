# Stage 9F-4B: Assembly Inspection and Secret-Dependency Audit

Stage 9F-4 produced a broad generated-code inventory. Stage 9F-4B narrows that
inventory to the primitives most relevant to ML-DSA side-channel behavior.

## Targeted primitives

- `multiply_challenge`;
- `sign_prepared`;
- `verify_with_mu`;
- `sample_eta_poly`;
- `sample_in_ball`;
- `high_bits`;
- `low_bits`;
- `power2round`;
- NTT and inverse NTT;
- secret-key and signature encoding/decoding.

## Instruction classes

For each located symbol, the analyzer inventories:

- conditional branches;
- conditional moves and selects;
- integer division instructions;
- indexed-memory candidates;
- load/store-like instructions;
- multiply-like instructions.

It emits complete symbol excerpts for manual review.

## Secret-dependency matrix

The stage also generates a review matrix describing:

- which inputs are secret, ephemeral, transcript-derived, or public;
- which branches are algorithmically expected;
- which instruction classes require deeper review.

## Run

```bash
./scripts/run-stage9f4b-secret-dependency-audit.sh
```

## Outputs

```text
target/stage9f4b/
├── release-targeted-audit.md
├── debug-targeted-audit.md
├── triage-summary.md
├── secret-dependency-matrix.md
├── release/excerpts/
├── debug/excerpts/
├── rustc-version.txt
├── cargo-version.txt
└── system.txt
```

## Interpretation

This stage answers whether LLVM emitted potentially relevant instruction
classes. It does not automatically determine whether a given branch, select,
division, or memory address depends on secret data. That determination requires
manual data-flow review of each excerpt.

The highest-priority findings are:

1. division instructions in secret-bearing arithmetic;
2. indexed loads or stores whose index is derived from secret coefficients;
3. conditional branches inside fixed-schedule primitives;
4. debug/release differences that alter secret-bearing control flow;
5. unexpected branches beyond documented rejection sampling and sparse public
   support handling.
