# Stage 9F-4: Compiler and Generated-Code Audit

This stage audits compiler output without modifying cryptographic behavior.

## Outputs

The stage emits debug and optimized assembly and inventories:

- conditional branches;
- division instructions;
- indirect control flow;
- load/store-like instructions;
- symbol/name occurrences for security-relevant primitives.

It also extracts assembly excerpts around:

- `multiply_challenge`;
- `sign_prepared`;
- `verify_with_mu`;
- `sample_eta_poly`;
- `sample_in_ball`;
- `high_bits`;
- `low_bits`.

## Run on macOS or Linux

```bash
./scripts/run-stage9f4-generated-code-audit.sh
```

Evidence appears under:

```text
target/stage9f4/
```

Important files:

- `release-audit.txt`;
- `debug-audit.txt`;
- `debug-release-diff.txt`;
- `symbol-excerpts.txt`;
- `rustc-version.txt`;
- `cargo-version.txt`;
- `system.txt`.

## Interpretation

Assembly-wide branch counts are not direct leakage findings. They are an
inventory used to identify where compiler-generated control flow differs
between debug and optimized builds.

Particular attention should be paid to:

1. divisions or remainders in secret-bearing arithmetic;
2. branches around rejection conditions;
3. branches around sparse challenge support;
4. data-dependent addressing;
5. compiler transformations that introduce conditional control flow.

## Linux Valgrind workflow

The package also includes:

```bash
./scripts/run-stage9f4-linux-valgrind.sh
```

and a GitHub Actions workflow. The current Linux step performs Memcheck-based
dynamic validation. Strict secret-taint instrumentation with ctgrind
annotations should be added in Stage 9F-4B because it requires explicit
`VALGRIND_MAKE_MEM_UNDEFINED` and `VALGRIND_MAKE_MEM_DEFINED` boundaries around
secret buffers.

## Evidence boundary

This stage is a generated-code audit, not a formal constant-time proof.
