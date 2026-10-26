# SMAUG-T Gaussian Sampler Assurance Record

## Scope

This record describes implementation and assurance evidence for
the experimental SMAUG-T 1.1.1 Gaussian sampler in `pqc-rs-smaug-t`.

The implementation is experimental and is not presented as a
side-channel-certified cryptographic implementation.

## Reference implementation

The upstream reference is SMAUG-T 1.1.1, pinned at:

`bbc463cd788eae36c6d155cef667ac9dbd9054cd`

The pinned C reference contains an indexing discrepancy in
`src/dg.c`, within `load64_littleendian`.

The original implementation writes to `out[j]` instead of
`out[i * 10 + j]`, overwriting earlier bitplane words.

The Rust implementation follows the corrected intended semantics
rather than reproducing the upstream indexing error.

See `GAUSSIAN_REFERENCE_DISCREPANCY.md` for details.

## Functional correctness evidence

The dual-reference validation harness distinguishes:

- Original upstream Gaussian behavior, retained as a regression oracle.
- Corrected Gaussian behavior, used for Rust coefficient parity.
- Other reference oracles, retained for existing validation coverage.

Validation spans four parameter modes:

- mode1
- mode3
- mode5
- modet

Three deterministic seed patterns were exercised.

The corrected-reference Gaussian comparison established exact parity
for 11,520 polynomial and vector coefficients.

The original-reference regression also passed.

These tests establish parity for the tested inputs, not an
exhaustive proof of functional correctness.

## Source-level constant-time hardening

The Gaussian sign application uses arithmetic masking:

    let sign_mask = 0i16.wrapping_sub(sign as i16);
    let signed = ((magnitude as i16) ^ sign_mask)
        .wrapping_sub(sign_mask);

This replaces a source-level conditional selection on the sign bit.

The associated arithmetic test covers magnitudes 0 through 3
and both possible sign bits.

Source-level branchlessness alone does not guarantee that
optimized machine code is constant-time.

## Optimized machine-code inspection

### Build environment

- Architecture: AArch64
- Operating system: macOS
- Rust: 1.89.0
- LLVM: 20.1.7
- Rust target: `aarch64-apple-darwin`
- Git baseline: `313696d`
- Profile: release

The inspected function was `gaussian_poly_from_randomness`.

The generated assembly contained 1,161 lines for this function.

### Conditional control flow

Two conditional branches were identified:

1. A `b.ne` branch associated with public `log_q` validation.
2. A `b.lo` branch associated with the fixed four-group loop.

No secret-dependent conditional branch was identified in the
inspected function.

### Memory-access behavior

The inspection inventoried 291 load/store operations.

The observed input accesses used fixed offsets from the input
pointer. NEON lane loads used addresses formed by adding
constant offsets.

The observed output stores used fixed offsets from the output
pointer.

The loop advanced:

- Input pointer by 80 bytes per group.
- Output pointer by 128 bytes per group.
- Loop counter by one per group.

Constant-pool accesses used compiler-generated static addresses.

No secret-dependent memory-address calculation was identified
in the inspected function.

The inspection was manual and evidence-based, not a formal
machine-code information-flow proof.

## Assurance limitations

This record does not establish:

- Constant-time behavior across every supported architecture.
- Constant-time behavior across future Rust or LLVM versions.
- Constant-time behavior of SHAKE256 or other called functions.
- Constant-time behavior of the complete SMAUG-T implementation.
- Absence of microarchitectural leakage.
- Absence of power, electromagnetic, or fault-injection leakage.
- A formal proof of noninterference.
- A completed dynamic leakage assessment.

The static findings apply only to the inspected release build
and function.

## Reproduction

From the repository root:

    cargo fmt --manifest-path experimental/pqc-rs-smaug-t/Cargo.toml --check

    cargo clippy --manifest-path experimental/pqc-rs-smaug-t/Cargo.toml --all-targets -- -D warnings

    cargo test --manifest-path experimental/pqc-rs-smaug-t/Cargo.toml

    cargo rustc --manifest-path experimental/pqc-rs-smaug-t/Cargo.toml --release --lib -- --emit=asm

The dual-reference validation entry point is:

`experimental/pqc-rs-smaug-t/scripts/validate-reference.sh`

That harness requires the separately pinned C reference environment
and its documented dependencies.

## Current disposition

The Gaussian sampler has passed the recorded functional parity,
source-level sign-hardening, and AArch64 release-assembly inspections.

It is suitable to serve as the current experimental baseline for
subsequent SMAUG-T integration work, subject to the assurance
limitations above.

No claim of production readiness or side-channel certification
is made.
