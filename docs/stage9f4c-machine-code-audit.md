# Stage 9F-4C: Optimized Machine-Code Recovery

Stage 9F-4B failed because LLVM inlined or eliminated the library symbols that
the textual assembly parser expected.

Stage 9F-4C uses a dedicated audit binary with `#[inline(never)]` wrapper
functions. The wrappers provide stable recoverable boundaries while retaining
optimized production calls inside each boundary.

## Recovered audit boundaries

- challenge multiplication;
- eta sampling;
- challenge sampling;
- rounding and decomposition;
- encoding and decoding;
- complete signing and verification paths.

## Tooling

The stage uses:

- `cargo-binutils`;
- `rustup component add llvm-tools-preview`;
- `cargo objdump`;
- `cargo nm`.

Install the required Cargo extension:

```bash
cargo install cargo-binutils
rustup component add llvm-tools-preview
```

## Run

```bash
./scripts/run-stage9f4c-machine-code-audit.sh
```

## Outputs

```text
target/stage9f4c/
├── audit-binary.objdump.txt
├── audit-binary.nm.txt
├── audit-summary.md
├── flagged-instructions.md
├── audit_multiply_challenge.asm.txt
├── audit_sample_eta.asm.txt
├── audit_sample_ball.asm.txt
├── audit_rounding.asm.txt
├── audit_encoding.asm.txt
├── audit_sign_verify.asm.txt
├── rustc-version.txt
├── cargo-version.txt
└── system.txt
```

## Review order

1. Confirm every wrapper reports `status: recovered`.
2. Inspect division instructions in rounding and encoding.
3. Inspect indexed-memory candidates in sampling and multiplication.
4. Inspect conditional branches inside fixed-schedule wrappers.
5. Separate wrapper control flow from control flow in production calls.
6. Trace flagged instructions back to Rust source and classify their data
   dependency as public, transcript-derived, random, or secret.

The audit wrappers are test-harness code and do not change the ML-DSA library.
