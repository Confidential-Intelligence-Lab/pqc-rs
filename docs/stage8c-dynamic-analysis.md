# Stage 8C: Miri and Sanitizers

Stage 8C adds dynamic-analysis gates without changing the validated cryptographic algorithms.

## Miri

Run:

```bash
./scripts/install-dynamic-analysis-tools.sh
./scripts/run-miri.sh
```

The default scope covers library tests for `pqc-rs-core`, `pqc-rs-ml-kem`, and `pqc-rs-hpke`.

## AddressSanitizer

Run:

```bash
./scripts/run-address-sanitizer.sh
```

This runs the complete workspace tests and the HPKE negative tests under ASan.

## Undefined-behavior coverage

Rust nightly does not expose LLVM UndefinedBehaviorSanitizer through
`-Zsanitizer`. Miri is therefore the executable undefined-behavior gate. The
legacy command remains available for automation compatibility and records the
limitation explicitly:

```bash
./scripts/run-undefined-behavior-sanitizer.sh
```

## Acceptance criteria

Stage 8C passes when Miri and ASan complete without findings. The unavailable
UBSan capability is recorded as unsupported, never as passing security
evidence. Every confirmed defect must become a deterministic regression test.

A clean result is evidence from dynamic analysis, not a proof of constant-time behavior, absence of side channels, or cryptographic security.
