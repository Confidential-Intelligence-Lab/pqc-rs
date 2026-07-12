# Stage 8C: Miri and Sanitizers

Stage 8C adds dynamic-analysis gates without changing the validated cryptographic algorithms.

## Miri

Run:

```bash
./scripts/install-dynamic-analysis-tools.sh
./scripts/run-miri.sh
```

The default scope covers library tests for `pqc-core`, `pqc-ml-kem`, and `pqc-hpke`.

## AddressSanitizer

Run:

```bash
./scripts/run-address-sanitizer.sh
```

This runs the complete workspace tests and the HPKE negative tests under ASan.

## UndefinedBehaviorSanitizer

Run on Linux:

```bash
./scripts/run-undefined-behavior-sanitizer.sh
```

## Acceptance criteria

Stage 8C passes when Miri, ASan, and Linux UBSan complete without findings. Any unsupported operation or platform limitation must be recorded explicitly, and every defect must become a deterministic regression test.

A clean result is evidence from dynamic analysis, not a proof of constant-time behavior, absence of side channels, or cryptographic security.
