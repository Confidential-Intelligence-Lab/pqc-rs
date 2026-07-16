# Stage 10B-3: Typed Secret Assignment

Stage 10B-3 introduces:

- `SecretBytes<N>` fixed-size secret containers;
- redacted `Debug` output;
- constant-time conditional assignment;
- constant-time conditional selection;
- constant-time conditional swap;
- conditional assignment for fixed-size `u16`, `u32`, and `u64` arrays.

## Design constraints

`SecretBytes<N>` does not implement ordinary conditional selection or expose
its contents through `Debug`.

Mutable byte access remains available for cryptographic algorithms, but callers
must avoid secret-dependent indexing.

This stage does not yet implement zeroization. Secret lifecycle and guaranteed
memory clearing are reserved for Stage 10B-4.

## Run

```bash
./scripts/run-stage10b3-secret-containers.sh
```

The optimized audit wrapper is:

```text
crates/pqc-test-harness/src/bin/ct-stage10b3-audit.rs
```
