# Stage 10B-1: Masks, Equality, and Selection

This stage introduces shared constant-time helpers in `pqc-core`:

- canonical all-zero/all-one masks for `u8`, `u16`, `u32`, and `u64`;
- constant-time zero, nonzero, and equality tests;
- scalar branchless selection;
- fixed-size byte-array selection;
- fixed-size conditional assignment.

Secret masks must not be converted to Rust `bool` values in secret-bearing
paths. Compiler- and architecture-level behavior must still be validated.

Run:

```bash
python3 scripts/patch-stage10b1-enable-ct.py
./scripts/run-stage10b1-ct-primitives.sh
```
