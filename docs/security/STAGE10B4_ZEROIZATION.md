# Stage 10B-4: Zeroization and Secret Lifecycle

Stage 10B-4 adds explicit zeroization for byte and integer slices and wires
`SecretBytes<N>` to clear its owned storage on `Drop`.

The implementation uses volatile stores followed by a sequentially consistent
compiler fence. The generated-code gate recovers optimized wrappers and
requires visible store instructions.

This is a best-effort owned-memory guarantee. It does not prove erasure of
compiler-generated copies, registers, swap, crash dumps, caches, or other
microarchitectural state.

Run:

```bash
./scripts/run-stage10b4-zeroization.sh
```
