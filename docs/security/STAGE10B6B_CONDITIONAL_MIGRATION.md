# Stage 10B-6B: Conditional Assignment and Selection Migration

This stage inventories conditional assignments, swaps, and if-expression
selections in ML-KEM and ML-DSA.

Automatic rewriting is intentionally limited to one narrow pattern:

```rust
if mask == CtMask32::TRUE {
    destination = source;
}
```

which can become:

```rust
destination = ct_select_u32(mask, source, destination);
```

All other sites remain in a reviewer-facing report.

## Outputs

```text
audit/stage10b6/conditional-assignment-inventory.csv
audit/stage10b6/applied-conditional-assignment-migrations.csv
target/stage10b6/conditional-assignment-review.md
```

## Run

```bash
./scripts/run-stage10b6b-conditional-assignment.sh
```
