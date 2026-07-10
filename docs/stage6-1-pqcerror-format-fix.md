# Stage 6.1 PqcError Formatting Fix

The ACVP KeyGen runner attempted to call `.to_string()` on `PqcError`.
`PqcError` does not currently implement `Display`, so `ToString` is unavailable.

This patch formats the error through its existing `Debug` implementation:

```rust
format!("{error:?}")
```

This keeps the fix local to the test harness and does not change the public
error API in `pqc-core`.
