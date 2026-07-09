# Stage 4 Clippy Fix

This patch resolves two Clippy `-D warnings` failures:

1. Parenthesizes the compression expression in `compress_coefficient`.
2. Replaces cloned one-element slices in `polyvec` tests with `core::slice::from_ref`.

After applying this patch, rerun:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```
